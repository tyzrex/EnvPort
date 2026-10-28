package application

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/envport-dev/envport/internal/domain"
	"github.com/envport-dev/envport/internal/restore"
	planner "github.com/envport-dev/envport/internal/sync"
	"github.com/envport-dev/envport/pkg/protocol"
	"sort"
	"time"
)

type Entry struct {
	ProjectID domain.ID      `json:"project_id"`
	FileID    domain.ID      `json:"file_id"`
	Path      string         `json:"path"`
	Root      string         `json:"root,omitempty"`
	Action    planner.Action `json:"action"`
	Size      int64          `json:"size"`
	Base      string         `json:"-"`
	Local     string         `json:"-"`
	Remote    protocol.File  `json:"-"`
	Removed   bool           `json:"-"`
}
type Plan struct {
	Vault     domain.ID `json:"vault_id"`
	Storage   string    `json:"storage"`
	Snapshot  domain.ID `json:"snapshot_id,omitempty"`
	HeadToken string    `json:"-"`
	Entries   []Entry   `json:"entries"`
	manifest  protocol.Manifest
}
type Result struct {
	Snapshot   domain.ID `json:"snapshot_id,omitempty"`
	Uploaded   int       `json:"uploaded"`
	Downloaded int       `json:"downloaded"`
	Conflicts  int       `json:"conflicts"`
	Pending    int       `json:"pending"`
}

func (s *Service) PlanSync(ctx context.Context, v Vault) (Plan, error) {
	fresh, e := s.Vault(ctx, string(v.ID))
	if e != nil {
		return Plan{}, e
	}
	v = fresh
	st, e := s.OpenStore(ctx, v)
	if e != nil {
		return Plan{}, e
	}
	defer st.Close()
	m, tag, e := s.current(ctx, v, st)
	if e != nil {
		return Plan{}, e
	}
	return s.plan(ctx, v, m, tag)
}
func (s *Service) plan(ctx context.Context, v Vault, m protocol.Manifest, tag string) (Plan, error) {
	p := Plan{Vault: v.ID, Storage: v.Profile, Snapshot: m.ID, HeadToken: tag, Entries: []Entry{}, manifest: m}
	projects, e := s.Projects(ctx, v)
	if e != nil {
		return p, e
	}
	roots := map[domain.ID]string{}
	for _, project := range projects {
		roots[project.ID] = project.Root
	}
	entries := map[domain.ID]Entry{}
	for _, project := range m.Projects {
		for _, f := range project.Files {
			entries[f.ID] = Entry{ProjectID: project.ID, FileID: f.ID, Path: f.Path, Root: roots[project.ID], Remote: f, Size: f.Size}
		}
	}
	rows, e := s.DB.QueryContext(ctx, "SELECT project_id,id,path,removed FROM tracked_files WHERE vault_id=? ORDER BY project_id,path", v.ID)
	if e != nil {
		return p, e
	}
	for rows.Next() {
		var pid, id domain.ID
		var path string
		var removed bool
		if e = rows.Scan(&pid, &id, &path, &removed); e != nil {
			rows.Close()
			return p, e
		}
		en := entries[id]
		en.ProjectID = pid
		en.FileID = id
		en.Path = path
		en.Root = roots[pid]
		en.Removed = removed
		entries[id] = en
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return p, e
	}
	for _, en := range entries {
		if e := ctx.Err(); e != nil {
			return p, e
		}
		if en.Root == "" {
			en.Action = planner.Unmapped
			p.Entries = append(p.Entries, en)
			continue
		}
		b, e := restore.Read(en.Root, en.Path)
		if e == nil {
			en.Local = digest(b)
			en.Size = int64(len(b))
		} else if !errors.Is(e, domain.ErrNotFound) {
			return p, e
		}
		en.Base, e = base(ctx, s.DB, v.ID, en.FileID)
		if e != nil {
			return p, e
		}
		remote := en.Remote.Digest
		if en.Remote.Deleted {
			remote = planner.Deleted
		}
		en.Action = planner.Decide(en.Base, en.Local, remote, en.Removed)
		p.Entries = append(p.Entries, en)
	}
	sort.Slice(p.Entries, func(i, j int) bool {
		a, b := p.Entries[i], p.Entries[j]
		if a.ProjectID == b.ProjectID {
			return a.Path < b.Path
		}
		return a.ProjectID < b.ProjectID
	})
	return p, nil
}
func remoteDigest(f protocol.File) string {
	if f.Deleted {
		return planner.Deleted
	}
	return f.Digest
}
func (s *Service) Execute(ctx context.Context, v Vault, p Plan, downloads bool, acceptRemote bool) (Result, error) {
	result := Result{}
	if p.Vault != v.ID {
		return result, domain.ErrCorrupt
	}
	for _, en := range p.Entries {
		if en.Action == planner.Conflict {
			result.Conflicts++
		}
	}
	if result.Conflicts > 0 {
		return result, domain.ErrConflict
	}
	fresh, e := s.Vault(ctx, string(v.ID))
	if e != nil {
		return result, e
	}
	v = fresh
	st, e := s.OpenStore(ctx, v)
	if e != nil {
		return result, e
	}
	defer st.Close()
	m, tag, e := s.current(ctx, v, st)
	if e != nil {
		return result, e
	}
	if tag != p.HeadToken || m.ID != p.Snapshot {
		return result, domain.ErrPrecondition
	}
	// Revalidate every local precondition before either uploads or downloads.
	for _, en := range p.Entries {
		if en.Root == "" {
			continue
		}
		b, e := restore.Read(en.Root, en.Path)
		local := ""
		if e == nil {
			local = digest(b)
		} else if !errors.Is(e, domain.ErrNotFound) {
			return result, e
		}
		if local != en.Local {
			return result, errors.New("local files changed after preview; replan")
		}
	}
	changes := 0
	for _, en := range p.Entries {
		if en.Action == planner.Upload || en.Action == planner.Tombstone {
			changes++
		}
	}
	if changes > 0 {
		if !v.RecoveryVerified {
			return result, errors.New("export and verify a recovery bundle before backup")
		}
		caps := st.Capabilities()
		if !caps.Verified || !caps.ConditionalCreate || !caps.ConditionalReplace {
			return result, errors.New("storage conditional writes are unverified; run storage test")
		}
		device, e := s.Device(ctx)
		if e != nil {
			return result, e
		}
		next := m
		next.ID = domain.NewID()
		next.Version = 1
		next.Vault = v.ID
		next.Generation = m.Generation + 1
		next.Author = device
		next.Created = time.Now().UTC()
		next.Parents = []domain.ID{}
		if m.ID != "" {
			next.Parents = []domain.ID{m.ID}
		}
		next.Projects = append([]protocol.Project(nil), m.Projects...)
		for i := range next.Projects {
			next.Projects[i].Files = append([]protocol.File(nil), next.Projects[i].Files...)
		}
		projects, e := s.Projects(ctx, v)
		if e != nil {
			return result, e
		}
		byID := map[domain.ID]Project{}
		for _, pr := range projects {
			byID[pr.ID] = pr
		}
		op := domain.NewID()
		if _, e = s.DB.ExecContext(ctx, "INSERT INTO operations(id,vault_id,snapshot_id,expected_head,state) VALUES(?,?,?,?,'staged')", op, v.ID, next.ID, tag); e != nil {
			return result, e
		}
		for _, en := range p.Entries {
			if en.Action != planner.Upload && en.Action != planner.Tombstone {
				continue
			}
			journalDigest := en.Local
			if en.Action == planner.Tombstone {
				journalDigest = planner.Deleted
			}
			if _, e = s.DB.ExecContext(ctx, "INSERT INTO operation_files(operation_id,file_id,digest) VALUES(?,?,?)", op, en.FileID, journalDigest); e != nil {
				return result, e
			}
			f := protocol.File{ID: en.FileID, Path: en.Path, Deleted: en.Action == planner.Tombstone}
			if !f.Deleted {
				plain, e := restore.Read(en.Root, en.Path)
				if e != nil {
					return result, e
				}
				if digest(plain) != en.Local {
					return result, errors.New("local file changed during backup; replan")
				}
				f.Blob = domain.NewID()
				f.Digest = en.Local
				f.Size = int64(len(plain))
				if _, e = s.putEncrypted(ctx, v, st, "blobs/"+string(f.Blob)+".age", plain, domain.Condition{Mode: domain.CreateIfAbsent}); e != nil {
					return result, e
				}
				result.Uploaded++
			}
			pi := -1
			for i := range next.Projects {
				if next.Projects[i].ID == en.ProjectID {
					pi = i
				}
			}
			if pi < 0 {
				pr := byID[en.ProjectID]
				next.Projects = append(next.Projects, protocol.Project{ID: en.ProjectID, Identity: pr.Identity, Files: []protocol.File{}})
				pi = len(next.Projects) - 1
			}
			fi := -1
			for i := range next.Projects[pi].Files {
				if next.Projects[pi].Files[i].ID == f.ID {
					fi = i
				}
			}
			if fi < 0 {
				next.Projects[pi].Files = append(next.Projects[pi].Files, f)
			} else {
				next.Projects[pi].Files[fi] = f
			}
		}
		sort.Slice(next.Projects, func(i, j int) bool { return next.Projects[i].ID < next.Projects[j].ID })
		for i := range next.Projects {
			sort.Slice(next.Projects[i].Files, func(a, b int) bool { return next.Projects[i].Files[a].Path < next.Projects[i].Files[b].Path })
		}
		if e = next.Validate(v.ID); e != nil {
			return result, e
		}
		plain, _ := json.Marshal(next)
		if _, e = s.putEncrypted(ctx, v, st, "snapshots/"+string(next.ID)+".age", plain, domain.Condition{Mode: domain.CreateIfAbsent}); e != nil {
			return result, e
		}
		ref, _ := json.Marshal(protocol.Ref{Version: 1, Vault: v.ID, Snapshot: next.ID, Generation: next.Generation})
		cond := domain.Condition{Mode: domain.CreateIfAbsent}
		if tag != "" {
			cond = domain.Condition{Mode: domain.IfETagMatch, ETag: tag}
		}
		if _, e = s.putEncrypted(ctx, v, st, "refs/main", ref, cond); e != nil {
			observed, _, readErr := s.current(ctx, v, st)
			if readErr != nil || observed.ID != next.ID {
				if errors.Is(e, domain.ErrPrecondition) && readErr == nil {
					_, _ = s.DB.ExecContext(ctx, "UPDATE operations SET state='abandoned' WHERE id=?", op)
					return result, e
				}
				return result, errors.New("commit outcome uncertain; run doctor and sync to reconcile")
			}
		}
		if e = s.record(ctx, v, next, p.Entries, op); e != nil {
			return result, errors.New("remote commit succeeded; local reconciliation required")
		}
		m = next
		result.Snapshot = next.ID
	} else {
		result.Snapshot = m.ID
	}
	// Downloads use only authenticated manifest entries from the planned head.
	for _, en := range p.Entries {
		switch en.Action {
		case planner.Download:
			if !downloads {
				result.Pending++
				continue
			}
			plain, e := s.readBlob(ctx, v, st, en.Remote)
			if e != nil {
				return result, e
			}
			if en.Local != "" {
				if !acceptRemote {
					result.Pending++
					continue
				}
				if e = restore.Replace(en.Root, en.Path, plain, en.Local); e != nil {
					return result, e
				}
			} else {
				if e = restore.Write(en.Root, en.Path, plain); e != nil {
					return result, e
				}
			}
			if e = s.setBase(ctx, v.ID, en.FileID, en.Remote.Digest); e != nil {
				return result, e
			}
			result.Downloaded++
		case planner.Clean:
			if en.Root != "" && en.Local == remoteDigest(en.Remote) {
				if e = s.setBase(ctx, v.ID, en.FileID, en.Local); e != nil {
					return result, e
				}
			}
		case planner.Missing, planner.Unmapped, planner.DeletePending:
			result.Pending++
		}
	}
	if changes == 0 && m.ID != "" {
		if _, e = s.DB.ExecContext(ctx, "UPDATE vaults SET checkpoint=?,generation=? WHERE id=? AND generation<=?", m.ID, m.Generation, v.ID, m.Generation); e != nil {
			return result, e
		}
	}
	return result, nil
}
func (s *Service) setBase(ctx context.Context, v, f domain.ID, d string) error {
	_, e := s.DB.ExecContext(ctx, "INSERT INTO file_sync_states(vault_id,file_id,digest) VALUES(?,?,?) ON CONFLICT(vault_id,file_id) DO UPDATE SET digest=excluded.digest", v, f, d)
	return e
}
func (s *Service) record(ctx context.Context, v Vault, m protocol.Manifest, entries []Entry, op domain.ID) error {
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	for _, en := range entries {
		d := en.Local
		if en.Action == planner.Tombstone {
			d = planner.Deleted
		} else if en.Action != planner.Upload && !(en.Action == planner.Clean && en.Local == remoteDigest(en.Remote)) {
			continue
		}
		if _, e = tx.ExecContext(ctx, "INSERT INTO file_sync_states VALUES(?,?,?) ON CONFLICT(vault_id,file_id) DO UPDATE SET digest=excluded.digest", v.ID, en.FileID, d); e != nil {
			return e
		}
	}
	if _, e = tx.ExecContext(ctx, "UPDATE vaults SET checkpoint=?,generation=? WHERE id=? AND generation<=?", m.ID, m.Generation, v.ID, m.Generation); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, "UPDATE operations SET state='committed' WHERE id=?", op); e != nil {
		return e
	}
	return tx.Commit()
}
