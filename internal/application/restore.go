package application

import (
	"context"
	"errors"
	"github.com/envport-dev/envport/internal/domain"
	"github.com/envport-dev/envport/internal/restore"
	"github.com/envport-dev/envport/pkg/protocol"
	"sort"
)

type RestoreEntry struct {
	ProjectID domain.ID `json:"project_id"`
	FileID    domain.ID `json:"file_id"`
	Path      string    `json:"path"`
	Root      string    `json:"root,omitempty"`
	State     string    `json:"state"`
	Bytes     int64     `json:"bytes"`
	local     string
	file      protocol.File
}
type RestorePlan struct {
	Vault    domain.ID      `json:"vault_id"`
	Storage  string         `json:"storage"`
	Snapshot domain.ID      `json:"snapshot_id"`
	Entries  []RestoreEntry `json:"entries"`
}

func (s *Service) PlanRestore(ctx context.Context, v Vault, snapshot domain.ID) (RestorePlan, error) {
	out := RestorePlan{Vault: v.ID, Storage: v.Profile, Entries: []RestoreEntry{}}
	st, e := s.OpenStore(ctx, v)
	if e != nil {
		return out, e
	}
	defer st.Close()
	m, _, e := s.current(ctx, v, st)
	if e != nil {
		return out, e
	}
	if snapshot != "" {
		m, e = s.readManifest(ctx, v, st, snapshot)
		if e != nil {
			return out, e
		}
	}
	out.Snapshot = m.ID
	projects, e := s.Projects(ctx, v)
	if e != nil {
		return out, e
	}
	roots := map[domain.ID]string{}
	for _, p := range projects {
		roots[p.ID] = p.Root
	}
	for _, p := range m.Projects {
		for _, f := range p.Files {
			if f.Deleted {
				continue
			}
			en := RestoreEntry{ProjectID: p.ID, FileID: f.ID, Path: f.Path, Root: roots[p.ID], Bytes: f.Size, file: f, State: "create"}
			if en.Root == "" {
				en.State = "unmapped"
			} else {
				b, e := restore.Read(en.Root, en.Path)
				if e == nil {
					en.local = digest(b)
					if en.local == f.Digest {
						en.State = "identical"
					} else {
						en.State = "exists"
					}
				} else if !errors.Is(e, domain.ErrNotFound) {
					return out, e
				}
			}
			out.Entries = append(out.Entries, en)
		}
	}
	sort.Slice(out.Entries, func(i, j int) bool {
		a, b := out.Entries[i], out.Entries[j]
		if a.ProjectID == b.ProjectID {
			return a.Path < b.Path
		}
		return a.ProjectID < b.ProjectID
	})
	return out, nil
}
func (s *Service) ExecuteRestore(ctx context.Context, v Vault, p RestorePlan, acceptRemote bool) (Result, error) {
	out := Result{Snapshot: p.Snapshot}
	if p.Vault != v.ID {
		return out, domain.ErrCorrupt
	}
	for _, en := range p.Entries {
		if en.State == "exists" && !acceptRemote {
			return out, errors.New("restore destination exists; review plan and explicitly use --accept-remote to retain preimages and replace")
		}
		if en.State == "unmapped" {
			return out, errors.New("unmapped projects; use project map or restore --scan")
		}
	}
	st, e := s.OpenStore(ctx, v)
	if e != nil {
		return out, e
	}
	defer st.Close()
	current, _, e := s.current(ctx, v, st)
	if e != nil {
		return out, e
	}
	for _, en := range p.Entries {
		if e = ctx.Err(); e != nil {
			return out, e
		}
		if en.State == "identical" {
			continue
		}
		plain, e := s.readBlob(ctx, v, st, en.file)
		if e != nil {
			return out, e
		}
		if en.State == "exists" {
			e = restore.Replace(en.Root, en.Path, plain, en.local)
		} else {
			e = restore.Write(en.Root, en.Path, plain)
		}
		if e != nil {
			return out, e
		}
		out.Downloaded++
		if p.Snapshot == current.ID {
			if e = s.setBase(ctx, v.ID, en.FileID, en.file.Digest); e != nil {
				return out, e
			}
		}
	}
	return out, nil
}
