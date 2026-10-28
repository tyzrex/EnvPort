package application

import (
	"context"
	"database/sql"
	"errors"
	"github.com/envport-dev/envport/internal/discovery"
	"github.com/envport-dev/envport/internal/domain"
	"github.com/envport-dev/envport/pkg/protocol"
	"path/filepath"
)

func (s *Service) Projects(ctx context.Context, v Vault) ([]Project, error) {
	rows, e := s.DB.QueryContext(ctx, "SELECT id,identity,root FROM projects WHERE vault_id=? ORDER BY id", v.ID)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Project{}
	for rows.Next() {
		var p Project
		if e = rows.Scan(&p.ID, &p.Identity, &p.Root); e != nil {
			return nil, e
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
func (s *Service) Track(ctx context.Context, v Vault, root string, localOnly bool) ([]Project, error) {
	abs, e := filepath.Abs(root)
	if e != nil {
		return nil, e
	}
	result, e := discovery.Scan(ctx, []string{abs})
	if e != nil {
		return nil, e
	}
	if len(result.Files) == 0 {
		return nil, errors.New("no eligible environment files found")
	}
	st, e := s.OpenStore(ctx, v)
	if e != nil {
		return nil, e
	}
	defer st.Close()
	remote, _, e := s.current(ctx, v, st)
	if e != nil {
		return nil, e
	}
	existing, e := s.Projects(ctx, v)
	if e != nil {
		return nil, e
	}
	mapped := map[string]Project{}
	for _, p := range existing {
		mapped[p.Root] = p
	}
	seen := map[domain.ID]Project{}
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	for _, candidate := range result.Files {
		p, ok := mapped[candidate.Root]
		if !ok {
			identity, e := discovery.Identity(ctx, candidate.Root)
			if e != nil && !localOnly {
				return nil, e
			}
			if identity == "" && !localOnly {
				return nil, errors.New("project has no unambiguous Git remote; use --local for explicit UUID identity")
			}
			p = Project{ID: domain.NewID(), Identity: identity, Root: candidate.Root}
			if localOnly {
				p.Identity = ""
			}
			if p.Identity != "" {
				for _, rp := range remote.Projects {
					if rp.Identity == p.Identity {
						p.ID = rp.ID
					}
				}
				for _, ep := range existing {
					if ep.Identity == p.Identity && ep.Root != p.Root {
						return nil, errors.New("git identity already mapped; use project map explicitly")
					}
				}
			}
			for _, mp := range mapped {
				if mp.ID == p.ID && mp.Root != p.Root {
					return nil, errors.New("multiple checkouts share identity; map a single checkout explicitly")
				}
			}
			if _, e = tx.ExecContext(ctx, "INSERT INTO projects(vault_id,id,identity,root) VALUES(?,?,?,?)", v.ID, p.ID, p.Identity, p.Root); e != nil {
				return nil, errors.New("project mapping collision")
			}
			mapped[candidate.Root] = p
		}
		id := domain.NewID()
		for _, rp := range remote.Projects {
			if rp.ID == p.ID {
				for _, rf := range rp.Files {
					if rf.Path == candidate.Path {
						id = rf.ID
					}
				}
			}
		}
		if _, e = tx.ExecContext(ctx, "INSERT INTO tracked_files(vault_id,project_id,id,path) VALUES(?,?,?,?) ON CONFLICT(vault_id,project_id,path) DO NOTHING", v.ID, p.ID, id, candidate.Path); e != nil {
			return nil, e
		}
		seen[p.ID] = p
	}
	if e = tx.Commit(); e != nil {
		return nil, e
	}
	out := []Project{}
	for _, p := range seen {
		out = append(out, p)
	}
	return out, nil
}
func (s *Service) MapProject(ctx context.Context, v Vault, id domain.ID, root string) error {
	if !id.Valid() {
		return domain.ErrUnsafePath
	}
	abs, e := filepath.Abs(root)
	if e != nil {
		return e
	}
	if e = discovery.CheckRoot(abs); e != nil {
		return e
	}
	st, e := s.OpenStore(ctx, v)
	if e != nil {
		return e
	}
	defer st.Close()
	m, _, e := s.current(ctx, v, st)
	if e != nil {
		return e
	}
	var p *protocol.Project
	for i := range m.Projects {
		if m.Projects[i].ID == id {
			p = &m.Projects[i]
		}
	}
	if p == nil {
		return domain.ErrNotFound
	}
	if p.Identity != "" {
		identity, e := discovery.Identity(ctx, abs)
		if e != nil || identity != p.Identity {
			return errors.New("checkout identity does not match project")
		}
	}
	return s.persistMap(ctx, v, *p, abs)
}
func (s *Service) persistMap(ctx context.Context, v Vault, p protocol.Project, root string) error {
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, "INSERT INTO projects(vault_id,id,identity,root) VALUES(?,?,?,?) ON CONFLICT(vault_id,id) DO UPDATE SET root=excluded.root", v.ID, p.ID, p.Identity, root); e != nil {
		return errors.New("project location already mapped")
	}
	for _, f := range p.Files {
		if _, e = tx.ExecContext(ctx, "INSERT INTO tracked_files(vault_id,project_id,id,path,removed) VALUES(?,?,?,?,?) ON CONFLICT(vault_id,id) DO UPDATE SET path=excluded.path", v.ID, p.ID, f.ID, f.Path, f.Deleted); e != nil {
			return e
		}
	}
	return tx.Commit()
}
func (s *Service) AutoMap(ctx context.Context, v Vault, roots []string) error {
	result, e := discovery.Scan(ctx, roots)
	if e != nil {
		return e
	}
	st, e := s.OpenStore(ctx, v)
	if e != nil {
		return e
	}
	defer st.Close()
	m, _, e := s.current(ctx, v, st)
	if e != nil {
		return e
	}
	candidates := map[string]map[string]bool{}
	for _, f := range result.Files {
		if f.Identity != "" {
			if candidates[f.Identity] == nil {
				candidates[f.Identity] = map[string]bool{}
			}
			candidates[f.Identity][f.Root] = true
		}
	}
	// Include empty Git checkouts: a fresh clone may have no .env files yet.
	repos, e := discovery.FindRepositories(ctx, roots)
	if e != nil {
		return e
	}
	for _, r := range repos {
		id, e := discovery.Identity(ctx, r)
		if e != nil {
			return e
		}
		if id != "" {
			if candidates[id] == nil {
				candidates[id] = map[string]bool{}
			}
			candidates[id][r] = true
		}
	}
	for _, p := range m.Projects {
		matches := candidates[p.Identity]
		if len(matches) > 1 {
			return errors.New("multiple checkouts match a project; use project map explicitly")
		}
		for root := range matches {
			if e = s.persistMap(ctx, v, p, root); e != nil {
				return e
			}
		}
	}
	return nil
}
func (s *Service) RemoveFile(ctx context.Context, v Vault, id domain.ID) error {
	r, e := s.DB.ExecContext(ctx, "UPDATE tracked_files SET removed=1 WHERE vault_id=? AND id=?", v.ID, id)
	if e != nil {
		return e
	}
	n, _ := r.RowsAffected()
	if n == 0 {
		return domain.ErrNotFound
	}
	return nil
}
func (s *Service) Untrack(ctx context.Context, v Vault, id domain.ID) error {
	r, e := s.DB.ExecContext(ctx, "DELETE FROM tracked_files WHERE vault_id=? AND id=?", v.ID, id)
	if e != nil {
		return e
	}
	n, _ := r.RowsAffected()
	if n == 0 {
		return domain.ErrNotFound
	}
	return nil
}
func base(ctx context.Context, db interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, v domain.ID, f domain.ID) (string, error) {
	var d string
	e := db.QueryRowContext(ctx, "SELECT digest FROM file_sync_states WHERE vault_id=? AND file_id=?", v, f).Scan(&d)
	if errors.Is(e, sql.ErrNoRows) {
		return "", nil
	}
	return d, e
}
