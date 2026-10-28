package application

import (
	"context"
	"errors"
	"github.com/envport-dev/envport/internal/domain"
)

type Check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

func (s *Service) Doctor(ctx context.Context, v Vault) ([]Check, error) {
	out := []Check{}
	var integrity string
	e := s.DB.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&integrity)
	out = append(out, Check{"database", e == nil && integrity == "ok", "SQLite integrity"})
	_, e = s.Unlock(ctx, v)
	out = append(out, Check{"vault_key", e == nil, "encrypted key availability"})
	out = append(out, Check{"recovery", v.RecoveryVerified, "recovery bundle exported and verified"})
	st, e := s.OpenStore(ctx, v)
	if e != nil {
		out = append(out, Check{"storage", false, "storage unavailable"})
		return out, nil
	}
	defer st.Close()
	m, _, e := s.current(ctx, v, st)
	out = append(out, Check{"authenticated_head", e == nil, "authenticated history and trusted checkpoint"})
	if e != nil {
		return out, nil
	}
	caps := st.Capabilities()
	out = append(out, Check{"conditional_writes", caps.Verified && caps.ConditionalCreate && caps.ConditionalReplace, "provider capability test"})
	missing := false
	for _, p := range m.Projects {
		for _, f := range p.Files {
			if f.Deleted {
				continue
			}
			if _, e = s.readBlob(ctx, v, st, f); e != nil {
				missing = true
			}
		}
	}
	out = append(out, Check{"restore_readiness", !missing, "all current blobs authenticated and checksummed"})
	var pending int
	if e = s.DB.QueryRowContext(ctx, "SELECT count(*) FROM operations WHERE vault_id=? AND state='staged'", v.ID).Scan(&pending); e != nil {
		return out, e
	}
	out = append(out, Check{"journal", pending == 0, "staged commits may require sync reconciliation"})
	return out, nil
}
func (s *Service) PrunePreview(ctx context.Context, v Vault) ([]domain.ObjectInfo, error) {
	history, e := s.History(ctx, v)
	if e != nil {
		return nil, e
	}
	live := map[string]bool{namespace(v) + "refs/main": true}
	for _, m := range history {
		live[namespace(v)+"snapshots/"+string(m.ID)+".age"] = true
		for _, p := range m.Projects {
			for _, f := range p.Files {
				if !f.Deleted {
					live[namespace(v)+"blobs/"+string(f.Blob)+".age"] = true
				}
			}
		}
	}
	st, e := s.OpenStore(ctx, v)
	if e != nil {
		return nil, e
	}
	defer st.Close()
	out := []domain.ObjectInfo{}
	cursor := ""
	for {
		page, e := st.List(ctx, namespace(v), cursor, 1000)
		if e != nil {
			return nil, e
		}
		for _, o := range page.Objects {
			if !live[o.Key] {
				out = append(out, o)
			}
		}
		if page.Cursor == "" {
			break
		}
		if page.Cursor == cursor {
			return nil, errors.New("storage pagination did not advance")
		}
		cursor = page.Cursor
	}
	return out, nil
}

// ResolveLocal records the observed remote state as the base only after explicit user choice.
// The next backup then commits local bytes with CAS; remote history remains recoverable.
func (s *Service) ResolveLocal(ctx context.Context, v Vault, id domain.ID) error {
	p, e := s.PlanSync(ctx, v)
	if e != nil {
		return e
	}
	for _, en := range p.Entries {
		if en.FileID == id {
			if en.Action != "conflict" {
				return errors.New("file is not conflicted")
			}
			if en.Local == "" {
				return errors.New("local file is missing")
			}
			return s.setBase(ctx, v.ID, id, remoteDigest(en.Remote))
		}
	}
	return domain.ErrNotFound
}
