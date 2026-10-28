package application

import (
	"context"
	"github.com/envport-dev/envport/internal/domain"
)

// Reconcile classifies interrupted transactions using authenticated snapshot ancestry.
// A staged upload is not a backup unless its manifest is in committed history.
func (s *Service) Reconcile(ctx context.Context, v Vault) error {
	history, e := s.History(ctx, v)
	if e != nil {
		return e
	}
	committed := map[domain.ID]int64{}
	for _, m := range history {
		committed[m.ID] = m.Generation
	}
	rows, e := s.DB.QueryContext(ctx, "SELECT id,snapshot_id FROM operations WHERE vault_id=? AND state='staged' ORDER BY created_at,id", v.ID)
	if e != nil {
		return e
	}
	type op struct{ id, snapshot domain.ID }
	pending := []op{}
	for rows.Next() {
		var o op
		if e = rows.Scan(&o.id, &o.snapshot); e != nil {
			rows.Close()
			return e
		}
		pending = append(pending, o)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, o := range pending {
		tx, e := s.DB.BeginTx(ctx, nil)
		if e != nil {
			return e
		}
		generation, ok := committed[o.snapshot]
		state := "abandoned"
		if ok {
			state = "committed"
			var checkpointGeneration int64
			if e = tx.QueryRowContext(ctx, "SELECT generation FROM vaults WHERE id=?", v.ID).Scan(&checkpointGeneration); e != nil {
				tx.Rollback()
				return e
			}
			if generation >= checkpointGeneration {
				if _, e = tx.ExecContext(ctx, "INSERT INTO file_sync_states(vault_id,file_id,digest) SELECT ?,file_id,digest FROM operation_files WHERE operation_id=? AND true ON CONFLICT(vault_id,file_id) DO UPDATE SET digest=excluded.digest", v.ID, o.id); e != nil {
					tx.Rollback()
					return e
				}
				if _, e = tx.ExecContext(ctx, "UPDATE vaults SET checkpoint=?,generation=? WHERE id=? AND generation<=?", o.snapshot, generation, v.ID, generation); e != nil {
					tx.Rollback()
					return e
				}
			}
		}
		if _, e = tx.ExecContext(ctx, "UPDATE operations SET state=? WHERE id=?", state, o.id); e != nil {
			tx.Rollback()
			return e
		}
		if e = tx.Commit(); e != nil {
			return e
		}
	}
	return nil
}
