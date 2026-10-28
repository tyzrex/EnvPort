package application

import (
	"context"
	"errors"
	"github.com/envport-dev/envport/internal/domain"
	"io"
	"path/filepath"
	"strings"
	"testing"
)

type faultyStore struct {
	domain.ObjectStore
	mode string
}

func (f faultyStore) Put(ctx context.Context, k string, r io.Reader, c domain.Condition) (domain.ObjectInfo, error) {
	if strings.HasSuffix(k, "refs/main") {
		if f.mode == "reject" {
			return domain.ObjectInfo{}, errors.New("synthetic network outage")
		}
		if f.mode == "ambiguous" {
			out, e := f.ObjectStore.Put(ctx, k, r, c)
			if e != nil {
				return out, e
			}
			return domain.ObjectInfo{}, errors.New("synthetic lost response")
		}
	}
	return f.ObjectStore.Put(ctx, k, r, c)
}
func TestFailedAndAmbiguousCommitJournal(t *testing.T) {
	ctx := context.Background()
	s := testService(t, filepath.Join(t.TempDir(), "objects"))
	v := createVault(t, s)
	root := t.TempDir()
	write(t, root, ".env", []byte("FIXTURE=synthetic-journal\n"))
	if _, e := s.Track(ctx, v, root, true); e != nil {
		t.Fatal(e)
	}
	original := s.StoreFactory
	mode := "reject"
	s.StoreFactory = func(ctx context.Context, p Profile) (domain.ObjectStore, error) {
		st, e := original(ctx, p)
		if e != nil {
			return nil, e
		}
		return faultyStore{st, mode}, nil
	}
	p, e := s.PlanSync(ctx, v)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Execute(ctx, v, p, false, false); e == nil {
		t.Fatal("failed head write counted as backup")
	}
	fresh, _ := s.Vault(ctx, string(v.ID))
	if fresh.Checkpoint != "" {
		t.Fatal("failed commit advanced checkpoint")
	}
	if e = s.Reconcile(ctx, fresh); e != nil {
		t.Fatal(e)
	}
	var abandoned int
	s.DB.QueryRow("SELECT count(*) FROM operations WHERE state='abandoned'").Scan(&abandoned)
	if abandoned != 1 {
		t.Fatal("orphan transaction not classified")
	}
	mode = "ambiguous"
	out := execute(t, s, v, false, false)
	if out.Snapshot == "" {
		t.Fatal("ambiguous successful commit not reconciled")
	}
	var committed int
	s.DB.QueryRow("SELECT count(*) FROM operations WHERE state='committed'").Scan(&committed)
	if committed != 1 {
		t.Fatal("successful transaction missing")
	}
}
func TestCrashAfterRemoteCommitReconcilesBaseline(t *testing.T) {
	ctx := context.Background()
	s := testService(t, filepath.Join(t.TempDir(), "objects"))
	v := createVault(t, s)
	root := t.TempDir()
	write(t, root, ".env", []byte("FIXTURE=before-crash\n"))
	s.Track(ctx, v, root, true)
	s.DB.Exec("CREATE TRIGGER simulate_crash BEFORE UPDATE OF state ON operations WHEN new.state='committed' BEGIN SELECT RAISE(ABORT,'synthetic interruption'); END")
	p, e := s.PlanSync(ctx, v)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Execute(ctx, v, p, false, false); e == nil {
		t.Fatal("crash injection did not fire")
	}
	s.DB.Exec("DROP TRIGGER simulate_crash")
	if e = s.Reconcile(ctx, v); e != nil {
		t.Fatal(e)
	}
	v, _ = s.Vault(ctx, string(v.ID))
	if v.Generation != 1 {
		t.Fatal("committed head not recovered")
	}
	write(t, root, ".env", []byte("FIXTURE=edited-after-crash\n"))
	out := execute(t, s, v, false, false)
	if out.Uploaded != 1 {
		t.Fatal("baseline not recovered")
	}
}
