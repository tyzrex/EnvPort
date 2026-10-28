package application

import (
	"context"
	"errors"
	"github.com/envport-dev/envport/internal/domain"
	planner "github.com/envport-dev/envport/internal/sync"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type racingStore struct {
	domain.ObjectStore
	arrived chan<- struct{}
	release <-chan struct{}
}

func (s racingStore) Put(ctx context.Context, key string, r io.Reader, c domain.Condition) (domain.ObjectInfo, error) {
	if strings.HasSuffix(key, "refs/main") {
		select {
		case s.arrived <- struct{}{}:
		case <-ctx.Done():
			return domain.ObjectInfo{}, ctx.Err()
		}
		select {
		case <-s.release:
		case <-ctx.Done():
			return domain.ObjectInfo{}, ctx.Err()
		}
	}
	return s.ObjectStore.Put(ctx, key, r, c)
}
func TestConcurrentSnapshotCommitsOneWinnerThenConflict(t *testing.T) {
	ctx := context.Background()
	objects := filepath.Join(t.TempDir(), "objects")
	a := testService(t, objects)
	va := createVault(t, a)
	source := t.TempDir()
	write(t, source, ".env", []byte("FIXTURE=common-base\n"))
	a.Track(ctx, va, source, true)
	execute(t, a, va, false, false)
	recovery := filepath.Join(t.TempDir(), "recovery.age")
	a.ExportRecovery(ctx, va, recovery)
	b := testService(t, objects)
	vb, e := b.Join(ctx, "personal", "shared", recovery)
	if e != nil {
		t.Fatal(e)
	}
	history, e := b.History(ctx, vb)
	if e != nil {
		t.Fatal(e)
	}
	target := t.TempDir()
	if e = b.MapProject(ctx, vb, history[0].Projects[0].ID, target); e != nil {
		t.Fatal(e)
	}
	rp, e := b.PlanRestore(ctx, vb, "")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = b.ExecuteRestore(ctx, vb, rp, false); e != nil {
		t.Fatal(e)
	}
	write(t, source, ".env", []byte("FIXTURE=writer-a\n"))
	write(t, target, ".env", []byte("FIXTURE=writer-b\n"))
	va, _ = a.Vault(ctx, string(va.ID))
	pa, e := a.PlanSync(ctx, va)
	if e != nil {
		t.Fatal(e)
	}
	pb, e := b.PlanSync(ctx, vb)
	if e != nil {
		t.Fatal(e)
	}
	for i, p := range []Plan{pa, pb} {
		if len(p.Entries) != 1 {
			t.Fatalf("writer %d planned %d entries", i, len(p.Entries))
		}
		if p.Entries[0].Action != planner.Upload {
			t.Fatalf("writer %d planned %s (root %s)", i, p.Entries[0].Action, p.Entries[0].Root)
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	arrived, release := make(chan struct{}, 2), make(chan struct{})
	for _, s := range []*Service{a, b} {
		factory := s.StoreFactory
		s.StoreFactory = func(ctx context.Context, p Profile) (domain.ObjectStore, error) {
			st, e := factory(ctx, p)
			if e != nil {
				return nil, e
			}
			return racingStore{st, arrived, release}, nil
		}
	}
	type outcome struct {
		s   *Service
		v   Vault
		err error
	}
	results := make(chan outcome, 2)
	go func() { _, e := a.Execute(ctx, va, pa, false, false); results <- outcome{a, va, e} }()
	go func() { _, e := b.Execute(ctx, vb, pb, false, false); results <- outcome{b, vb, e} }()
	for i := 0; i < 2; i++ {
		select {
		case <-arrived:
		case o := <-results:
			close(release)
			t.Fatalf("writer failed before CAS barrier: %v", o.err)
		case <-ctx.Done():
			close(release)
			t.Fatal("snapshot concurrency barrier timed out")
		}
	}
	close(release)
	wins, losses := 0, 0
	var loser outcome
	for i := 0; i < 2; i++ {
		o := <-results
		if o.err == nil {
			wins++
		} else if errors.Is(o.err, domain.ErrPrecondition) {
			losses++
			loser = o
		} else {
			t.Fatal(o.err)
		}
	}
	if wins != 1 || losses != 1 {
		t.Fatal("concurrent snapshot head did not have exactly one winner")
	}
	replan, e := loser.s.PlanSync(ctx, loser.v)
	if e != nil {
		t.Fatal(e)
	}
	if len(replan.Entries) != 1 || replan.Entries[0].Action != planner.Conflict {
		t.Fatal("losing writer did not replan into conflict")
	}
	history, e = loser.s.History(ctx, loser.v)
	if e != nil || len(history) != 2 {
		t.Fatal("lost or duplicated committed history")
	}
}
