package filesystem

import (
	"bytes"
	"context"
	"errors"
	"github.com/envport-dev/envport/internal/domain"
	"github.com/envport-dev/envport/internal/storage"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestCrossConnectionCAS(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "objects")
	a, e := Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	b, e := Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	ctx := context.Background()
	initial, e := a.Put(ctx, "refs/main", bytes.NewBufferString("original"), domain.Condition{Mode: domain.CreateIfAbsent})
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i, s := range []*Store{a, b} {
		wg.Add(1)
		go func(s *Store, i int) {
			defer wg.Done()
			_, e := s.Put(ctx, "refs/main", bytes.NewReader([]byte{byte(i)}), domain.Condition{Mode: domain.IfETagMatch, ETag: initial.ETag})
			results <- e
		}(s, i)
	}
	wg.Wait()
	close(results)
	wins, conflicts := 0, 0
	for e := range results {
		if e == nil {
			wins++
		} else if errors.Is(e, domain.ErrPrecondition) {
			conflicts++
		} else {
			t.Fatal(e)
		}
	}
	if wins != 1 || conflicts != 1 {
		t.Fatal("CAS lost an update")
	}
}
func TestContractAndPagination(t *testing.T) {
	s, e := Open(filepath.Join(t.TempDir(), "objects"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	ctx := context.Background()
	if _, e = storage.Probe(ctx, s); e != nil {
		t.Fatal(e)
	}
	for _, k := range []string{"a/1", "a/2", "a/3", "b/1"} {
		if _, e = s.Put(ctx, k, bytes.NewReader(nil), domain.Condition{Mode: domain.CreateIfAbsent}); e != nil {
			t.Fatal(e)
		}
	}
	p, e := s.List(ctx, "a/", "", 2)
	if e != nil || len(p.Objects) != 2 || p.Cursor == "" {
		t.Fatal("bad first page")
	}
	next, e := s.List(ctx, "a/", p.Cursor, 2)
	if e != nil || len(next.Objects) != 1 || next.Cursor != "" {
		t.Fatal("bad second page")
	}
	if _, e = s.Put(ctx, "../escape", bytes.NewReader(nil), domain.Condition{}); e == nil {
		t.Fatal("unsafe key accepted")
	}
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, e = s.Put(ctx, "canceled", bytes.NewReader(nil), domain.Condition{}); e == nil {
		t.Fatal("canceled write accepted")
	}
}
func TestSymlinkDatabaseRejected(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "objects")
	if e := os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(filepath.Join(t.TempDir(), "victim"), filepath.Join(dir, "objects.db")); e != nil {
		t.Skip("symlinks unavailable")
	}
	if s, e := Open(dir); e == nil {
		s.Close()
		t.Fatal("database symlink accepted")
	}
}
