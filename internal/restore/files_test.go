package restore

import (
	"bytes"
	"github.com/envport-dev/envport/internal/domain"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestRoundTripAndNoOverwrite(t *testing.T) {
	root := t.TempDir()
	b := []byte("\xef\xbb\xbfFIXTURE=synthetic\r\n#comment\n\x00\xff")
	if e := Write(root, "nested/.env", b); e != nil {
		t.Fatal(e)
	}
	got, e := Read(root, "nested/.env")
	if e != nil || !bytes.Equal(got, b) {
		t.Fatal("bytes changed")
	}
	if e = Write(root, "nested/.env", []byte("different")); e == nil {
		t.Fatal("overwrite accepted")
	}
	info, _ := os.Stat(filepath.Join(root, "nested/.env"))
	if info.Mode().Perm() != 0600 {
		t.Fatal("unsafe permissions")
	}
}
func TestSymlinkAndTraversal(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	if e := os.Symlink(outside, filepath.Join(root, "escape")); e != nil {
		t.Skip(e)
	}
	if e := Write(root, "escape/.env", []byte("synthetic")); e == nil {
		t.Fatal("symlink followed")
	}
	if _, e := Read(root, "escape/.env"); e == nil {
		t.Fatal("read symlink followed")
	}
	for _, p := range []string{"../.env", "/tmp/.env", `C:\env`, "a/../.env"} {
		if e := Write(root, p, nil); e == nil {
			t.Fatal("unsafe path accepted")
		}
	}
	if _, e := os.Stat(filepath.Join(outside, ".env")); e == nil {
		t.Fatal("escaped root")
	}
}
func TestConcurrentCreateOnly(t *testing.T) {
	root := t.TempDir()
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, v := range []string{"one", "two"} {
		wg.Add(1)
		go func(v string) { defer wg.Done(); results <- Write(root, ".env", []byte(v)) }(v)
	}
	wg.Wait()
	close(results)
	wins := 0
	for e := range results {
		if e == nil {
			wins++
		}
	}
	if wins != 1 {
		t.Fatal("concurrent overwrite")
	}
}
func TestExplicitReplacePreservesPreimage(t *testing.T) {
	root := t.TempDir()
	before := []byte("FIXTURE=before\n")
	after := []byte("FIXTURE=after\n")
	Write(root, ".env", before)
	if e := Replace(root, ".env", after, "incorrect"); e == nil {
		t.Fatal("stale preimage accepted")
	}
	if e := Replace(root, ".env", after, hash(before)); e != nil {
		t.Fatal(e)
	}
	files, _ := filepath.Glob(filepath.Join(root, ".envport-preimage-*"))
	if len(files) != 1 {
		t.Fatal("preimage missing")
	}
	b, _ := os.ReadFile(files[0])
	if !bytes.Equal(b, before) {
		t.Fatal("preimage changed")
	}
	os.WriteFile(filepath.Join(root, ".env"), []byte("later"), 0600)
	b, _ = os.ReadFile(files[0])
	if !bytes.Equal(b, before) {
		t.Fatal("preimage shared inode")
	}
}
func TestNoFollowFinalSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	os.WriteFile(target, []byte("unchanged"), 0600)
	if e := os.Symlink("target", filepath.Join(root, ".env")); e != nil {
		t.Skip(e)
	}
	if e := Write(root, ".env", nil); e == nil {
		t.Fatal("symlink accepted")
	}
	if _, e := Read(root, ".env"); e != domain.ErrUnsafePath {
		t.Fatal("read final symlink")
	}
}
