package discovery

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestCanonicalRemote(t *testing.T) {
	for _, raw := range []string{"git@GitHub.com:Org/Repo.git", "https://github.com/Org/Repo.git", "ssh://git@github.com:22/Org/Repo.git"} {
		got, e := CanonicalRemote(raw)
		if e != nil || got != "github.com/Org/Repo" {
			t.Errorf("canonicalization failed for %s", raw)
		}
	}
	a, _ := CanonicalRemote("https://git.example:8443/org/repo.git")
	if a != "git.example:8443/org/repo" {
		t.Fatal("port lost")
	}
	for _, raw := range []string{"/tmp/repo", "file:///tmp/repo", "https://user:secret@example.com/repo?token=x", "https://x/../repo", "https://x/", "malformed"} {
		if _, e := CanonicalRemote(raw); e == nil {
			t.Errorf("accepted unsupported remote %q", raw)
		}
	}
}
func TestExplicitScan(t *testing.T) {
	root := t.TempDir()
	for _, p := range []string{".env", ".env.local", ".env.example", ".env.sample", "node_modules/pkg/.env", ".venv/.env", "nested/.env.production"} {
		abs := filepath.Join(root, p)
		os.MkdirAll(filepath.Dir(abs), 0700)
		os.WriteFile(abs, []byte("FIXTURE=synthetic\n"), 0600)
	}
	outside := filepath.Join(t.TempDir(), ".env")
	os.WriteFile(outside, []byte("FIXTURE=other\n"), 0600)
	_ = os.Symlink(outside, filepath.Join(root, ".env.link"))
	r, e := Scan(context.Background(), []string{root})
	if e != nil {
		t.Fatal(e)
	}
	if len(r.Files) != 3 {
		t.Fatalf("want 3 files, got %d", len(r.Files))
	}
	if _, e = Scan(context.Background(), nil); e == nil {
		t.Fatal("implicit scan accepted")
	}
}
func TestNestedGitAndWorktreeMarker(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{root, filepath.Join(root, "nested")} {
		if out, e := exec.Command("git", "init", dir).CombinedOutput(); e != nil {
			t.Fatalf("git init: %s", out)
		}
		os.WriteFile(filepath.Join(dir, ".env"), []byte("FIXTURE=x\n"), 0600)
	}
	r, e := Scan(context.Background(), []string{root})
	if e != nil || len(r.Files) != 2 || r.Files[0].Root == r.Files[1].Root {
		t.Fatal("nested repositories collapsed")
	}
}
func FuzzCanonicalRemote(f *testing.F) {
	f.Add("git@example.com:org/repo.git")
	f.Add("https://host/repo")
	f.Fuzz(func(t *testing.T, s string) { _, _ = CanonicalRemote(s) })
}

func TestAncestorGitMarkerCannotExpandExplicitRoot(t *testing.T) {
	parent := t.TempDir()
	if e := os.Mkdir(filepath.Join(parent, ".git"), 0700); e != nil {
		t.Fatal(e)
	}
	root := filepath.Join(parent, "approved")
	os.Mkdir(root, 0700)
	os.WriteFile(filepath.Join(root, ".env"), []byte("FIXTURE=inside\n"), 0600)
	os.WriteFile(filepath.Join(parent, ".env"), []byte("FIXTURE=outside\n"), 0600)
	r, e := Scan(context.Background(), []string{root})
	if e != nil {
		t.Fatal(e)
	}
	if len(r.Files) != 1 || r.Files[0].Root != root || r.Files[0].Path != ".env" {
		t.Fatal("ancestor Git metadata expanded approved root")
	}
}

func TestSubdirectoryDoesNotInheritAncestorIdentity(t *testing.T) {
	parent := t.TempDir()
	for _, args := range [][]string{{"init", parent}, {"-C", parent, "remote", "add", "origin", "git@example.test:fixtures/ancestor.git"}} {
		if _, e := exec.Command("git", args...).Output(); e != nil {
			t.Fatal(e)
		}
	}
	root := filepath.Join(parent, "approved-subdir")
	os.Mkdir(root, 0700)
	os.WriteFile(filepath.Join(root, ".env"), []byte("FIXTURE=inside\n"), 0600)
	r, e := Scan(context.Background(), []string{root})
	if e != nil || len(r.Files) != 1 {
		t.Fatal("scan failed")
	}
	if r.Files[0].Identity != "" || r.Files[0].Root != root {
		t.Fatal("ancestor identity leaked into independent explicit root")
	}
}
