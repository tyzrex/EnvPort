package application

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"github.com/envport-dev/envport/internal/domain"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func legacyFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	data, e := os.ReadFile("../../testdata/legacy/SYNTHETIC_KEY.hex")
	if e != nil {
		t.Fatal(e)
	}
	key, e := hex.DecodeString(strings.TrimSpace(string(data)))
	if e != nil {
		t.Fatal(e)
	}
	os.WriteFile(filepath.Join(root, "key.bin"), key, 0600)
	if e = os.CopyFS(filepath.Join(root, "vault"), os.DirFS("../../testdata/legacy/vault")); e != nil {
		t.Fatal(e)
	}
	return root
}
func treeHash(t *testing.T, root string) [32]byte {
	t.Helper()
	var all []byte
	filepath.WalkDir(root, func(p string, d os.DirEntry, e error) error {
		if e != nil {
			t.Fatal(e)
		}
		if !d.IsDir() {
			b, e := os.ReadFile(p)
			if e != nil {
				t.Fatal(e)
			}
			all = append(all, b...)
		}
		return nil
	})
	return sha256.Sum256(all)
}
func TestOriginalStarterMigrationReadOnly(t *testing.T) {
	ctx := context.Background()
	source := legacyFixture(t)
	before := treeHash(t, source)
	s := testService(t, filepath.Join(t.TempDir(), "objects"))
	id := domain.ID("2a18106f58e664563215f0450e3c5bff")
	preview, e := s.MigrateLegacy(ctx, "imported", "shared", source, id, "", "", true)
	if e != nil || preview.Files != 2 || preview.Vault != "" {
		t.Fatal("preview failed")
	}
	recovery := filepath.Join(t.TempDir(), "recovery.age")
	receipt := filepath.Join(t.TempDir(), "receipt.json")
	out, e := s.MigrateLegacy(ctx, "imported", "shared", source, id, recovery, receipt, false)
	if e != nil {
		t.Fatal(e)
	}
	if !out.Verified || out.Files != 2 || !out.SourcePreserved {
		t.Fatal("unverified migration")
	}
	if before != treeHash(t, source) {
		t.Fatal("legacy source mutated")
	}
	v, e := s.Vault(ctx, "imported")
	if e != nil {
		t.Fatal(e)
	}
	history, e := s.History(ctx, v)
	if e != nil || len(history) != 1 || len(history[0].Projects) != 1 {
		t.Fatal("imported history missing")
	}
	target := t.TempDir()
	gitRepo(t, target)
	if _, e := os.Stat(filepath.Join(target, ".git")); e != nil {
		t.Fatal(e)
	}
	if _, e := exec.Command("git", "-C", target, "remote", "set-url", "origin", "https://example.test/fixtures/legacy.git").Output(); e != nil {
		t.Fatal(e)
	}
	if e = s.MapProject(ctx, v, history[0].Projects[0].ID, target); e != nil {
		t.Fatal(e)
	}
	plan, e := s.PlanRestore(ctx, v, "")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.ExecuteRestore(ctx, v, plan, false); e != nil {
		t.Fatal(e)
	}
	for path, fixture := range map[string]string{".env": "expected.bin", ".env.local": "expected.local.bin"} {
		expected, e := os.ReadFile("../../testdata/legacy/" + fixture)
		if e != nil {
			t.Fatal(e)
		}
		actual, e := os.ReadFile(filepath.Join(target, path))
		if e != nil || !bytes.Equal(expected, actual) {
			t.Fatal("migrated bytes differ from original")
		}
	}
	if e = s.VerifyRecovery(ctx, v, recovery); e != nil {
		t.Fatal(e)
	}
}
