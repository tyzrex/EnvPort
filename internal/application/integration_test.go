package application

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/envport-dev/envport/internal/domain"
	"github.com/envport-dev/envport/internal/persistence"
	"github.com/envport-dev/envport/internal/restore"
	"github.com/envport-dev/envport/internal/storage/filesystem"
	planner "github.com/envport-dev/envport/internal/sync"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func testService(t *testing.T, objects string) *Service {
	t.Helper()
	db, e := persistence.Open(filepath.Join(t.TempDir(), "state"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close() })
	s := New(db, func(_ context.Context, p Profile) (domain.ObjectStore, error) { return filesystem.Open(p.Path) }, func(kind string) (string, error) {
		if kind == "recovery" {
			return "synthetic-independent-recovery-passphrase", nil
		}
		return "synthetic-local-unlock-passphrase", nil
	})
	if e = s.AddProfile(context.Background(), Profile{Name: "shared", Driver: "filesystem", Path: objects}); e != nil {
		t.Fatal(e)
	}
	return s
}
func createVault(t *testing.T, s *Service) Vault {
	t.Helper()
	ctx := context.Background()
	v, e := s.CreateVault(ctx, "personal", "shared")
	if e != nil {
		t.Fatal(e)
	}
	recovery := filepath.Join(t.TempDir(), "recovery.age")
	if e = s.ExportRecovery(ctx, v, recovery); e != nil {
		t.Fatal(e)
	}
	v, e = s.Vault(ctx, "personal")
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func gitRepo(t *testing.T, p string) {
	t.Helper()
	if e := os.MkdirAll(p, 0700); e != nil {
		t.Fatal(e)
	}
	for _, args := range [][]string{{"init", p}, {"-C", p, "remote", "add", "origin", "git@example.test:fixtures/project.git"}} {
		if _, e := exec.Command("git", args...).Output(); e != nil {
			t.Fatal(e)
		}
	}
}
func write(t *testing.T, root, path string, b []byte) {
	t.Helper()
	p := filepath.Join(root, path)
	if e := os.MkdirAll(filepath.Dir(p), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(p, b, 0600); e != nil {
		t.Fatal(e)
	}
}
func execute(t *testing.T, s *Service, v Vault, downloads, accept bool) Result {
	t.Helper()
	ctx := context.Background()
	v, e := s.Vault(ctx, string(v.ID))
	if e != nil {
		t.Fatal(e)
	}
	p, e := s.PlanSync(ctx, v)
	if e != nil {
		t.Fatal(e)
	}
	out, e := s.Execute(ctx, v, p, downloads, accept)
	if e != nil {
		t.Fatal(e)
	}
	return out
}
func TestTwoInstallationsRecoverySyncAndHistory(t *testing.T) {
	ctx := context.Background()
	objects := filepath.Join(t.TempDir(), "objects")
	a := testService(t, objects)
	va := createVault(t, a)
	source := filepath.Join(t.TempDir(), "linux", "projects", "original-name")
	gitRepo(t, source)
	fixtures := map[string][]byte{}
	for i := 0; i < 105; i++ {
		name := fmt.Sprintf("apps/service-%03d/.env.local", i)
		data := []byte(fmt.Sprintf("# synthetic fixture %d\r\nKEY=fixture-%d\r\n\x00\xff", i, i))
		write(t, source, name, data)
		fixtures[name] = data
	}
	write(t, source, ".env.example", []byte("EXAMPLE=ignored\n"))
	projects, e := a.Track(ctx, va, source, false)
	if e != nil || len(projects) != 1 {
		t.Fatalf("track: %v", e)
	}
	first := execute(t, a, va, false, false)
	if first.Uploaded != 105 {
		t.Fatalf("uploaded %d", first.Uploaded)
	}
	recovery := filepath.Join(t.TempDir(), "portable.age")
	if e = a.ExportRecovery(ctx, va, recovery); e != nil {
		t.Fatal(e)
	}
	b := testService(t, objects)
	vb, e := b.Join(ctx, "personal", "shared", recovery)
	if e != nil {
		t.Fatal(e)
	}
	da, _ := a.Device(ctx)
	db, _ := b.Device(ctx)
	if da == db {
		t.Fatal("devices share identity")
	}
	destination := filepath.Join(t.TempDir(), "mac", "Code", "renamed-checkout")
	gitRepo(t, destination)
	if e = b.AutoMap(ctx, vb, []string{filepath.Dir(destination)}); e != nil {
		t.Fatal(e)
	}
	rp, e := b.PlanRestore(ctx, vb, "")
	if e != nil || len(rp.Entries) != 105 {
		t.Fatalf("restore plan: %v", e)
	}
	rr, e := b.ExecuteRestore(ctx, vb, rp, false)
	if e != nil || rr.Downloaded != 105 {
		t.Fatalf("restore: %v", e)
	}
	for name, data := range fixtures {
		actual, e := restore.Read(destination, name)
		if e != nil || !bytes.Equal(data, actual) {
			t.Fatal("byte-for-byte restore failed")
		}
	}
	path := "apps/service-000/.env.local"
	changed := []byte("KEY=synthetic-from-mac\n")
	write(t, destination, path, changed)
	second := execute(t, b, vb, false, false)
	if second.Uploaded != 1 {
		t.Fatal("changed file not backed up")
	}
	va, _ = a.Vault(ctx, string(va.ID))
	p, e := a.PlanSync(ctx, va)
	if e != nil {
		t.Fatal(e)
	}
	downloads := 0
	for _, en := range p.Entries {
		if en.Action == planner.Download {
			downloads++
		}
	}
	if downloads != 1 {
		t.Fatal("remote update not planned")
	}
	pending, e := a.Execute(ctx, va, p, true, false)
	if e != nil || pending.Pending != 1 {
		t.Fatal("implicit overwrite was not refused")
	}
	actual, _ := restore.Read(source, path)
	if !bytes.Equal(actual, fixtures[path]) {
		t.Fatal("source silently overwritten")
	}
	res := execute(t, a, va, true, true)
	if res.Downloaded != 1 {
		t.Fatal("explicit remote acceptance failed")
	}
	actual, _ = restore.Read(source, path)
	if !bytes.Equal(actual, changed) {
		t.Fatal("sync bytes changed")
	}
	// Both devices independently modify the same common version.
	execute(t, b, vb, true, false)
	write(t, source, path, []byte("KEY=synthetic-linux-edit\n"))
	write(t, destination, path, []byte("KEY=synthetic-mac-edit\n"))
	execute(t, a, va, false, false)
	vb, _ = b.Vault(ctx, string(vb.ID))
	conflict, e := b.PlanSync(ctx, vb)
	if e != nil {
		t.Fatal(e)
	}
	var file domain.ID
	for _, en := range conflict.Entries {
		if en.Path == path {
			if en.Action != planner.Conflict {
				t.Fatalf("want conflict, got %s", en.Action)
			}
			file = en.FileID
		}
	}
	if _, e = b.Execute(ctx, vb, conflict, true, true); !errors.Is(e, domain.ErrConflict) {
		t.Fatal("conflict overwritten")
	}
	before, _ := restore.Read(destination, path)
	if string(before) != "KEY=synthetic-mac-edit\n" {
		t.Fatal("conflict bytes changed")
	}
	if e = b.ResolveLocal(ctx, vb, file); e != nil {
		t.Fatal(e)
	}
	execute(t, b, vb, false, false)
	history, e := b.History(ctx, vb)
	if e != nil || len(history) != 4 {
		t.Fatalf("history: %v count %d", e, len(history))
	}
	historical, e := b.PlanRestore(ctx, vb, first.Snapshot)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = b.ExecuteRestore(ctx, vb, historical, false); e == nil {
		t.Fatal("historical restore overwrote existing file")
	}
	// Missing local files do not create remote tombstones.
	if e = os.Remove(filepath.Join(destination, path)); e != nil {
		t.Fatal(e)
	}
	vb, _ = b.Vault(ctx, string(vb.ID))
	missing, e := b.PlanSync(ctx, vb)
	if e != nil {
		t.Fatal(e)
	}
	for _, en := range missing.Entries {
		if en.FileID == file && en.Action != planner.Missing {
			t.Fatalf("missing treated as %s", en.Action)
		}
	}
	out, e := b.Execute(ctx, vb, missing, false, false)
	if e != nil || out.Uploaded != 0 {
		t.Fatal("absence caused commit")
	}
	// Reopen with no in-memory identities and verify recovery plus private envelope.
	fresh := New(b.DB, b.StoreFactory, b.Secret)
	if _, e = fresh.Unlock(ctx, vb); e != nil {
		t.Fatal("fresh unlock failed")
	}
	checks, e := fresh.Doctor(ctx, vb)
	if e != nil {
		t.Fatal(e)
	}
	for _, c := range checks {
		if !c.OK {
			t.Fatalf("doctor: %s", c.Name)
		}
	}
	// The object database and state contain no file values.
	for _, p := range []string{filepath.Join(objects, "objects.db"), filepath.Join(b.DB.Dir, "state.db")} {
		raw, _ := os.ReadFile(p)
		if bytes.Contains(raw, []byte("synthetic-mac-edit")) {
			t.Fatal("plaintext leaked to persistence")
		}
	}
}
func TestStalePlansAndRollback(t *testing.T) {
	ctx := context.Background()
	objects := filepath.Join(t.TempDir(), "objects")
	s := testService(t, objects)
	v := createVault(t, s)
	root := t.TempDir()
	write(t, root, ".env", []byte("FIXTURE=one\n"))
	if _, e := s.Track(ctx, v, root, true); e != nil {
		t.Fatal(e)
	}
	first := execute(t, s, v, false, false)
	v, _ = s.Vault(ctx, string(v.ID))
	st, e := s.OpenStore(ctx, v)
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	oldHead, _, e := readObject(ctx, st, namespace(v)+"refs/main")
	if e != nil {
		t.Fatal(e)
	}
	plan, e := s.PlanSync(ctx, v)
	if e != nil {
		t.Fatal(e)
	}
	write(t, root, ".env", []byte("FIXTURE=two\n"))
	if _, e = s.Execute(ctx, v, plan, false, false); e == nil {
		t.Fatal("stale local preview accepted")
	}
	execute(t, s, v, false, false)
	if _, e = s.Execute(ctx, v, plan, false, false); !errors.Is(e, domain.ErrPrecondition) {
		t.Fatal("stale remote preview accepted")
	}
	v, _ = s.Vault(ctx, string(v.ID))
	if _, e = st.Put(ctx, namespace(v)+"refs/main", bytes.NewReader(oldHead), domain.Condition{Mode: domain.Unconditional}); e != nil {
		t.Fatal(e)
	}
	if _, e = s.PlanSync(ctx, v); !errors.Is(e, domain.ErrRollback) {
		t.Fatal("rollback accepted")
	}
	if first.Snapshot == "" {
		t.Fatal("missing snapshot")
	}
}
func TestIsolationAndTampering(t *testing.T) {
	ctx := context.Background()
	objects := filepath.Join(t.TempDir(), "objects")
	s := testService(t, objects)
	a := createVault(t, s)
	b, e := s.CreateVault(ctx, "work", "shared")
	if e != nil {
		t.Fatal(e)
	}
	root := t.TempDir()
	write(t, root, ".env", []byte("KEY=synthetic-private\n"))
	s.Track(ctx, a, root, true)
	execute(t, s, a, false, false)
	st, _ := s.OpenStore(ctx, a)
	defer st.Close()
	m, _, e := s.current(ctx, a, st)
	if e != nil {
		t.Fatal(e)
	}
	blob := m.Projects[0].Files[0]
	if _, e = s.readBlob(ctx, b, st, blob); e == nil {
		t.Fatal("cross-vault access accepted")
	}
	data, _, e := readObject(ctx, st, namespace(a)+"blobs/"+string(blob.Blob)+".age")
	if e != nil {
		t.Fatal(e)
	}
	data[len(data)-1] ^= 1
	st.Put(ctx, namespace(a)+"blobs/"+string(blob.Blob)+".age", bytes.NewReader(data), domain.Condition{Mode: domain.Unconditional})
	if _, e = s.readBlob(ctx, a, st, blob); e == nil {
		t.Fatal("tampering accepted")
	}
}
func TestRecoveryRequiredBeforeBackup(t *testing.T) {
	ctx := context.Background()
	s := testService(t, filepath.Join(t.TempDir(), "objects"))
	v, e := s.CreateVault(ctx, "personal", "shared")
	if e != nil {
		t.Fatal(e)
	}
	root := t.TempDir()
	write(t, root, ".env", []byte("FIXTURE=synthetic\n"))
	if _, e = s.Track(ctx, v, root, true); e != nil {
		t.Fatal(e)
	}
	p, e := s.PlanSync(ctx, v)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Execute(ctx, v, p, false, false); e == nil {
		t.Fatal("unrecoverable backup permitted")
	}
}

func TestHistoricalRestoreTombstoneAndRetention(t *testing.T) {
	ctx := context.Background()
	s := testService(t, filepath.Join(t.TempDir(), "objects"))
	v := createVault(t, s)
	root := t.TempDir()
	original := []byte("FIXTURE=historical-original\r\n")
	write(t, root, ".env", original)
	if _, e := s.Track(ctx, v, root, true); e != nil {
		t.Fatal(e)
	}
	first := execute(t, s, v, false, false)
	write(t, root, ".env", []byte("FIXTURE=current-version\n"))
	execute(t, s, v, false, false)
	p, e := s.PlanSync(ctx, v)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.RemoveFile(ctx, v, p.Entries[0].FileID); e != nil {
		t.Fatal(e)
	}
	execute(t, s, v, false, false)
	actual, _ := restore.Read(root, ".env")
	if string(actual) != "FIXTURE=current-version\n" {
		t.Fatal("tombstone deleted local bytes")
	}
	history, e := s.History(ctx, v)
	if e != nil || len(history) != 3 {
		t.Fatal("history lost after tombstone")
	}
	target := t.TempDir()
	if e = s.MapProject(ctx, v, history[0].Projects[0].ID, target); e != nil {
		t.Fatal(e)
	}
	rp, e := s.PlanRestore(ctx, v, first.Snapshot)
	if e != nil {
		t.Fatal(e)
	}
	if len(rp.Entries) != 1 {
		t.Fatalf("historical plan has %d entries", len(rp.Entries))
	}
	if rp.Entries[0].Root != target || rp.Entries[0].State != "create" {
		t.Fatalf("historical plan state=%s root=%s target=%s", rp.Entries[0].State, rp.Entries[0].Root, target)
	}
	if _, e = s.ExecuteRestore(ctx, v, rp, false); e != nil {
		t.Fatal(e)
	}
	actual, e = restore.Read(target, ".env")
	if e != nil || !bytes.Equal(actual, original) {
		t.Fatalf("old snapshot restore: read error %v; bytes equal=%v", e, bytes.Equal(actual, original))
	}
	orphans, e := s.PrunePreview(ctx, v)
	if e != nil || len(orphans) != 0 {
		t.Fatal("retained historical blobs considered garbage")
	}
}
