package persistence

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestMigrationAndReopen(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	db, e := Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	if e = db.Set(context.Background(), "fixture", "synthetic"); e != nil {
		t.Fatal(e)
	}
	db.Close()
	db, e = Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	v, e := db.Get(context.Background(), "fixture")
	if e != nil || v != "synthetic" {
		t.Fatal("state lost on reopen")
	}
	var result string
	if e = db.QueryRow("PRAGMA integrity_check").Scan(&result); e != nil || result != "ok" {
		t.Fatal("database corrupt")
	}
}
func TestRejectPublicStateDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "public")
	os.Mkdir(dir, 0755)
	if db, e := Open(dir); e == nil {
		db.Close()
		t.Fatal("public directory accepted")
	}
}

func TestUnknownNewerSchemaRefused(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	db, e := Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.Exec("INSERT INTO schema_migrations VALUES(999)"); e != nil {
		t.Fatal(e)
	}
	db.Close()
	if db, e = Open(dir); e == nil {
		db.Close()
		t.Fatal("newer state schema silently rewritten")
	}
}
func TestUpgradeFromSchemaOne(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	db, e := Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	db.Exec("DROP TABLE operation_files")
	db.Exec("DELETE FROM schema_migrations WHERE version=2")
	db.Close()
	db, e = Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	var version int
	if e = db.QueryRow("SELECT MAX(version) FROM schema_migrations").Scan(&version); e != nil || version != 2 {
		t.Fatal("migration did not advance")
	}
	if _, e = db.Exec("SELECT * FROM operation_files"); e != nil {
		t.Fatal("journal migration missing")
	}
}
