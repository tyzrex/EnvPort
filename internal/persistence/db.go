// Package persistence owns local, device-specific SQLite state. It never stores file contents or unwrapped keys.
package persistence

import (
	"context"
	"database/sql"
	"errors"
	_ "modernc.org/sqlite"
	"os"
	"path/filepath"
)

type DB struct {
	*sql.DB
	Dir string
}

const schema = `
CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS storage_profiles(name TEXT PRIMARY KEY,config BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS vaults(id TEXT PRIMARY KEY,name TEXT NOT NULL UNIQUE,profile TEXT NOT NULL REFERENCES storage_profiles(name),checkpoint TEXT NOT NULL DEFAULT '',generation INTEGER NOT NULL DEFAULT 0,recovery_verified INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS projects(vault_id TEXT NOT NULL REFERENCES vaults(id),id TEXT NOT NULL,identity TEXT NOT NULL,root TEXT NOT NULL,PRIMARY KEY(vault_id,id),UNIQUE(vault_id,root));
CREATE TABLE IF NOT EXISTS tracked_files(vault_id TEXT NOT NULL,project_id TEXT NOT NULL,id TEXT NOT NULL,path TEXT NOT NULL,removed INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(vault_id,id),UNIQUE(vault_id,project_id,path),FOREIGN KEY(vault_id,project_id) REFERENCES projects(vault_id,id));
CREATE TABLE IF NOT EXISTS file_sync_states(vault_id TEXT NOT NULL,file_id TEXT NOT NULL,digest TEXT NOT NULL,PRIMARY KEY(vault_id,file_id));
CREATE TABLE IF NOT EXISTS operations(id TEXT PRIMARY KEY,vault_id TEXT NOT NULL REFERENCES vaults(id),snapshot_id TEXT NOT NULL,expected_head TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('staged','committed','abandoned')),created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS conflicts(vault_id TEXT NOT NULL,file_id TEXT NOT NULL,kind TEXT NOT NULL,PRIMARY KEY(vault_id,file_id));
CREATE TABLE IF NOT EXISTS operation_files(operation_id TEXT NOT NULL REFERENCES operations(id),file_id TEXT NOT NULL,digest TEXT NOT NULL,PRIMARY KEY(operation_id,file_id));
INSERT OR IGNORE INTO schema_migrations VALUES(1);
INSERT OR IGNORE INTO schema_migrations VALUES(2);
`

func Open(dir string) (*DB, error) {
	abs, e := filepath.Abs(dir)
	if e != nil {
		return nil, e
	}
	if e = os.MkdirAll(abs, 0700); e != nil {
		return nil, e
	}
	info, e := os.Lstat(abs)
	if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("state directory must be a real private directory")
	}
	if info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("state directory permissions must be 0700")
	}
	p := filepath.Join(abs, "state.db")
	if i, e := os.Lstat(p); e == nil && (i.Mode()&os.ModeSymlink != 0 || !i.Mode().IsRegular()) {
		return nil, errors.New("unsafe state database")
	}
	db, e := sql.Open("sqlite", p)
	if e != nil {
		return nil, errors.New("open state database failed")
	}
	db.SetMaxOpenConns(1)
	for _, q := range []string{"PRAGMA foreign_keys=ON", "PRAGMA busy_timeout=10000", "PRAGMA journal_mode=WAL"} {
		if _, e = db.Exec(q); e != nil {
			db.Close()
			return nil, errors.New("configure state database failed")
		}
	}
	var existing int
	checkErr := db.QueryRow("SELECT COALESCE(MAX(version),0) FROM schema_migrations").Scan(&existing)
	if checkErr == nil && existing > 2 {
		db.Close()
		return nil, errors.New("state database requires a newer EnvPort version")
	}
	tx, e := db.Begin()
	if e != nil {
		db.Close()
		return nil, e
	}
	if _, e = tx.Exec(schema); e != nil {
		tx.Rollback()
		db.Close()
		return nil, errors.New("migrate state database failed")
	}
	if e = tx.Commit(); e != nil {
		db.Close()
		return nil, errors.New("migrate state database failed")
	}
	if e = os.Chmod(p, 0600); e != nil {
		db.Close()
		return nil, e
	}
	return &DB{db, abs}, nil
}
func (db *DB) Get(ctx context.Context, key string) (string, error) {
	var s string
	e := db.QueryRowContext(ctx, "SELECT value FROM settings WHERE key=?", key).Scan(&s)
	return s, e
}
func (db *DB) Set(ctx context.Context, key, value string) error {
	_, e := db.ExecContext(ctx, "INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", key, value)
	return e
}
