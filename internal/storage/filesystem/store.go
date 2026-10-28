// Package filesystem implements a local encrypted object namespace using SQLite for cross-process atomic CAS.
package filesystem

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"github.com/envport-dev/envport/internal/domain"
	"io"
	_ "modernc.org/sqlite"
	"os"
	"path/filepath"
	"strings"
)

type Store struct{ db *sql.DB }

func Open(dir string) (*Store, error) {
	if e := os.MkdirAll(dir, 0700); e != nil {
		return nil, errors.New("create object directory failed")
	}
	info, e := os.Lstat(dir)
	if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, domain.ErrUnsafePath
	}
	if info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("object directory must have permissions 0700")
	}
	p := filepath.Join(dir, "objects.db")
	if i, e := os.Lstat(p); e == nil && (i.Mode()&os.ModeSymlink != 0 || !i.Mode().IsRegular()) {
		return nil, domain.ErrUnsafePath
	}
	db, e := sql.Open("sqlite", p)
	if e != nil {
		return nil, errors.New("open object store failed")
	}
	db.SetMaxOpenConns(1)
	for _, q := range []string{"PRAGMA busy_timeout=10000", "PRAGMA journal_mode=WAL", "CREATE TABLE IF NOT EXISTS objects(key TEXT PRIMARY KEY,body BLOB NOT NULL,etag TEXT NOT NULL)"} {
		if _, e = db.Exec(q); e != nil {
			db.Close()
			return nil, errors.New("initialize object store failed")
		}
	}
	if e = os.Chmod(p, 0600); e != nil {
		db.Close()
		return nil, e
	}
	return &Store{db}, nil
}
func (s *Store) Close() error { return s.db.Close() }
func (s *Store) Capabilities() domain.Capabilities {
	return domain.Capabilities{ConditionalCreate: true, ConditionalReplace: true, Verified: true, MaxObjectSize: domain.MaxObjectSize}
}
func (s *Store) Put(ctx context.Context, k string, r io.Reader, c domain.Condition) (domain.ObjectInfo, error) {
	if e := domain.ValidateKey(k); e != nil {
		return domain.ObjectInfo{}, e
	}
	if e := c.Validate(); e != nil {
		return domain.ObjectInfo{}, e
	}
	b, e := io.ReadAll(io.LimitReader(r, domain.MaxObjectSize+1))
	if e != nil {
		return domain.ObjectInfo{}, errors.New("read object failed")
	}
	if int64(len(b)) > domain.MaxObjectSize {
		return domain.ObjectInfo{}, errors.New("object size limit exceeded")
	}
	h := sha256.Sum256(b)
	etag := hex.EncodeToString(h[:])
	var result sql.Result
	switch c.Mode {
	case domain.CreateIfAbsent:
		result, e = s.db.ExecContext(ctx, "INSERT INTO objects(key,body,etag) VALUES(?,?,?) ON CONFLICT(key) DO NOTHING", k, b, etag)
	case domain.IfETagMatch:
		result, e = s.db.ExecContext(ctx, "UPDATE objects SET body=?,etag=? WHERE key=? AND etag=?", b, etag, k, c.ETag)
	case domain.Unconditional:
		result, e = s.db.ExecContext(ctx, "INSERT INTO objects VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET body=excluded.body,etag=excluded.etag", k, b, etag)
	}
	if e != nil {
		return domain.ObjectInfo{}, errors.New("object write failed")
	}
	n, e := result.RowsAffected()
	if e != nil {
		return domain.ObjectInfo{}, e
	}
	if n != 1 {
		return domain.ObjectInfo{}, domain.ErrPrecondition
	}
	return domain.ObjectInfo{Key: k, ETag: etag, Size: int64(len(b))}, nil
}
func (s *Store) Get(ctx context.Context, k string) (io.ReadCloser, domain.ObjectInfo, error) {
	if e := domain.ValidateKey(k); e != nil {
		return nil, domain.ObjectInfo{}, e
	}
	var b []byte
	var tag string
	e := s.db.QueryRowContext(ctx, "SELECT body,etag FROM objects WHERE key=?", k).Scan(&b, &tag)
	if errors.Is(e, sql.ErrNoRows) {
		return nil, domain.ObjectInfo{}, domain.ErrNotFound
	}
	if e != nil {
		return nil, domain.ObjectInfo{}, errors.New("object read failed")
	}
	return io.NopCloser(bytes.NewReader(b)), domain.ObjectInfo{Key: k, ETag: tag, Size: int64(len(b))}, nil
}
func (s *Store) Head(ctx context.Context, k string) (domain.ObjectInfo, error) {
	if e := domain.ValidateKey(k); e != nil {
		return domain.ObjectInfo{}, e
	}
	var n int64
	var tag string
	e := s.db.QueryRowContext(ctx, "SELECT length(body),etag FROM objects WHERE key=?", k).Scan(&n, &tag)
	if errors.Is(e, sql.ErrNoRows) {
		e = domain.ErrNotFound
	}
	return domain.ObjectInfo{Key: k, ETag: tag, Size: n}, e
}
func (s *Store) List(ctx context.Context, prefix, cursor string, limit int) (domain.Page, error) {
	if limit < 1 || limit > 1000 {
		limit = 1000
	}
	rows, e := s.db.QueryContext(ctx, "SELECT key,etag,length(body) FROM objects WHERE key>? AND substr(key,1,?)=? ORDER BY key LIMIT ?", cursor, len(prefix), prefix, limit+1)
	if e != nil {
		return domain.Page{}, errors.New("object list failed")
	}
	defer rows.Close()
	p := domain.Page{Objects: []domain.ObjectInfo{}}
	for rows.Next() {
		var o domain.ObjectInfo
		if e = rows.Scan(&o.Key, &o.ETag, &o.Size); e != nil {
			return p, e
		}
		if !strings.HasPrefix(o.Key, prefix) {
			return p, domain.ErrCorrupt
		}
		p.Objects = append(p.Objects, o)
	}
	if len(p.Objects) > limit {
		p.Objects = p.Objects[:limit]
		p.Cursor = p.Objects[limit-1].Key
	}
	return p, rows.Err()
}
func (s *Store) Delete(ctx context.Context, k string) error {
	if e := domain.ValidateKey(k); e != nil {
		return e
	}
	_, e := s.db.ExecContext(ctx, "DELETE FROM objects WHERE key=?", k)
	return e
}
