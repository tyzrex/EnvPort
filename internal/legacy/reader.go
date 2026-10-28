// Package legacy reads the supplied MIT-licensed EnvPort starter's EVP1 AES-GCM format.
// It never mutates the source vault and cannot write new legacy snapshots.
package legacy

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/envport-dev/envport/internal/discovery"
	"github.com/envport-dev/envport/internal/domain"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Entry struct {
	Project    string `json:"project"`
	Repository string `json:"repository,omitempty"`
	Relative   string `json:"relative"`
	Object     string `json:"object"`
	Digest     string `json:"digest"`
}
type Manifest struct {
	Version  int       `json:"version"`
	Snapshot string    `json:"snapshot"`
	Created  time.Time `json:"created"`
	Files    []Entry   `json:"files"`
}
type Reader struct {
	root *os.Root
	key  []byte
}

func Open(home string) (*Reader, error) {
	if e := discovery.CheckRoot(home); e != nil {
		return nil, e
	}
	root, e := os.OpenRoot(home)
	if e != nil {
		return nil, errors.New("cannot open legacy vault")
	}
	r := &Reader{root: root}
	key, e := r.read("key.bin")
	if e != nil || len(key) != 32 {
		root.Close()
		return nil, errors.New("legacy key.bin unavailable or invalid")
	}
	r.key = key
	return r, nil
}
func (r *Reader) Close() error {
	for i := range r.key {
		r.key[i] = 0
	}
	return r.root.Close()
}
func (r *Reader) read(p string) ([]byte, error) {
	if e := domain.ValidatePath(p); e != nil {
		return nil, e
	}
	parts := strings.Split(p, "/")
	for i := range parts {
		info, e := r.root.Lstat(strings.Join(parts[:i+1], "/"))
		if e != nil || info.Mode()&os.ModeSymlink != 0 {
			return nil, domain.ErrUnsafePath
		}
		if i == len(parts)-1 && (!info.Mode().IsRegular() || info.Size() > domain.MaxObjectSize) {
			return nil, domain.ErrCorrupt
		}
	}
	f, e := r.root.Open(p)
	if e != nil {
		return nil, errors.New("legacy object unavailable")
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, domain.MaxObjectSize+1))
	if e != nil || int64(len(b)) > domain.MaxObjectSize {
		return nil, domain.ErrCorrupt
	}
	return b, nil
}
func decrypt(key, enc []byte) ([]byte, error) {
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, domain.ErrCorrupt
	}
	g, e := cipher.NewGCM(block)
	if e != nil {
		return nil, domain.ErrCorrupt
	}
	n := g.NonceSize()
	if len(enc) < 4+n || string(enc[:4]) != "EVP1" {
		return nil, domain.ErrCorrupt
	}
	plain, e := g.Open(nil, enc[4:4+n], enc[4+n:], []byte("envport-v1"))
	if e != nil {
		return nil, domain.ErrCorrupt
	}
	return plain, nil
}
func (r *Reader) Load(ctx context.Context, id domain.ID) (Manifest, string, error) {
	var m Manifest
	if e := ctx.Err(); e != nil {
		return m, "", e
	}
	if !id.Valid() {
		return m, "", domain.ErrCorrupt
	}
	enc, e := r.read("vault/snapshots/" + string(id) + ".enc")
	if e != nil {
		return m, "", e
	}
	sourceHash := sha256.Sum256(enc)
	plain, e := decrypt(r.key, enc)
	if e != nil {
		return m, "", e
	}
	if json.Unmarshal(plain, &m) != nil || m.Version != 1 || m.Snapshot != string(id) || len(m.Files) > domain.MaxManifestFiles {
		return m, "", domain.ErrCorrupt
	}
	seen := map[string]bool{}
	identityByProject := map[string]string{}
	for _, f := range m.Files {
		if len(f.Project) != 24 || strings.Trim(f.Project, "0123456789abcdef") != "" || domain.ValidateTrackedPath(f.Relative) != nil || !strings.HasPrefix(f.Object, "objects/") || filepath.Ext(f.Object) != ".enc" || !domain.ID(strings.TrimSuffix(strings.TrimPrefix(f.Object, "objects/"), ".enc")).Valid() {
			return m, "", domain.ErrCorrupt
		}
		hash, e := hex.DecodeString(f.Digest)
		if e != nil || len(hash) != 32 {
			return m, "", domain.ErrCorrupt
		}
		key := f.Project + "/" + strings.ToLower(f.Relative)
		if seen[key] {
			return m, "", domain.ErrCorrupt
		}
		seen[key] = true
		if prior, ok := identityByProject[f.Project]; ok && prior != f.Repository {
			return m, "", domain.ErrCorrupt
		}
		identityByProject[f.Project] = f.Repository
	}
	return m, hex.EncodeToString(sourceHash[:]), nil
}
func (r *Reader) Read(ctx context.Context, f Entry) ([]byte, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if domain.ValidatePath(f.Object) != nil || !strings.HasPrefix(f.Object, "objects/") {
		return nil, domain.ErrUnsafePath
	}
	b, e := r.read("vault/" + f.Object)
	if e != nil {
		return nil, e
	}
	plain, e := decrypt(r.key, b)
	if e != nil || int64(len(plain)) > domain.MaxFileSize {
		return nil, domain.ErrCorrupt
	}
	hash := sha256.Sum256(plain)
	if hex.EncodeToString(hash[:]) != f.Digest {
		return nil, domain.ErrCorrupt
	}
	return plain, nil
}
