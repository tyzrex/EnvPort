// Package restore confines all I/O to approved roots and never overwrites existing files.
package restore

import (
	"errors"
	"github.com/envport-dev/envport/internal/discovery"
	"github.com/envport-dev/envport/internal/domain"
	"io"
	"os"
	"path"
	"strings"
)

func open(root, rel string) (*os.Root, error) {
	if e := domain.ValidatePath(rel); e != nil {
		return nil, e
	}
	if e := discovery.CheckRoot(root); e != nil {
		return nil, e
	}
	r, e := os.OpenRoot(root)
	if e != nil {
		return nil, domain.ErrUnsafePath
	}
	parts := strings.Split(rel, "/")
	for i := range parts {
		p := strings.Join(parts[:i+1], "/")
		s, e := r.Lstat(p)
		if errors.Is(e, os.ErrNotExist) {
			break
		}
		if e != nil || s.Mode()&os.ModeSymlink != 0 {
			r.Close()
			return nil, domain.ErrUnsafePath
		}
		if i == len(parts)-1 && !s.Mode().IsRegular() {
			r.Close()
			return nil, domain.ErrUnsafePath
		}
		if i < len(parts)-1 && !s.IsDir() {
			r.Close()
			return nil, domain.ErrUnsafePath
		}
	}
	return r, nil
}
func Read(root, rel string) ([]byte, error) {
	r, e := open(root, rel)
	if e != nil {
		return nil, e
	}
	defer r.Close()
	f, e := readHandle(r, rel)
	if errors.Is(e, os.ErrNotExist) {
		return nil, domain.ErrNotFound
	}
	if e != nil {
		return nil, errors.New("cannot read tracked file")
	}
	defer f.Close()
	s, e := f.Stat()
	if e != nil || !s.Mode().IsRegular() || s.Size() > domain.MaxFileSize {
		return nil, errors.New("tracked file is not regular or exceeds size limit")
	}
	b, e := io.ReadAll(io.LimitReader(f, domain.MaxFileSize+1))
	if e != nil || int64(len(b)) > domain.MaxFileSize {
		return nil, errors.New("read tracked file failed")
	}
	return b, nil
}
func Exists(root, rel string) (bool, error) {
	r, e := open(root, rel)
	if e != nil {
		return false, e
	}
	defer r.Close()
	_, e = r.Lstat(rel)
	if errors.Is(e, os.ErrNotExist) {
		return false, nil
	}
	return e == nil, e
}

// Write stages a complete 0600 file and atomically links it into a vacant destination.
// Link provides atomic no-replace semantics even if another process creates the destination.
func Write(root, rel string, data []byte) error {
	r, e := open(root, rel)
	if e != nil {
		return e
	}
	defer r.Close()
	parent := path.Dir(rel)
	if parent != "." {
		if e = r.MkdirAll(parent, 0700); e != nil {
			return errors.New("create restore directory failed")
		}
	}
	temp := path.Join(parent, ".envport-"+string(domain.NewID())+".tmp")
	f, e := r.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return errors.New("stage restore failed")
	}
	defer r.Remove(temp)
	if _, e = f.Write(data); e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil || ce != nil {
		return errors.New("flush restore failed")
	}
	if e = r.Link(temp, rel); e != nil {
		if errors.Is(e, os.ErrExist) {
			return errors.New("destination exists; restore refused")
		}
		return errors.New("atomic no-overwrite restore failed")
	}
	if dir, e := r.Open(parent); e == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

// Replace requires an explicit caller decision and a matching preimage digest.
// The preimage remains recoverable in a private, uniquely named sibling file.
func Replace(root, rel string, data []byte, expected string) error {
	return replace(root, rel, data, expected)
}
