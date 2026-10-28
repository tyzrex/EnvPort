package restore

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/envport-dev/envport/internal/domain"
	"os"
	"path"
)

func hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func replace(root, rel string, data []byte, expected string) error {
	before, e := Read(root, rel)
	if e != nil || hash(before) != expected {
		return errors.New("destination changed; replacement refused")
	}
	r, e := open(root, rel)
	if e != nil {
		return e
	}
	defer r.Close()
	parent, e := r.OpenRoot(path.Dir(rel))
	if e != nil {
		return domain.ErrUnsafePath
	}
	defer parent.Close()
	name := path.Base(rel)
	info, e := parent.Lstat(name)
	if e != nil || !info.Mode().IsRegular() {
		return domain.ErrUnsafePath
	}
	backup := ".envport-preimage-" + string(domain.NewID())
	bf, e := parent.OpenFile(backup, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return errors.New("cannot preserve preimage; replacement refused")
	}
	if _, e = bf.Write(before); e == nil {
		e = bf.Sync()
	}
	bce := bf.Close()
	if e != nil || bce != nil {
		return errors.New("cannot flush preimage; replacement refused")
	}
	temp := ".envport-stage-" + string(domain.NewID())
	f, e := parent.OpenFile(temp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer parent.Remove(temp)
	if _, e = f.Write(data); e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil || ce != nil {
		return errors.New("stage replacement failed")
	}
	// Verify the actual target still names the original inode.
	current, e := parent.Lstat(name)
	if e != nil || !os.SameFile(info, current) || current.Mode()&os.ModeSymlink != 0 {
		return errors.New("destination changed before replacement")
	}
	check, e := parent.ReadFile(name)
	if e != nil || hash(check) != expected {
		return errors.New("destination contents changed before replacement")
	}
	if e = parent.Rename(temp, name); e != nil {
		return errors.New("atomic replacement failed; preimage retained")
	}
	if dir, e := parent.Open("."); e == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}
