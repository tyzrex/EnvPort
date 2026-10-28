package application

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	crypt "github.com/envport-dev/envport/internal/crypto"
	"github.com/envport-dev/envport/internal/domain"
	"github.com/envport-dev/envport/pkg/protocol"
	"io"
)

func digest(b []byte) string   { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func namespace(v Vault) string { return "v1/vaults/" + string(v.ID) + "/" }
func readObject(ctx context.Context, st domain.ObjectStore, key string) ([]byte, domain.ObjectInfo, error) {
	r, info, e := st.Get(ctx, key)
	if e != nil {
		return nil, info, e
	}
	defer r.Close()
	b, e := io.ReadAll(io.LimitReader(r, domain.MaxObjectSize+1))
	if e != nil || int64(len(b)) > domain.MaxObjectSize {
		return nil, info, domain.ErrCorrupt
	}
	return b, info, nil
}
func decode(b []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e := d.Decode(out); e != nil {
		return domain.ErrCorrupt
	}
	if d.Decode(new(any)) != io.EOF {
		return domain.ErrCorrupt
	}
	return nil
}
func (s *Service) readManifest(ctx context.Context, v Vault, st domain.ObjectStore, id domain.ID) (protocol.Manifest, error) {
	var m protocol.Manifest
	if !id.Valid() {
		return m, domain.ErrCorrupt
	}
	b, _, e := readObject(ctx, st, namespace(v)+"snapshots/"+string(id)+".age")
	if e != nil {
		return m, e
	}
	k, e := s.Unlock(ctx, v)
	if e != nil {
		return m, e
	}
	plain, e := crypt.Decrypt(b, k, domain.MaxObjectSize)
	if e != nil {
		return m, e
	}
	if e = decode(plain, &m); e != nil {
		return m, e
	}
	if m.ID != id {
		return m, domain.ErrCorrupt
	}
	return m, m.Validate(v.ID)
}
func (s *Service) current(ctx context.Context, v Vault, st domain.ObjectStore) (protocol.Manifest, string, error) {
	fresh, err := s.Vault(ctx, string(v.ID))
	if err != nil {
		return protocol.Manifest{}, "", err
	}
	v = fresh
	b, info, e := readObject(ctx, st, namespace(v)+"refs/main")
	if errors.Is(e, domain.ErrNotFound) {
		if v.Checkpoint != "" {
			return protocol.Manifest{}, "", domain.ErrRollback
		}
		return protocol.Manifest{Version: 1, Vault: v.ID, Projects: []protocol.Project{}}, "", nil
	}
	if e != nil {
		return protocol.Manifest{}, "", e
	}
	k, e := s.Unlock(ctx, v)
	if e != nil {
		return protocol.Manifest{}, "", e
	}
	plain, e := crypt.Decrypt(b, k, 4096)
	if e != nil {
		return protocol.Manifest{}, "", e
	}
	var ref protocol.Ref
	if e = decode(plain, &ref); e != nil || ref.Version != 1 || ref.Vault != v.ID || !ref.Snapshot.Valid() {
		return protocol.Manifest{}, "", domain.ErrCorrupt
	}
	m, e := s.readManifest(ctx, v, st, ref.Snapshot)
	if e != nil {
		return m, "", e
	}
	if m.Generation != ref.Generation {
		return m, "", domain.ErrCorrupt
	}
	if v.Checkpoint != "" {
		walk := m
		found := false
		for n := 0; n < 10000; n++ {
			if walk.ID == v.Checkpoint {
				if walk.Generation != v.Generation {
					return m, "", domain.ErrRollback
				}
				found = true
				break
			}
			if len(walk.Parents) == 0 || walk.Generation <= v.Generation {
				break
			}
			parent, e := s.readManifest(ctx, v, st, walk.Parents[0])
			if e != nil {
				return m, "", e
			}
			if parent.Generation != walk.Generation-1 {
				return m, "", domain.ErrCorrupt
			}
			walk = parent
		}
		if !found {
			return m, "", domain.ErrRollback
		}
	}
	return m, info.ETag, nil
}
func (s *Service) putEncrypted(ctx context.Context, v Vault, st domain.ObjectStore, key string, plain []byte, c domain.Condition) (domain.ObjectInfo, error) {
	k, e := s.Unlock(ctx, v)
	if e != nil {
		return domain.ObjectInfo{}, e
	}
	b, e := crypt.Encrypt(plain, k.Recipient())
	if e != nil {
		return domain.ObjectInfo{}, e
	}
	return st.Put(ctx, namespace(v)+key, bytes.NewReader(b), c)
}
func (s *Service) readBlob(ctx context.Context, v Vault, st domain.ObjectStore, f protocol.File) ([]byte, error) {
	if !f.Blob.Valid() {
		return nil, domain.ErrCorrupt
	}
	b, _, e := readObject(ctx, st, namespace(v)+"blobs/"+string(f.Blob)+".age")
	if e != nil {
		return nil, e
	}
	k, e := s.Unlock(ctx, v)
	if e != nil {
		return nil, e
	}
	plain, e := crypt.Decrypt(b, k, domain.MaxFileSize)
	if e != nil {
		return nil, e
	}
	if digest(plain) != f.Digest || int64(len(plain)) != f.Size {
		return nil, domain.ErrCorrupt
	}
	return plain, nil
}
func (s *Service) History(ctx context.Context, v Vault) ([]protocol.Manifest, error) {
	st, e := s.OpenStore(ctx, v)
	if e != nil {
		return nil, e
	}
	defer st.Close()
	m, _, e := s.current(ctx, v, st)
	if e != nil {
		return nil, e
	}
	out := []protocol.Manifest{}
	for m.ID != "" {
		out = append(out, m)
		if len(out) > 10000 {
			return nil, errors.New("history limit exceeded")
		}
		if len(m.Parents) == 0 {
			break
		}
		parent, e := s.readManifest(ctx, v, st, m.Parents[0])
		if e != nil {
			return nil, e
		}
		if parent.Generation != m.Generation-1 {
			return nil, domain.ErrCorrupt
		}
		m = parent
	}
	return out, nil
}
