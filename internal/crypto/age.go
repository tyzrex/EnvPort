// Package crypto uses age for payload encryption and passphrase-protected key envelopes.
package crypto

import (
	"bytes"
	"errors"
	"filippo.io/age"
	"github.com/envport-dev/envport/internal/domain"
	"io"
)

func NewIdentity() (*age.X25519Identity, error) { return age.GenerateX25519Identity() }
func Encrypt(data []byte, recipient age.Recipient) ([]byte, error) {
	var b bytes.Buffer
	w, e := age.Encrypt(&b, recipient)
	if e != nil {
		return nil, errors.New("encryption failed")
	}
	if _, e = w.Write(data); e != nil {
		return nil, errors.New("encryption failed")
	}
	if e = w.Close(); e != nil {
		return nil, errors.New("encryption failed")
	}
	return b.Bytes(), nil
}
func Decrypt(data []byte, identity age.Identity, limit int64) ([]byte, error) {
	if int64(len(data)) > domain.MaxObjectSize {
		return nil, domain.ErrCorrupt
	}
	r, e := age.Decrypt(bytes.NewReader(data), identity)
	if e != nil {
		return nil, domain.ErrCorrupt
	}
	out, e := io.ReadAll(io.LimitReader(r, limit+1))
	if e != nil || int64(len(out)) > limit {
		return nil, domain.ErrCorrupt
	}
	return out, nil
}
func Seal(data []byte, passphrase string) ([]byte, error) {
	if len(passphrase) < 12 || len(passphrase) > 1024 {
		return nil, errors.New("passphrase must contain 12 to 1024 bytes")
	}
	r, e := age.NewScryptRecipient(passphrase)
	if e != nil {
		return nil, errors.New("invalid passphrase")
	}
	return Encrypt(data, r)
}
func Open(data []byte, passphrase string) ([]byte, error) {
	i, e := age.NewScryptIdentity(passphrase)
	if e != nil {
		return nil, domain.ErrCorrupt
	}
	i.SetMaxWorkFactor(18)
	return Decrypt(data, i, 1<<20)
}
