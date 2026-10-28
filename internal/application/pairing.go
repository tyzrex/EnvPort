package application

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"filippo.io/age"
	crypt "github.com/envport-dev/envport/internal/crypto"
	"github.com/envport-dev/envport/internal/domain"
	"github.com/envport-dev/envport/internal/restore"
	"path/filepath"
	"time"
)

type deviceSecret struct {
	Version    int       `json:"version"`
	ID         domain.ID `json:"device_id"`
	Encryption string    `json:"encryption_private_key"`
	Signing    string    `json:"signing_private_key"`
}
type JoinRequest struct {
	Version    int       `json:"version"`
	Vault      domain.ID `json:"vault_id"`
	Device     domain.ID `json:"device_id"`
	Nonce      domain.ID `json:"nonce"`
	Encryption string    `json:"encryption_public_key"`
	Signing    string    `json:"signing_public_key"`
	Expires    time.Time `json:"expires_at"`
	Signature  string    `json:"signature,omitempty"`
}
type deviceGrant struct {
	Version          int       `json:"version"`
	Vault            domain.ID `json:"vault_id"`
	Device           domain.ID `json:"device_id"`
	Request          string    `json:"request_fingerprint"`
	Expires          time.Time `json:"expires_at"`
	Identity         string    `json:"vault_private_identity"`
	Issuer           string    `json:"issuer_signing_public_key"`
	RecoveryVerified bool      `json:"recovery_verified"`
	Signature        string    `json:"signature,omitempty"`
}
type PairingInfo struct {
	Vault              domain.ID `json:"vault_id"`
	Device             domain.ID `json:"device_id"`
	RequestFingerprint string    `json:"request_fingerprint,omitempty"`
	IssuerFingerprint  string    `json:"issuer_fingerprint,omitempty"`
	Expires            time.Time `json:"expires_at,omitempty"`
}

func (s *Service) loadDevice(ctx context.Context) (deviceSecret, error) {
	var d deviceSecret
	id, e := s.Device(ctx)
	if e != nil {
		return d, e
	}
	pass, e := s.Secret("unlock")
	if e != nil {
		return d, e
	}
	b, e := restore.Read(s.DB.Dir, "device.age")
	if errors.Is(e, domain.ErrNotFound) {
		enc, e := crypt.NewIdentity()
		if e != nil {
			return d, e
		}
		_, sign, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return d, e
		}
		d = deviceSecret{1, id, enc.String(), base64.StdEncoding.EncodeToString(sign)}
		plain, _ := json.Marshal(d)
		sealed, e := crypt.Seal(plain, pass)
		if e != nil {
			return d, e
		}
		if e = restore.Write(s.DB.Dir, "device.age", sealed); e != nil {
			return d, e
		}
		return d, nil
	}
	if e != nil {
		return d, e
	}
	plain, e := crypt.Open(b, pass)
	if e != nil {
		return d, errors.New("device key unlock failed")
	}
	if decode(plain, &d) != nil || d.Version != 1 || d.ID != id {
		return d, domain.ErrCorrupt
	}
	sign, e := base64.StdEncoding.DecodeString(d.Signing)
	if e != nil || len(sign) != ed25519.PrivateKeySize {
		return d, domain.ErrCorrupt
	}
	if _, e = age.ParseX25519Identity(d.Encryption); e != nil {
		return d, domain.ErrCorrupt
	}
	return d, nil
}
func signing(d deviceSecret) ed25519.PrivateKey {
	b, _ := base64.StdEncoding.DecodeString(d.Signing)
	return ed25519.PrivateKey(b)
}
func requestBytes(r JoinRequest) []byte       { r.Signature = ""; b, _ := json.Marshal(r); return b }
func requestFingerprint(r JoinRequest) string { return digest(requestBytes(r)) }
func (r JoinRequest) validate(now time.Time) error {
	if r.Version != 1 || !r.Vault.Valid() || !r.Device.Valid() || !r.Nonce.Valid() || !r.Expires.After(now) || r.Expires.After(now.Add(24*time.Hour)) {
		return errors.New("invalid or expired join request")
	}
	if _, e := age.ParseX25519Recipient(r.Encryption); e != nil {
		return domain.ErrCorrupt
	}
	pub, e := base64.StdEncoding.DecodeString(r.Signing)
	if e != nil || len(pub) != ed25519.PublicKeySize {
		return domain.ErrCorrupt
	}
	signature, e := base64.StdEncoding.DecodeString(r.Signature)
	if e != nil || !ed25519.Verify(ed25519.PublicKey(pub), requestBytes(r), signature) {
		return errors.New("join request signature invalid")
	}
	return nil
}
func writeArtifact(destination string, b []byte) error {
	abs, e := filepath.Abs(destination)
	if e != nil {
		return e
	}
	return restore.Write(filepath.Dir(abs), filepath.Base(abs), b)
}
func readArtifact(source string) ([]byte, error) {
	abs, e := filepath.Abs(source)
	if e != nil {
		return nil, e
	}
	return restore.Read(filepath.Dir(abs), filepath.Base(abs))
}
func (s *Service) RequestDevice(ctx context.Context, vault domain.ID, destination string) (PairingInfo, error) {
	if !vault.Valid() {
		return PairingInfo{}, errors.New("valid --vault-id is required")
	}
	d, e := s.loadDevice(ctx)
	if e != nil {
		return PairingInfo{}, e
	}
	enc, _ := age.ParseX25519Identity(d.Encryption)
	key := signing(d)
	r := JoinRequest{Version: 1, Vault: vault, Device: d.ID, Nonce: domain.NewID(), Encryption: enc.Recipient().String(), Signing: base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)), Expires: time.Now().UTC().Add(30 * time.Minute)}
	r.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, requestBytes(r)))
	b, _ := json.Marshal(r)
	fp := requestFingerprint(r)
	if e = writeArtifact(destination, b); e != nil {
		return PairingInfo{}, e
	}
	if e = s.DB.Set(ctx, "pending_request:"+fp, string(b)); e != nil {
		return PairingInfo{}, e
	}
	return PairingInfo{Vault: vault, Device: d.ID, RequestFingerprint: fp, Expires: r.Expires}, nil
}
func (s *Service) ApproveDevice(ctx context.Context, v Vault, source, destination, confirmedFingerprint string) (PairingInfo, error) {
	b, e := readArtifact(source)
	if e != nil {
		return PairingInfo{}, e
	}
	var request JoinRequest
	if e = decode(b, &request); e != nil {
		return PairingInfo{}, e
	}
	if e = request.validate(time.Now()); e != nil {
		return PairingInfo{}, e
	}
	fp := requestFingerprint(request)
	if request.Vault != v.ID || fp != confirmedFingerprint {
		return PairingInfo{}, errors.New("request binding or out-of-band fingerprint confirmation failed")
	}
	root, e := s.Unlock(ctx, v)
	if e != nil {
		return PairingInfo{}, e
	}
	d, e := s.loadDevice(ctx)
	if e != nil {
		return PairingInfo{}, e
	}
	sign := signing(d)
	pub := sign.Public().(ed25519.PublicKey)
	grant := deviceGrant{Version: 1, Vault: v.ID, Device: request.Device, Request: fp, Expires: request.Expires, Identity: root.String(), Issuer: base64.StdEncoding.EncodeToString(pub), RecoveryVerified: v.RecoveryVerified}
	plain, _ := json.Marshal(grant)
	grant.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(sign, plain))
	plain, _ = json.Marshal(grant)
	recipient, _ := age.ParseX25519Recipient(request.Encryption)
	sealed, e := crypt.Encrypt(plain, recipient)
	if e != nil {
		return PairingInfo{}, e
	}
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return PairingInfo{}, e
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, "INSERT INTO settings(key,value) VALUES(?,?)", "approved_request:"+fp, string(request.Device)); e != nil {
		return PairingInfo{}, errors.New("request already approved")
	}
	if e = writeArtifact(destination, sealed); e != nil {
		return PairingInfo{}, e
	}
	if e = tx.Commit(); e != nil {
		return PairingInfo{}, e
	}
	return PairingInfo{Vault: v.ID, Device: request.Device, RequestFingerprint: fp, IssuerFingerprint: digest(pub), Expires: request.Expires}, nil
}
func (s *Service) JoinDevice(ctx context.Context, name, profile, source, issuerFingerprint string) (Vault, error) {
	if !validName(name) {
		return Vault{}, errors.New("invalid vault name")
	}
	if _, e := s.Profile(ctx, profile); e != nil {
		return Vault{}, e
	}
	d, e := s.loadDevice(ctx)
	if e != nil {
		return Vault{}, e
	}
	sealed, e := readArtifact(source)
	if e != nil {
		return Vault{}, e
	}
	identity, _ := age.ParseX25519Identity(d.Encryption)
	plain, e := crypt.Decrypt(sealed, identity, 1<<20)
	if e != nil {
		return Vault{}, e
	}
	var grant deviceGrant
	if e = decode(plain, &grant); e != nil {
		return Vault{}, e
	}
	signature, e := base64.StdEncoding.DecodeString(grant.Signature)
	if e != nil {
		return Vault{}, domain.ErrCorrupt
	}
	grant.Signature = ""
	canonical, _ := json.Marshal(grant)
	pub, e := base64.StdEncoding.DecodeString(grant.Issuer)
	if e != nil || len(pub) != ed25519.PublicKeySize || digest(pub) != issuerFingerprint || !ed25519.Verify(ed25519.PublicKey(pub), canonical, signature) {
		return Vault{}, errors.New("grant issuer fingerprint or signature does not match trusted device")
	}
	if grant.Version != 1 || grant.Device != d.ID || !grant.Vault.Valid() || !grant.Expires.After(time.Now()) {
		return Vault{}, errors.New("grant is expired or bound to another device")
	}
	pending, e := s.DB.Get(ctx, "pending_request:"+grant.Request)
	if e != nil {
		return Vault{}, errors.New("join request missing or already consumed")
	}
	var request JoinRequest
	if decode([]byte(pending), &request) != nil || request.validate(time.Now()) != nil || requestFingerprint(request) != grant.Request || request.Vault != grant.Vault || request.Device != d.ID || !request.Expires.Equal(grant.Expires) {
		return Vault{}, domain.ErrCorrupt
	}
	root, e := age.ParseX25519Identity(grant.Identity)
	if e != nil {
		return Vault{}, domain.ErrCorrupt
	}
	if e = s.saveKey(ctx, grant.Vault, root); e != nil {
		return Vault{}, e
	}
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return Vault{}, e
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, "INSERT INTO vaults(id,name,profile,recovery_verified) VALUES(?,?,?,?)", grant.Vault, name, profile, grant.RecoveryVerified); e != nil {
		return Vault{}, errors.New("vault already joined or name in use")
	}
	result, e := tx.ExecContext(ctx, "DELETE FROM settings WHERE key=? AND value=?", "pending_request:"+grant.Request, pending)
	if e != nil {
		return Vault{}, e
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		return Vault{}, errors.New("join request already consumed")
	}
	if e = tx.Commit(); e != nil {
		return Vault{}, e
	}
	if e = s.Use(ctx, name); e != nil {
		return Vault{}, e
	}
	return s.Vault(ctx, name)
}
