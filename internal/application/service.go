// Package application provides the engine used by CLI and future desktop adapters.
package application

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"filippo.io/age"
	crypt "github.com/envport-dev/envport/internal/crypto"
	"github.com/envport-dev/envport/internal/domain"
	"github.com/envport-dev/envport/internal/persistence"
	"github.com/envport-dev/envport/internal/restore"
	"os"
	"path/filepath"
	"sync"
)

type Profile struct {
	Name    string          `json:"name"`
	Driver  string          `json:"driver"`
	Path    string          `json:"path,omitempty"`
	Options json.RawMessage `json:"options,omitempty"`
}
type Vault struct {
	ID               domain.ID `json:"id"`
	Name             string    `json:"name"`
	Profile          string    `json:"storage"`
	Checkpoint       domain.ID `json:"checkpoint,omitempty"`
	Generation       int64     `json:"generation"`
	RecoveryVerified bool      `json:"recovery_verified"`
}
type Project struct {
	ID       domain.ID `json:"id"`
	Identity string    `json:"identity,omitempty"`
	Root     string    `json:"root"`
}
type KeyBundle struct {
	Version  int       `json:"version"`
	Vault    domain.ID `json:"vault_id"`
	Identity string    `json:"identity"`
}
type StoreFactory func(context.Context, Profile) (domain.ObjectStore, error)
type SecretFunc func(kind string) (string, error)
type Service struct {
	DB           *persistence.DB
	StoreFactory StoreFactory
	Secret       SecretFunc
	NoNetwork    bool
	mu           sync.Mutex
	keys         map[domain.ID]*age.X25519Identity
}

func New(db *persistence.DB, f StoreFactory, secret SecretFunc) *Service {
	return &Service{DB: db, StoreFactory: f, Secret: secret, keys: map[domain.ID]*age.X25519Identity{}}
}
func (s *Service) Device(ctx context.Context) (domain.ID, error) {
	v, e := s.DB.Get(ctx, "device_id")
	if errors.Is(e, sql.ErrNoRows) {
		id := domain.NewID()
		_, e = s.DB.ExecContext(ctx, "INSERT INTO settings(key,value) VALUES('device_id',?) ON CONFLICT(key) DO NOTHING", id)
		if e != nil {
			return "", e
		}
		v, e = s.DB.Get(ctx, "device_id")
	}
	if e != nil {
		return "", e
	}
	id := domain.ID(v)
	if !id.Valid() {
		return "", domain.ErrCorrupt
	}
	return id, nil
}
func (s *Service) AddProfile(ctx context.Context, p Profile) error {
	if !validName(p.Name) {
		return errors.New("profile name must contain letters, numbers, dash or underscore")
	}
	if p.Driver != "filesystem" && p.Driver != "s3" && p.Driver != "lan" {
		return errors.New("unsupported storage driver")
	}
	if p.Driver == "filesystem" {
		abs, e := filepath.Abs(p.Path)
		if e != nil || p.Path == "" {
			return errors.New("filesystem path is required")
		}
		p.Path = abs
	}
	b, e := json.Marshal(p)
	if e != nil {
		return e
	}
	_, e = s.DB.ExecContext(ctx, "INSERT INTO storage_profiles(name,config) VALUES(?,?)", p.Name, b)
	if e != nil {
		return errors.New("cannot add profile; name may already exist")
	}
	return nil
}
func validName(v string) bool {
	if v == "" || len(v) > 64 {
		return false
	}
	for _, r := range v {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}
func (s *Service) Profiles(ctx context.Context) ([]Profile, error) {
	rows, e := s.DB.QueryContext(ctx, "SELECT config FROM storage_profiles ORDER BY name")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Profile{}
	for rows.Next() {
		var b []byte
		if e = rows.Scan(&b); e != nil {
			return nil, e
		}
		var p Profile
		if e = json.Unmarshal(b, &p); e != nil {
			return nil, domain.ErrCorrupt
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
func (s *Service) Profile(ctx context.Context, name string) (Profile, error) {
	var b []byte
	e := s.DB.QueryRowContext(ctx, "SELECT config FROM storage_profiles WHERE name=?", name).Scan(&b)
	if errors.Is(e, sql.ErrNoRows) {
		return Profile{}, domain.ErrNotFound
	}
	if e != nil {
		return Profile{}, e
	}
	var p Profile
	e = json.Unmarshal(b, &p)
	return p, e
}
func (s *Service) OpenStore(ctx context.Context, v Vault) (domain.ObjectStore, error) {
	p, e := s.Profile(ctx, v.Profile)
	if e != nil {
		return nil, e
	}
	if s.NoNetwork && p.Driver != "filesystem" {
		return nil, errors.New("network disabled by --no-network")
	}
	return s.StoreFactory(ctx, p)
}
func (s *Service) Vault(ctx context.Context, name string) (Vault, error) {
	if name == "" {
		var e error
		name, e = s.DB.Get(ctx, "active_vault")
		if e != nil {
			return Vault{}, errors.New("no active vault; create or join a vault")
		}
	}
	var v Vault
	e := s.DB.QueryRowContext(ctx, "SELECT id,name,profile,checkpoint,generation,recovery_verified FROM vaults WHERE name=? OR id=?", name, name).Scan(&v.ID, &v.Name, &v.Profile, &v.Checkpoint, &v.Generation, &v.RecoveryVerified)
	if errors.Is(e, sql.ErrNoRows) {
		return v, domain.ErrNotFound
	}
	return v, e
}
func (s *Service) Vaults(ctx context.Context) ([]Vault, error) {
	rows, e := s.DB.QueryContext(ctx, "SELECT id,name,profile,checkpoint,generation,recovery_verified FROM vaults ORDER BY name")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Vault{}
	for rows.Next() {
		var v Vault
		if e = rows.Scan(&v.ID, &v.Name, &v.Profile, &v.Checkpoint, &v.Generation, &v.RecoveryVerified); e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *Service) Use(ctx context.Context, name string) error {
	v, e := s.Vault(ctx, name)
	if e != nil {
		return e
	}
	return s.DB.Set(ctx, "active_vault", v.Name)
}
func (s *Service) keyPath(id domain.ID) string { return "key-" + string(id) + ".age" }
func (s *Service) Unlock(ctx context.Context, v Vault) (*age.X25519Identity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if k := s.keys[v.ID]; k != nil {
		return k, nil
	}
	b, e := restore.Read(s.DB.Dir, s.keyPath(v.ID))
	if e != nil {
		return nil, errors.New("encrypted vault key is unavailable")
	}
	pass, e := s.Secret("unlock")
	if e != nil {
		return nil, e
	}
	plain, e := crypt.Open(b, pass)
	if e != nil {
		return nil, errors.New("cannot unlock vault; passphrase incorrect or key envelope damaged")
	}
	var kb KeyBundle
	if json.Unmarshal(plain, &kb) != nil || kb.Version != 1 || kb.Vault != v.ID {
		return nil, domain.ErrCorrupt
	}
	k, e := age.ParseX25519Identity(kb.Identity)
	if e != nil {
		return nil, domain.ErrCorrupt
	}
	s.keys[v.ID] = k
	return k, nil
}
func (s *Service) saveKey(ctx context.Context, id domain.ID, k *age.X25519Identity) error {
	pass, e := s.Secret("unlock")
	if e != nil {
		return e
	}
	plain, e := json.Marshal(KeyBundle{1, id, k.String()})
	if e != nil {
		return e
	}
	b, e := crypt.Seal(plain, pass)
	if e != nil {
		return e
	}
	if e = restore.Write(s.DB.Dir, s.keyPath(id), b); e != nil {
		return e
	}
	s.mu.Lock()
	s.keys[id] = k
	s.mu.Unlock()
	return nil
}
func (s *Service) CreateVault(ctx context.Context, name, profile string) (Vault, error) {
	if !validName(name) {
		return Vault{}, errors.New("invalid vault name")
	}
	if _, e := s.Profile(ctx, profile); e != nil {
		return Vault{}, e
	}
	if _, e := s.Vault(ctx, name); e == nil {
		return Vault{}, errors.New("vault name already exists")
	}
	id := domain.NewID()
	k, e := crypt.NewIdentity()
	if e != nil {
		return Vault{}, e
	}
	if e = s.saveKey(ctx, id, k); e != nil {
		return Vault{}, e
	}
	_, e = s.DB.ExecContext(ctx, "INSERT INTO vaults(id,name,profile) VALUES(?,?,?)", id, name, profile)
	if e != nil {
		return Vault{}, errors.New("create vault state failed")
	}
	if e = s.Use(ctx, name); e != nil {
		return Vault{}, e
	}
	return s.Vault(ctx, name)
}
func (s *Service) ExportRecovery(ctx context.Context, v Vault, destination string) error {
	k, e := s.Unlock(ctx, v)
	if e != nil {
		return e
	}
	pass, e := s.Secret("recovery")
	if e != nil {
		return e
	}
	plain, _ := json.Marshal(KeyBundle{1, v.ID, k.String()})
	b, e := crypt.Seal(plain, pass)
	if e != nil {
		return e
	}
	check, e := crypt.Open(b, pass)
	if e != nil || string(check) != string(plain) {
		return errors.New("recovery verification failed")
	}
	abs, e := filepath.Abs(destination)
	if e != nil {
		return e
	}
	if e = restore.Write(filepath.Dir(abs), filepath.Base(abs), b); e != nil {
		return e
	}
	_, e = s.DB.ExecContext(ctx, "UPDATE vaults SET recovery_verified=1 WHERE id=?", v.ID)
	return e
}
func (s *Service) readRecovery(source string) (KeyBundle, error) {
	var kb KeyBundle
	abs, e := filepath.Abs(source)
	if e != nil {
		return kb, e
	}
	b, e := restore.Read(filepath.Dir(abs), filepath.Base(abs))
	if e != nil {
		return kb, errors.New("cannot read recovery bundle")
	}
	pass, e := s.Secret("recovery")
	if e != nil {
		return kb, e
	}
	plain, e := crypt.Open(b, pass)
	if e != nil {
		return kb, errors.New("cannot decrypt recovery bundle")
	}
	if json.Unmarshal(plain, &kb) != nil || kb.Version != 1 || !kb.Vault.Valid() {
		return kb, domain.ErrCorrupt
	}
	if _, e = age.ParseX25519Identity(kb.Identity); e != nil {
		return kb, domain.ErrCorrupt
	}
	return kb, nil
}
func (s *Service) VerifyRecovery(ctx context.Context, v Vault, source string) error {
	kb, e := s.readRecovery(source)
	if e != nil {
		return e
	}
	k, e := s.Unlock(ctx, v)
	if e != nil {
		return e
	}
	if kb.Vault != v.ID || kb.Identity != k.String() {
		return errors.New("recovery bundle belongs to another vault")
	}
	_, e = s.DB.ExecContext(ctx, "UPDATE vaults SET recovery_verified=1 WHERE id=?", v.ID)
	return e
}
func (s *Service) Join(ctx context.Context, name, profile, source string) (Vault, error) {
	if !validName(name) {
		return Vault{}, errors.New("invalid vault name")
	}
	if _, e := s.Profile(ctx, profile); e != nil {
		return Vault{}, e
	}
	kb, e := s.readRecovery(source)
	if e != nil {
		return Vault{}, e
	}
	k, _ := age.ParseX25519Identity(kb.Identity)
	if e = s.saveKey(ctx, kb.Vault, k); e != nil {
		return Vault{}, e
	}
	_, e = s.DB.ExecContext(ctx, "INSERT INTO vaults(id,name,profile,recovery_verified) VALUES(?,?,?,1)", kb.Vault, name, profile)
	if e != nil {
		return Vault{}, errors.New("vault already joined or name in use")
	}
	if _, e = s.Device(ctx); e != nil {
		return Vault{}, e
	}
	if e = s.Use(ctx, name); e != nil {
		return Vault{}, e
	}
	return s.Vault(ctx, name)
}
func (s *Service) RemoveProfile(ctx context.Context, name string) error {
	result, e := s.DB.ExecContext(ctx, "DELETE FROM storage_profiles WHERE name=?", name)
	if e != nil {
		return errors.New("storage profile is in use by a vault")
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return domain.ErrNotFound
	}
	return nil
}
func (s *Service) EnsureInitialized(ctx context.Context) error { _, e := s.Device(ctx); return e }
func DefaultStateDir() string {
	if v := os.Getenv("ENVPORT_HOME"); v != "" {
		return v
	}
	if v := os.Getenv("XDG_STATE_HOME"); v != "" {
		return filepath.Join(v, "envport")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "state", "envport")
}
