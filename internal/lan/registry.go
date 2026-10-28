package lan

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"

	"github.com/envport-dev/envport/internal/discovery"
	"github.com/envport-dev/envport/internal/domain"
	"github.com/envport-dev/envport/internal/restore"
	_ "modernc.org/sqlite"
)

type Namespace struct {
	ID   domain.ID `json:"id"`
	Name string    `json:"name"`
}
type Client struct {
	Namespace   domain.ID `json:"namespace"`
	Fingerprint string    `json:"fingerprint"`
	ReadOnly    bool      `json:"read_only"`
	Revoked     bool      `json:"revoked"`
}
type registry struct{ *sql.DB }

func privateDirectory(dir string, create bool) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	if create {
		ancestor := abs
		for {
			_, e := os.Lstat(ancestor)
			if e == nil {
				break
			}
			if !os.IsNotExist(e) {
				return "", e
			}
			next := filepath.Dir(ancestor)
			if next == ancestor {
				return "", domain.ErrUnsafePath
			}
			ancestor = next
		}
		if err = discovery.CheckRoot(ancestor); err != nil {
			return "", err
		}
		if err = os.MkdirAll(abs, 0700); err != nil {
			return "", err
		}
	}
	if err = discovery.CheckRoot(abs); err != nil {
		return "", err
	}
	info, err := os.Lstat(abs)
	if err != nil || info.Mode().Perm()&0077 != 0 {
		return "", errors.New("LAN state directory must have permissions 0700")
	}
	return abs, nil
}

func openRegistry(dir string, create bool) (*registry, error) {
	abs, err := privateDirectory(dir, create)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(abs, "registry.db")
	info, err := os.Lstat(path)
	if err != nil && (!create || !os.IsNotExist(err)) {
		return nil, errors.New("LAN host is not initialized")
	}
	if err == nil && (!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0) {
		return nil, domain.ErrUnsafePath
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, errors.New("LAN registry unavailable")
	}
	db.SetMaxOpenConns(1)
	fail := func() (*registry, error) {
		_ = db.Close()
		return nil, errors.New("LAN registry initialization failed")
	}
	for _, q := range []string{"PRAGMA foreign_keys=ON", "PRAGMA busy_timeout=5000", "PRAGMA journal_mode=WAL"} {
		if _, err = db.Exec(q); err != nil {
			return fail()
		}
	}
	if create {
		_, err = db.Exec(`CREATE TABLE namespaces(id TEXT PRIMARY KEY,name TEXT NOT NULL UNIQUE);
CREATE TABLE clients(namespace TEXT NOT NULL REFERENCES namespaces(id),fingerprint TEXT NOT NULL,read_only INTEGER NOT NULL,revoked INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(namespace,fingerprint));
PRAGMA user_version=1;`)
		if err != nil {
			return fail()
		}
	}
	var version int
	if err = db.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != Version {
		return fail()
	}
	if err = os.Chmod(path, 0600); err != nil {
		return fail()
	}
	return &registry{db}, nil
}

func (r *registry) authorize(ctx context.Context, ns domain.ID, fingerprint string, write bool) bool {
	var readOnly bool
	if r.QueryRowContext(ctx, "SELECT read_only FROM clients WHERE namespace=? AND fingerprint=? AND revoked=0", ns, fingerprint).Scan(&readOnly) != nil {
		return false
	}
	return !write || !readOnly
}

func CreateNamespace(ctx context.Context, dir, name string) (Namespace, error) {
	if len(name) == 0 || len(name) > 64 {
		return Namespace{}, errors.New("namespace name must contain 1 to 64 bytes")
	}
	for _, c := range name {
		if c < 32 || c == 127 {
			return Namespace{}, errors.New("invalid namespace name")
		}
	}
	r, err := openRegistry(dir, false)
	if err != nil {
		return Namespace{}, err
	}
	defer r.Close()
	n := Namespace{ID: domain.NewID(), Name: name}
	if _, err = r.ExecContext(ctx, "INSERT INTO namespaces(id,name) VALUES(?,?)", n.ID, n.Name); err != nil {
		return Namespace{}, errors.New("namespace name already exists or registry is unavailable")
	}
	return n, nil
}

func Namespaces(ctx context.Context, dir string) ([]Namespace, error) {
	r, err := openRegistry(dir, false)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	rows, err := r.QueryContext(ctx, "SELECT id,name FROM namespaces ORDER BY name")
	if err != nil {
		return nil, errors.New("LAN registry read failed")
	}
	defer rows.Close()
	out := []Namespace{}
	for rows.Next() {
		var n Namespace
		if err = rows.Scan(&n.ID, &n.Name); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func Clients(ctx context.Context, dir string) ([]Client, error) {
	r, err := openRegistry(dir, false)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	rows, err := r.QueryContext(ctx, "SELECT namespace,fingerprint,read_only,revoked FROM clients ORDER BY namespace,fingerprint")
	if err != nil {
		return nil, errors.New("LAN registry read failed")
	}
	defer rows.Close()
	out := []Client{}
	for rows.Next() {
		var c Client
		if err = rows.Scan(&c.Namespace, &c.Fingerprint, &c.ReadOnly, &c.Revoked); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func Revoke(ctx context.Context, dir string, namespace domain.ID, fingerprint string) error {
	if !namespace.Valid() {
		return domain.ErrUnsafePath
	}
	r, err := openRegistry(dir, false)
	if err != nil {
		return err
	}
	defer r.Close()
	result, err := r.ExecContext(ctx, "UPDATE clients SET revoked=1 WHERE namespace=? AND fingerprint=? AND revoked=0", namespace, fingerprint)
	if err != nil {
		return errors.New("LAN authorization update failed")
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return domain.ErrNotFound
	}
	return nil
}

func writeFile(file string, data []byte) error {
	abs, err := filepath.Abs(file)
	if err != nil {
		return err
	}
	return restore.Write(filepath.Dir(abs), filepath.Base(abs), data)
}
func readFile(file string) ([]byte, error) {
	abs, err := filepath.Abs(file)
	if err != nil {
		return nil, err
	}
	b, err := restore.Read(filepath.Dir(abs), filepath.Base(abs))
	if err != nil {
		return nil, errors.New("LAN control file unavailable")
	}
	if len(b) > MaxControlSize {
		return nil, errors.New("LAN control document exceeds size limit")
	}
	return b, nil
}
