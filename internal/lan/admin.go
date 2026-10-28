package lan

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/envport-dev/envport/internal/domain"
	"github.com/envport-dev/envport/internal/restore"
)

type HostInfo struct {
	Version           int       `json:"version"`
	Endpoint          string    `json:"endpoint"`
	ServerCertificate string    `json:"server_certificate"`
	Fingerprint       string    `json:"server_fingerprint"`
	DefaultNamespace  domain.ID `json:"default_namespace"`
}

func Init(ctx context.Context, dir, endpoint string, secret Secret) (HostInfo, error) {
	u, err := Endpoint(endpoint)
	if err != nil {
		return HostInfo{}, err
	}
	abs, err := privateDirectory(dir, true)
	if err != nil {
		return HostInfo{}, err
	}
	for _, name := range []string{"server.json", "server-key.age", "registry.db"} {
		if _, err = os.Lstat(filepath.Join(abs, name)); !os.IsNotExist(err) {
			return HostInfo{}, errors.New("LAN host state already exists; refusing to replace identity or registry")
		}
	}
	identity, err := NewIdentity(u.String())
	if err != nil {
		return HostInfo{}, err
	}
	cert, err := Certificate(identity.Certificate, x509.ExtKeyUsageServerAuth)
	if err != nil {
		return HostInfo{}, err
	}
	if err = saveIdentity(abs, "server-key.age", identity, secret); err != nil {
		return HostInfo{}, err
	}
	r, err := openRegistry(abs, true)
	if err != nil {
		return HostInfo{}, err
	}
	defer r.Close()
	ns := domain.NewID()
	if _, err = r.ExecContext(ctx, "INSERT INTO namespaces(id,name) VALUES(?,'personal')", ns); err != nil {
		return HostInfo{}, errors.New("create default LAN namespace failed")
	}
	info := HostInfo{Version: Version, Endpoint: u.String(), ServerCertificate: identity.Certificate, Fingerprint: Fingerprint(cert), DefaultNamespace: ns}
	b, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return HostInfo{}, err
	}
	if err = restore.Write(abs, "server.json", b); err != nil {
		return HostInfo{}, err
	}
	return info, nil
}

func Inspect(dir string) (HostInfo, error) {
	var info HostInfo
	if _, err := privateDirectory(dir, false); err != nil {
		return info, err
	}
	b, err := restore.Read(dir, "server.json")
	if err != nil {
		return info, errors.New("LAN host is not initialized; run serve init")
	}
	if err = Decode(b, &info); err != nil {
		return info, err
	}
	if info.Version != Version || !info.DefaultNamespace.Valid() {
		return info, errors.New("unsupported LAN host configuration")
	}
	u, err := Endpoint(info.Endpoint)
	if err != nil {
		return info, err
	}
	cert, err := Certificate(info.ServerCertificate, x509.ExtKeyUsageServerAuth)
	if err != nil {
		return info, err
	}
	if Fingerprint(cert) != info.Fingerprint || cert.VerifyHostname(u.Hostname()) != nil {
		return info, errors.New("LAN host certificate binding is invalid")
	}
	return info, nil
}

func Authorize(ctx context.Context, dir, requestFile, confirmedFingerprint string, namespace domain.ID, readOnly bool, output string, secret Secret) (Connection, error) {
	if !namespace.Valid() {
		return Connection{}, errors.New("valid --namespace is required")
	}
	b, err := readFile(requestFile)
	if err != nil {
		return Connection{}, err
	}
	var request Request
	if err = Decode(b, &request); err != nil {
		return Connection{}, err
	}
	if err = request.Validate(); err != nil {
		return Connection{}, err
	}
	if RequestFingerprint(request) != confirmedFingerprint {
		return Connection{}, errors.New("request fingerprint does not match out-of-band confirmation")
	}
	info, err := Inspect(dir)
	if err != nil {
		return Connection{}, err
	}
	i, err := loadIdentity(dir, "server-key.age", secret)
	if err != nil {
		return Connection{}, err
	}
	pair, err := i.TLS(x509.ExtKeyUsageServerAuth)
	if err != nil {
		return Connection{}, err
	}
	if Fingerprint(pair.Leaf) != info.Fingerprint {
		return Connection{}, errors.New("LAN host identity mismatch")
	}
	connection := Connection{Version: Version, Request: request, Endpoint: info.Endpoint, Namespace: namespace, ServerCertificate: info.ServerCertificate, ReadOnly: readOnly}
	message, err := json.Marshal(connection)
	if err != nil {
		return Connection{}, err
	}
	connection.Signature = ed25519.Sign(pair.PrivateKey.(ed25519.PrivateKey), message)
	cert, err := Certificate(request.Certificate, x509.ExtKeyUsageClientAuth)
	if err != nil {
		return Connection{}, err
	}
	r, err := openRegistry(dir, false)
	if err != nil {
		return Connection{}, err
	}
	defer r.Close()
	tx, err := r.BeginTx(ctx, nil)
	if err != nil {
		return Connection{}, errors.New("LAN registry unavailable")
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "INSERT INTO clients(namespace,fingerprint,read_only) VALUES(?,?,?)", namespace, Fingerprint(cert), readOnly); err != nil {
		return Connection{}, errors.New("namespace is unavailable or client certificate was already authorized; create a fresh request")
	}
	b, err = json.MarshalIndent(connection, "", "  ")
	if err != nil {
		return Connection{}, err
	}
	if err = writeFile(output, b); err != nil {
		return Connection{}, err
	}
	if err = tx.Commit(); err != nil {
		return Connection{}, errors.New("LAN authorization commit failed")
	}
	return connection, nil
}
