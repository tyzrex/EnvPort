// Package lan implements the built-in, authenticated LAN ciphertext-storage host.
// TLS identities grant storage access only; they are never vault decryption keys.
package lan

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"time"

	crypt "github.com/envport-dev/envport/internal/crypto"
	"github.com/envport-dev/envport/internal/domain"
	"github.com/envport-dev/envport/internal/restore"
)

const Version = 1
const MaxControlSize = 32 << 10

type Secret func() (string, error)

type Identity struct {
	Version     int    `json:"version"`
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"private_key"`
}

type Request struct {
	Version     int       `json:"version"`
	ID          domain.ID `json:"request_id"`
	Certificate string    `json:"certificate"`
	Expires     time.Time `json:"expires_at"`
}

type Connection struct {
	Version           int       `json:"version"`
	Request           Request   `json:"request"`
	Endpoint          string    `json:"endpoint"`
	Namespace         domain.ID `json:"namespace"`
	ServerCertificate string    `json:"server_certificate"`
	ReadOnly          bool      `json:"read_only"`
	Signature         []byte    `json:"signature,omitempty"`
}

// Config contains public trust material and a reference to a private encrypted file.
type Config struct {
	Version           int       `json:"version"`
	Endpoint          string    `json:"endpoint"`
	Namespace         domain.ID `json:"namespace"`
	ServerCertificate string    `json:"server_certificate"`
	CredentialRef     domain.ID `json:"credential_ref"`
	Verified          bool      `json:"conditional_writes_verified"`
}

func Decode(b []byte, out any) error {
	if len(b) > MaxControlSize {
		return errors.New("LAN control document exceeds size limit")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return errors.New("invalid LAN control document")
	}
	return nil
}

// Endpoint accepts literal private/loopback/link-local addresses only. No DNS,
// proxies, public IPs, relay discovery, redirects or cloud credentials are used.
func Endpoint(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || u.Opaque != "" || u.RawPath != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("LAN endpoint must be an HTTPS private IP address with a port")
	}
	a, err := netip.ParseAddr(u.Hostname())
	if err != nil || a.Zone() != "" || a.IsUnspecified() || !(a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast()) {
		return nil, errors.New("LAN endpoint requires a literal private, loopback or link-local IP address")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New("LAN endpoint requires a valid explicit port")
	}
	u.Path = ""
	return u, nil
}

func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func Certificate(text string, usage x509.ExtKeyUsage) (*x509.Certificate, error) {
	block, rest := pem.Decode([]byte(text))
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("invalid LAN certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.New("invalid LAN certificate")
	}
	if _, ok := cert.PublicKey.(ed25519.PublicKey); !ok {
		return nil, errors.New("unsupported LAN certificate key")
	}
	if cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) != nil {
		return nil, errors.New("invalid LAN certificate signature")
	}
	now := time.Now()
	if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return nil, errors.New("LAN certificate expired or not yet valid")
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != usage {
		return nil, errors.New("invalid LAN certificate purpose")
	}
	return cert, nil
}

func NewIdentity(serverEndpoint string) (Identity, error) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Identity{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return Identity{}, err
	}
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "EnvPort LAN"}, NotBefore: time.Now().Add(-5 * time.Minute), NotAfter: time.Now().AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true}
	if serverEndpoint != "" {
		u, err := Endpoint(serverEndpoint)
		if err != nil {
			return Identity{}, err
		}
		cert.IsCA = true
		cert.KeyUsage |= x509.KeyUsageCertSign
		cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		cert.IPAddresses = []net.IP{net.ParseIP(u.Hostname())}
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, pub, key)
	if err != nil {
		return Identity{}, errors.New("create LAN certificate failed")
	}
	pk, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return Identity{}, err
	}
	return Identity{Version: Version, Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}))}, nil
}

func (i Identity) TLS(usage x509.ExtKeyUsage) (tls.Certificate, error) {
	if i.Version != Version {
		return tls.Certificate{}, errors.New("unsupported LAN identity version")
	}
	cert, err := Certificate(i.Certificate, usage)
	if err != nil {
		return tls.Certificate{}, err
	}
	pair, err := tls.X509KeyPair([]byte(i.Certificate), []byte(i.PrivateKey))
	if err != nil {
		return tls.Certificate{}, errors.New("invalid LAN private identity")
	}
	pair.Leaf = cert
	return pair, nil
}

func saveIdentity(root, name string, identity Identity, secret Secret) error {
	pass, err := secret()
	if err != nil {
		return err
	}
	plain, err := json.Marshal(identity)
	if err != nil {
		return err
	}
	sealed, err := crypt.Seal(plain, pass)
	if err != nil {
		return err
	}
	return restore.Write(root, name, sealed)
}

func loadIdentity(root, name string, secret Secret) (Identity, error) {
	var identity Identity
	b, err := restore.Read(root, name)
	if err != nil {
		return identity, errors.New("encrypted LAN identity is unavailable")
	}
	pass, err := secret()
	if err != nil {
		return identity, err
	}
	plain, err := crypt.Open(b, pass)
	if err != nil {
		return identity, errors.New("LAN identity unlock failed")
	}
	err = Decode(plain, &identity)
	return identity, err
}

func RequestFingerprint(r Request) string {
	b, _ := json.Marshal(r)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func (r Request) Validate() error {
	if r.Version != Version || !r.ID.Valid() || !r.Expires.After(time.Now()) || r.Expires.After(time.Now().Add(35*time.Minute)) {
		return errors.New("invalid or expired LAN join request")
	}
	_, err := Certificate(r.Certificate, x509.ExtKeyUsageClientAuth)
	return err
}

// NewRequest writes only public material to the request file. The TLS private key
// is generated on the client and remains in its encrypted local envelope.
func NewRequest(root, output string, secret Secret) (Request, error) {
	i, err := NewIdentity("")
	if err != nil {
		return Request{}, err
	}
	r := Request{Version: Version, ID: domain.NewID(), Certificate: i.Certificate, Expires: time.Now().UTC().Add(30 * time.Minute)}
	if err = saveIdentity(root, "lan-client-"+string(r.ID)+".age", i, secret); err != nil {
		return Request{}, err
	}
	b, err := json.Marshal(r)
	if err != nil {
		return Request{}, err
	}
	if err = writeFile(output, b); err != nil {
		return Request{}, err
	}
	return r, nil
}

func LoadClientIdentity(root string, ref domain.ID, secret Secret) (Identity, error) {
	if !ref.Valid() {
		return Identity{}, errors.New("invalid LAN credential reference")
	}
	return loadIdentity(root, "lan-client-"+string(ref)+".age", secret)
}

func ImportConnection(root, file, trustedFingerprint string, secret Secret) (Config, error) {
	b, err := readFile(file)
	if err != nil {
		return Config{}, err
	}
	var c Connection
	if err = Decode(b, &c); err != nil {
		return Config{}, err
	}
	if c.Version != Version || !c.Namespace.Valid() {
		return Config{}, errors.New("invalid LAN connection binding")
	}
	if _, err = Endpoint(c.Endpoint); err != nil {
		return Config{}, err
	}
	if err = c.Request.Validate(); err != nil {
		return Config{}, err
	}
	cert, err := Certificate(c.ServerCertificate, x509.ExtKeyUsageServerAuth)
	if err != nil {
		return Config{}, err
	}
	if Fingerprint(cert) != trustedFingerprint {
		return Config{}, errors.New("server fingerprint does not match trusted host")
	}
	signature := c.Signature
	c.Signature = nil
	message, _ := json.Marshal(c)
	if !ed25519.Verify(cert.PublicKey.(ed25519.PublicKey), message, signature) {
		return Config{}, errors.New("LAN connection signature is invalid")
	}
	i, err := LoadClientIdentity(root, c.Request.ID, secret)
	if err != nil {
		return Config{}, err
	}
	if i.Certificate != c.Request.Certificate {
		return Config{}, errors.New("LAN connection belongs to another client")
	}
	if _, err = i.TLS(x509.ExtKeyUsageClientAuth); err != nil {
		return Config{}, err
	}
	return Config{Version: Version, Endpoint: c.Endpoint, Namespace: c.Namespace, ServerCertificate: c.ServerCertificate, CredentialRef: c.Request.ID}, nil
}
