package lan

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/envport-dev/envport/internal/domain"
	protocol "github.com/envport-dev/envport/internal/lan"
	"github.com/envport-dev/envport/internal/storage"
)

var fixturePass = func() (string, error) { return "synthetic-lan-fixture-passphrase", nil }

type hostFixture struct {
	dir  string
	info protocol.HostInfo
	host *protocol.Server
}
type clientFixture struct {
	dir         string
	config      protocol.Config
	identity    protocol.Identity
	store       *Store
	fingerprint string
	connection  string
}

func newHost(t *testing.T) *hostFixture {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "host")
	info, err := protocol.Init(context.Background(), dir, "https://"+listener.Addr().String(), fixturePass)
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	host, err := protocol.OpenServer(dir, fixturePass)
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan error, 1)
	go func() { finished <- host.Serve(ctx, listener, nil) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-finished:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(10 * time.Second):
			t.Error("LAN server did not shut down")
		}
		_ = host.Close()
	})
	return &hostFixture{dir, info, host}
}

func (h *hostFixture) client(t *testing.T, namespace domain.ID, readOnly bool) *clientFixture {
	t.Helper()
	ctx := context.Background()
	root := t.TempDir()
	requestFile := filepath.Join(root, "request.json")
	connectionFile := filepath.Join(root, "connection.json")
	request, err := protocol.NewRequest(root, requestFile, fixturePass)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = protocol.Authorize(ctx, h.dir, requestFile, protocol.RequestFingerprint(request), namespace, readOnly, connectionFile, fixturePass); err != nil {
		t.Fatal(err)
	}
	cfg, err := protocol.ImportConnection(root, connectionFile, h.info.Fingerprint, fixturePass)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := protocol.LoadClientIdentity(root, cfg.CredentialRef, fixturePass)
	if err != nil {
		t.Fatal(err)
	}
	store, err := Open(ctx, cfg, identity)
	if err != nil {
		t.Fatal(err)
	}
	if !readOnly {
		if _, err = storage.Probe(ctx, store); err != nil {
			store.Close()
			t.Fatal(err)
		}
		store.Close()
		cfg.Verified = true
		store, err = Open(ctx, cfg, identity)
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { store.Close() })
	cert, err := protocol.Certificate(identity.Certificate, x509.ExtKeyUsageClientAuth)
	if err != nil {
		t.Fatal(err)
	}
	return &clientFixture{root, cfg, identity, store, protocol.Fingerprint(cert), connectionFile}
}

func TestLANStoreIsolationCASPaginationAndRevocation(t *testing.T) {
	h := newHost(t)
	ctx := context.Background()
	a := h.client(t, h.info.DefaultNamespace, false)
	b := h.client(t, h.info.DefaultNamespace, false)
	other, err := protocol.CreateNamespace(ctx, h.dir, "separate-user")
	if err != nil {
		t.Fatal(err)
	}
	foreign := a.config
	foreign.Namespace = other.ID
	if store, err := Open(ctx, foreign, a.identity); err == nil {
		store.Close()
		t.Fatal("client accessed an unauthorized namespace")
	}
	initial, err := a.store.Put(ctx, "refs/main", bytes.NewBufferString("synthetic-original"), domain.Condition{Mode: domain.CreateIfAbsent})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i, s := range []*Store{a.store, b.store} {
		wg.Add(1)
		go func(i int, s *Store) {
			defer wg.Done()
			_, err := s.Put(ctx, "refs/main", bytes.NewReader([]byte{byte(i)}), domain.Condition{Mode: domain.IfETagMatch, ETag: initial.ETag})
			results <- err
		}(i, s)
	}
	wg.Wait()
	close(results)
	wins, losses := 0, 0
	for err := range results {
		if err == nil {
			wins++
		} else if errors.Is(err, domain.ErrPrecondition) {
			losses++
		} else {
			t.Fatal(err)
		}
	}
	if wins != 1 || losses != 1 {
		t.Fatal("LAN CAS did not produce exactly one winner")
	}
	for i, key := range []string{"round-trip/zero", "round-trip/binary", "round-trip/large"} {
		body := [][]byte{nil, {'\x00', '\xff', '\r', '\n'}, bytes.Repeat([]byte("synthetic-"), 1<<17)}[i]
		if _, err = a.store.Put(ctx, key, bytes.NewReader(body), domain.Condition{}); err != nil {
			t.Fatal(err)
		}
		r, info, err := a.store.Get(ctx, key)
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(r)
		r.Close()
		if err != nil || !bytes.Equal(got, body) || info.Size != int64(len(body)) {
			t.Fatal("LAN altered object bytes")
		}
		head, err := a.store.Head(ctx, key)
		if err != nil || head.ETag != info.ETag || head.Size != info.Size {
			t.Fatal("LAN HEAD mismatch")
		}
	}
	page, err := a.store.List(ctx, "round-trip/", "", 2)
	if err != nil || len(page.Objects) != 2 || page.Cursor == "" {
		t.Fatal("first LAN page failed")
	}
	next, err := a.store.List(ctx, "round-trip/", page.Cursor, 2)
	if err != nil || len(next.Objects) != 1 || next.Cursor != "" {
		t.Fatal("LAN pagination failed")
	}
	if _, err = a.store.List(ctx, "", "namespaces/"+string(other.ID)+"/object", 1); err == nil {
		t.Fatal("foreign namespace cursor accepted")
	}
	if _, err = a.store.Put(ctx, "../outside", bytes.NewReader(nil), domain.Condition{}); err == nil {
		t.Fatal("traversal accepted")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = a.store.Head(canceled, "refs/main"); !errors.Is(err, context.Canceled) {
		t.Fatal("LAN cancellation not propagated")
	}
	ro := h.client(t, h.info.DefaultNamespace, true)
	if _, err = ro.store.Head(ctx, "refs/main"); err != nil {
		t.Fatal("read-only access failed")
	}
	if _, err = ro.store.Put(ctx, "denied", bytes.NewReader(nil), domain.Condition{}); err == nil {
		t.Fatal("read-only client wrote object")
	}
	if err = ro.store.Delete(ctx, "refs/main"); err == nil {
		t.Fatal("read-only client deleted object")
	}
	if err = protocol.Revoke(ctx, h.dir, h.info.DefaultNamespace, a.fingerprint); err != nil {
		t.Fatal(err)
	}
	if _, err = a.store.Head(ctx, "refs/main"); err == nil {
		t.Fatal("revoked client retained access on existing connection")
	}
	requestBytes, err := os.ReadFile(filepath.Join(a.dir, "request.json"))
	if err != nil {
		t.Fatal(err)
	}
	var oldRequest protocol.Request
	if json.Unmarshal(requestBytes, &oldRequest) != nil {
		t.Fatal("request fixture invalid")
	}
	if _, err = protocol.Authorize(ctx, h.dir, filepath.Join(a.dir, "request.json"), protocol.RequestFingerprint(oldRequest), h.info.DefaultNamespace, false, filepath.Join(a.dir, "replayed-connection.json"), fixturePass); err == nil {
		t.Fatal("replayed request reactivated revoked client")
	}

	if _, err = b.store.Head(ctx, "refs/main"); err != nil {
		t.Fatal("revocation affected another client")
	}
	clients, err := protocol.Clients(ctx, h.dir)
	if err != nil || len(clients) != 3 {
		t.Fatal("client authorizations missing")
	}
	if _, err = protocol.Init(ctx, h.dir, h.info.Endpoint, fixturePass); err == nil {
		t.Fatal("host reinitialization replaced identity")
	}
}

func TestLANTrustAndCredentialSafety(t *testing.T) {
	h := newHost(t)
	ctx := context.Background()
	a := h.client(t, h.info.DefaultNamespace, false)
	if _, err := protocol.ImportConnection(a.dir, a.connection, "wrong-fingerprint", fixturePass); err == nil {
		t.Fatal("untrusted host imported")
	}
	stranger := t.TempDir()
	if _, err := protocol.ImportConnection(stranger, a.connection, h.info.Fingerprint, fixturePass); err == nil {
		t.Fatal("another installation imported client access without private identity")
	}
	if _, err := protocol.LoadClientIdentity(a.dir, a.config.CredentialRef, func() (string, error) { return "incorrect-synthetic-unlock-passphrase", nil }); err == nil {
		t.Fatal("wrong credential passphrase accepted")
	}
	encoded, _ := json.Marshal(a.config)
	if bytes.Contains(encoded, []byte("PRIVATE KEY")) || bytes.Contains(encoded, []byte(a.identity.PrivateKey)) {
		t.Fatal("private identity leaked into profile")
	}
	sealed, err := os.ReadFile(filepath.Join(a.dir, "lan-client-"+string(a.config.CredentialRef)+".age"))
	if err != nil || bytes.Contains(sealed, []byte("PRIVATE KEY")) {
		t.Fatal("client key not encrypted at rest")
	}
	otherIdentity, err := protocol.NewIdentity(h.info.Endpoint)
	if err != nil {
		t.Fatal(err)
	}
	changed := a.config
	changed.ServerCertificate = otherIdentity.Certificate
	if store, err := Open(ctx, changed, a.identity); err == nil {
		store.Close()
		t.Fatal("changed server certificate accepted")
	}
	unauthorized, err := protocol.NewIdentity("")
	if err != nil {
		t.Fatal(err)
	}
	if store, err := Open(ctx, a.config, unauthorized); err == nil {
		store.Close()
		t.Fatal("unknown client certificate gained storage access")
	}
	// A connection document is signed, including its namespace and endpoint.
	b, err := os.ReadFile(a.connection)
	if err != nil {
		t.Fatal(err)
	}
	var connection protocol.Connection
	json.Unmarshal(b, &connection)
	connection.Namespace = domain.NewID()
	b, _ = json.Marshal(connection)
	tampered := filepath.Join(a.dir, "tampered.json")
	os.WriteFile(tampered, b, 0600)
	if _, err = protocol.ImportConnection(a.dir, tampered, h.info.Fingerprint, fixturePass); err == nil {
		t.Fatal("modified connection accepted")
	}
	for _, endpoint := range []string{"http://127.0.0.1:7443", "https://8.8.8.8:7443", "https://example.com:7443", "https://user:password@192.168.1.10:7443", "https://127.0.0.1:7443/redirect", "https://127.0.0.1:7443/?query=secret", "https://0.0.0.0:7443", "https://[::ffff:8.8.8.8]:7443"} {
		if _, err = protocol.Endpoint(endpoint); err == nil {
			t.Fatal("unsafe LAN endpoint accepted")
		}
	}
}

func TestLANHTTPBoundary(t *testing.T) {
	h := newHost(t)
	a := h.client(t, h.info.DefaultNamespace, false)
	target := h.info.Endpoint + "/lan/v1/namespaces/" + string(h.info.DefaultNamespace) + "/objects?key=boundary"
	request := func(method, target string, headers map[string]string, body io.Reader) int {
		t.Helper()
		req, err := http.NewRequest(method, target, body)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-EnvPort-Protocol", "1")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		response, err := a.store.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, response.Body)
		return response.StatusCode
	}
	if status := request("PUT", target, nil, strings.NewReader("synthetic")); status != 428 {
		t.Fatalf("unconditional write without explicit mode returned %d", status)
	}
	if status := request("PUT", target, map[string]string{"If-Match": "\"old\"", "If-None-Match": "*"}, nil); status != 428 {
		t.Fatal("ambiguous condition accepted")
	}
	if status := request("PUT", target, map[string]string{"If-None-Match": "*", "Origin": "https://untrusted.invalid"}, nil); status != 403 {
		t.Fatal("browser origin accepted")
	}
	if status := request("PUT", target, map[string]string{"If-None-Match": "*"}, io.LimitReader(zeroReader{}, domain.MaxObjectSize+1)); status != 413 {
		t.Fatalf("oversized chunked request returned %d", status)
	}
	if status := request("PUT", target+"&key=other", map[string]string{"If-None-Match": "*"}, nil); status != 400 {
		t.Fatal("duplicate key accepted")
	}
	bad := h.info.Endpoint + "/lan/v1/namespaces/" + string(h.info.DefaultNamespace) + "/objects?key=" + url.QueryEscape("../../outside")
	if status := request("PUT", bad, map[string]string{"If-None-Match": "*"}, nil); status != 400 {
		t.Fatal("HTTP traversal accepted")
	}
	// No client certificate: TLS authentication must fail before an object response.
	serverCert, _ := protocol.Certificate(h.info.ServerCertificate, x509.ExtKeyUsageServerAuth)
	roots := x509.NewCertPool()
	roots.AddCert(serverCert)
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	if response, err := client.Get(target); err == nil {
		response.Body.Close()
		t.Fatal("unauthenticated TLS client reached storage")
	}
}

type zeroReader struct{}

func (zeroReader) Read(b []byte) (int, error) { clear(b); return len(b), nil }
