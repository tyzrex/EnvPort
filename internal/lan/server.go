package lan

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/envport-dev/envport/internal/domain"
	"github.com/envport-dev/envport/internal/storage/filesystem"
)

type Server struct {
	info     HostInfo
	registry *registry
	store    *filesystem.Store
	identity tls.Certificate
	inflight chan struct{}
}

func OpenServer(dir string, secret Secret) (*Server, error) {
	info, err := Inspect(dir)
	if err != nil {
		return nil, err
	}
	i, err := loadIdentity(dir, "server-key.age", secret)
	if err != nil {
		return nil, err
	}
	pair, err := i.TLS(x509.ExtKeyUsageServerAuth)
	if err != nil {
		return nil, err
	}
	if Fingerprint(pair.Leaf) != info.Fingerprint {
		return nil, errors.New("LAN host identity mismatch")
	}
	r, err := openRegistry(dir, false)
	if err != nil {
		return nil, err
	}
	store, err := filesystem.Open(filepath.Join(dir, "objects"))
	if err != nil {
		r.Close()
		return nil, err
	}
	return &Server{info: info, registry: r, store: store, identity: pair, inflight: make(chan struct{}, 8)}, nil
}

func (s *Server) Close() error { return errors.Join(s.store.Close(), s.registry.Close()) }
func (s *Server) TLSConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{s.identity}, ClientAuth: tls.RequireAnyClientCert, SessionTicketsDisabled: true, VerifyConnection: func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) != 1 {
			return errors.New("client certificate required")
		}
		cert := cs.PeerCertificates[0]
		// Validate the pinned client identity's self-signature, lifetime and TLS purpose.
		pemText := string(pemCertificate(cert.Raw))
		if _, err := Certificate(pemText, x509.ExtKeyUsageClientAuth); err != nil {
			return errors.New("invalid client identity")
		}
		return nil
	}}
}

// Run serves only TLS on an explicitly chosen private address. A nil ready callback
// is valid; tests and the CLI use it to report readiness after the listener exists.
func (s *Server) Run(ctx context.Context, listen string, ready func(net.Addr)) error {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return errors.New("listen address requires a literal private IP and port")
	}
	n, portErr := strconv.Atoi(port)
	if portErr != nil || n < 1 || n > 65535 {
		return errors.New("listen address requires a numeric port between 1 and 65535")
	}
	a, err := netip.ParseAddr(host)
	if err != nil || a.Zone() != "" || (a.IsUnspecified() || (!a.IsPrivate() && !a.IsLoopback() && !a.IsLinkLocalUnicast())) {
		return errors.New("listen address must be a literal private or loopback IP; wildcard binding is disabled")
	}
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return errors.New("cannot bind LAN listener")
	}
	return s.Serve(ctx, listener, ready)
}

func (s *Server) Serve(ctx context.Context, listener net.Listener, ready func(net.Addr)) error {
	listener = &boundedListener{Listener: listener, slots: make(chan struct{}, 32), done: make(chan struct{})}
	defer listener.Close()
	server := &http.Server{Handler: s, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 45 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10, ErrorLog: log.New(io.Discard, "", 0), TLSConfig: s.TLSConfig()}
	finished := make(chan struct{})
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		select {
		case <-ctx.Done():
			shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if server.Shutdown(shutdown) != nil {
				_ = server.Close()
			}
		case <-finished:
		}
	}()
	if ready != nil {
		ready(listener.Addr())
	}
	err := server.Serve(tls.NewListener(listener, server.TLSConfig))
	close(finished)
	<-shutdownDone
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return errors.New("LAN listener stopped unexpectedly")
}

func respondError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Error string `json:"error"`
	}{code})
}
func storageError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, domain.ErrNotFound):
		respondError(w, 404, "not_found")
	case errors.Is(err, domain.ErrPrecondition):
		respondError(w, 412, "precondition_failed")
	case errors.Is(err, domain.ErrUnsafePath):
		respondError(w, 400, "invalid_key")
	default:
		respondError(w, 503, "storage_unavailable")
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.TLS == nil || len(r.TLS.PeerCertificates) != 1 {
		respondError(w, 401, "client_identity_required")
		return
	}
	if r.Header.Get("Origin") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("X-EnvPort-Protocol") != "1" {
		respondError(w, 403, "client_protocol_required")
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if len(parts) != 5 || parts[0] != "lan" || parts[1] != "v1" || parts[2] != "namespaces" || !domain.ID(parts[3]).Valid() || r.URL.RawPath != "" {
		respondError(w, 404, "not_found")
		return
	}
	ns := domain.ID(parts[3])
	cert := r.TLS.PeerCertificates[0]
	if time.Now().Before(cert.NotBefore) || !time.Now().Before(cert.NotAfter) {
		respondError(w, 403, "access_denied")
		return
	}
	write := r.Method == http.MethodPut || r.Method == http.MethodDelete
	// Check every operation, including requests on an established TLS connection.
	if !s.registry.authorize(r.Context(), ns, Fingerprint(cert), write) {
		respondError(w, 403, "access_denied")
		return
	}
	select {
	case s.inflight <- struct{}{}:
		defer func() { <-s.inflight }()
	default:
		respondError(w, 429, "busy")
		return
	}
	if parts[4] == "capabilities" && r.Method == http.MethodGet && r.URL.RawQuery == "" {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			Version      int                 `json:"version"`
			Capabilities domain.Capabilities `json:"capabilities"`
		}{Version, s.store.Capabilities()})
		return
	}
	if parts[4] != "objects" {
		respondError(w, 404, "not_found")
		return
	}
	query, err := urlQuery(r.URL.RawQuery)
	if err != nil {
		respondError(w, 400, "invalid_query")
		return
	}
	base := "namespaces/" + string(ns) + "/"
	key := query.Get("key")
	if key == "" && r.Method == http.MethodGet {
		s.list(w, r, base, query)
		return
	}
	if len(query) != 1 || domain.ValidateKey(key) != nil {
		respondError(w, 400, "invalid_key")
		return
	}
	objectKey := base + key
	switch r.Method {
	case http.MethodGet:
		body, info, err := s.store.Get(r.Context(), objectKey)
		if err != nil {
			storageError(w, err)
			return
		}
		defer body.Close()
		objectHeaders(w, info)
		_, _ = io.Copy(w, body)
	case http.MethodHead:
		info, err := s.store.Head(r.Context(), objectKey)
		if err != nil {
			storageError(w, err)
			return
		}
		objectHeaders(w, info)
		w.WriteHeader(http.StatusOK)
	case http.MethodPut:
		condition, err := writeCondition(r)
		if err != nil {
			respondError(w, 428, "write_condition_required")
			return
		}
		if r.ContentLength > domain.MaxObjectSize {
			respondError(w, 413, "object_too_large")
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, domain.MaxObjectSize))
		if err != nil {
			var large *http.MaxBytesError
			if errors.As(err, &large) {
				respondError(w, 413, "object_too_large")
			} else {
				respondError(w, 400, "incomplete_body")
			}
			return
		}
		info, err := s.store.Put(r.Context(), objectKey, bytes.NewReader(body), condition)
		if err != nil {
			storageError(w, err)
			return
		}
		w.Header().Set("ETag", strconv.Quote(info.ETag))
		w.Header().Set("X-EnvPort-Object-Size", strconv.FormatInt(info.Size, 10))
		w.WriteHeader(http.StatusOK)
	case http.MethodDelete:
		if err := s.store.Delete(r.Context(), objectKey); err != nil {
			storageError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		respondError(w, 405, "method_not_allowed")
	}
}

func objectHeaders(w http.ResponseWriter, info domain.ObjectInfo) {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(info.Size, 10))
	w.Header().Set("ETag", strconv.Quote(info.ETag))
}

func writeCondition(r *http.Request) (domain.Condition, error) {
	match, none, mode := r.Header.Get("If-Match"), r.Header.Get("If-None-Match"), r.Header.Get("X-EnvPort-Write-Mode")
	if len(r.Header.Values("If-Match")) > 1 || len(r.Header.Values("If-None-Match")) > 1 || len(r.Header.Values("X-EnvPort-Write-Mode")) > 1 {
		return domain.Condition{}, errors.New("ambiguous write condition")
	}
	if match == "" && none == "*" && mode == "" {
		return domain.Condition{Mode: domain.CreateIfAbsent}, nil
	}
	if match != "" && none == "" && mode == "" {
		etag, err := strconv.Unquote(match)
		if err == nil && etag != "" && len(etag) <= 1024 {
			return domain.Condition{Mode: domain.IfETagMatch, ETag: etag}, nil
		}
	}
	if match == "" && none == "" && mode == "unconditional" {
		return domain.Condition{Mode: domain.Unconditional}, nil
	}
	return domain.Condition{}, errors.New("invalid write condition")
}
