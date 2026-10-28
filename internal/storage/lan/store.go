// Package lan adapts EnvPort's pinned mutual-TLS LAN protocol to ObjectStore.
package lan

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/envport-dev/envport/internal/domain"
	protocol "github.com/envport-dev/envport/internal/lan"
)

type Store struct {
	client    *http.Client
	transport *http.Transport
	endpoint  string
	namespace domain.ID
	verified  bool
}

func Open(ctx context.Context, c protocol.Config, identity protocol.Identity) (*Store, error) {
	if c.Version != protocol.Version || !c.Namespace.Valid() || !c.CredentialRef.Valid() {
		return nil, errors.New("invalid LAN profile")
	}
	u, err := protocol.Endpoint(c.Endpoint)
	if err != nil {
		return nil, err
	}
	server, err := protocol.Certificate(c.ServerCertificate, x509.ExtKeyUsageServerAuth)
	if err != nil {
		return nil, err
	}
	if err = server.VerifyHostname(u.Hostname()); err != nil {
		return nil, errors.New("LAN server certificate does not match endpoint")
	}
	pair, err := identity.TLS(x509.ExtKeyUsageClientAuth)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(server)
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{Proxy: nil, MaxIdleConns: 8, MaxIdleConnsPerHost: 4, MaxConnsPerHost: 8, MaxResponseHeaderBytes: 16 << 10, ResponseHeaderTimeout: 30 * time.Second, IdleConnTimeout: 30 * time.Second, TLSHandshakeTimeout: 5 * time.Second, DisableCompression: true,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if address != u.Host {
				return nil, errors.New("LAN transport refused another endpoint")
			}
			return dialer.DialContext(ctx, network, address)
		},
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{pair}, VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) != 1 || subtle.ConstantTimeCompare(cs.PeerCertificates[0].Raw, server.Raw) != 1 {
				return errors.New("LAN server identity changed")
			}
			return nil
		}},
	}
	client := &http.Client{Transport: transport, Timeout: 45 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return errors.New("LAN redirects are disabled") }}
	s := &Store{client: client, transport: transport, endpoint: u.String(), namespace: c.Namespace}
	response, err := s.do(ctx, http.MethodGet, "capabilities", nil, nil, domain.Condition{})
	if err != nil {
		transport.CloseIdleConnections()
		return nil, err
	}
	defer response.Body.Close()
	var result struct {
		Version      int                 `json:"version"`
		Capabilities domain.Capabilities `json:"capabilities"`
	}
	if decodeResponse(response.Body, &result, protocol.MaxControlSize) != nil || result.Version != protocol.Version || !result.Capabilities.ConditionalCreate || !result.Capabilities.ConditionalReplace || !result.Capabilities.Verified {
		transport.CloseIdleConnections()
		return nil, errors.New("LAN host protocol or conditional writes are unsupported")
	}
	s.verified = c.Verified
	return s, nil
}

func (s *Store) Close() error { s.transport.CloseIdleConnections(); return nil }
func (s *Store) Capabilities() domain.Capabilities {
	return domain.Capabilities{ConditionalCreate: s.verified, ConditionalReplace: s.verified, Verified: s.verified, MaxObjectSize: domain.MaxObjectSize}
}

func decodeResponse(r io.Reader, out any, limit int64) error {
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil || int64(len(b)) > limit {
		return domain.ErrCorrupt
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return domain.ErrCorrupt
	}
	return nil
}

func (s *Store) do(ctx context.Context, method, resource string, query url.Values, body []byte, c domain.Condition) (*http.Response, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	target := s.endpoint + "/lan/v1/namespaces/" + string(s.namespace) + "/" + resource
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("invalid LAN request")
	}
	req.Header.Set("X-EnvPort-Protocol", "1")
	if method == http.MethodPut {
		req.Header.Set("Content-Type", "application/octet-stream")
		switch c.Mode {
		case domain.CreateIfAbsent:
			req.Header.Set("If-None-Match", "*")
		case domain.IfETagMatch:
			req.Header.Set("If-Match", c.ETag)
		case domain.Unconditional:
			req.Header.Set("X-EnvPort-Write-Mode", "unconditional")
		}
	}
	response, err := s.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("LAN connection failed; check host availability, trusted certificate and client authorization")
	}
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return response, nil
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case 404:
		return nil, domain.ErrNotFound
	case 412:
		return nil, domain.ErrPrecondition
	case 401, 403:
		return nil, errors.New("LAN access denied; authorize this client for the selected namespace")
	case 413:
		return nil, errors.New("LAN object size limit exceeded")
	case 429:
		return nil, errors.New("LAN host busy; retry with a fresh operation plan")
	default:
		return nil, errors.New("LAN storage operation failed")
	}
}

func validateETag(tag string) bool {
	plain, err := strconv.Unquote(tag)
	if err != nil || len(plain) != 64 {
		return false
	}
	for _, c := range plain {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func (s *Store) Put(ctx context.Context, key string, r io.Reader, c domain.Condition) (domain.ObjectInfo, error) {
	if err := domain.ValidateKey(key); err != nil {
		return domain.ObjectInfo{}, err
	}
	if err := c.Validate(); err != nil {
		return domain.ObjectInfo{}, err
	}
	if c.Mode == domain.IfETagMatch {
		value, err := strconv.Unquote(c.ETag)
		if err != nil || value == "" || len(value) > 1024 {
			return domain.ObjectInfo{}, errors.New("invalid LAN match token")
		}
	}

	body, err := io.ReadAll(io.LimitReader(r, domain.MaxObjectSize+1))
	if err != nil || int64(len(body)) > domain.MaxObjectSize {
		return domain.ObjectInfo{}, errors.New("object read failed or size limit exceeded")
	}
	response, err := s.do(ctx, http.MethodPut, "objects", url.Values{"key": {key}}, body, c)
	if err != nil {
		return domain.ObjectInfo{}, err
	}
	defer response.Body.Close()
	tag := response.Header.Get("ETag")
	size, err := strconv.ParseInt(response.Header.Get("X-EnvPort-Object-Size"), 10, 64)
	if err != nil || size != int64(len(body)) || !validateETag(tag) {
		return domain.ObjectInfo{}, domain.ErrCorrupt
	}
	return domain.ObjectInfo{Key: key, ETag: tag, Size: size}, nil
}

func (s *Store) Get(ctx context.Context, key string) (io.ReadCloser, domain.ObjectInfo, error) {
	if err := domain.ValidateKey(key); err != nil {
		return nil, domain.ObjectInfo{}, err
	}
	response, err := s.do(ctx, http.MethodGet, "objects", url.Values{"key": {key}}, nil, domain.Condition{})
	if err != nil {
		return nil, domain.ObjectInfo{}, err
	}
	tag := response.Header.Get("ETag")
	if response.ContentLength < 0 || response.ContentLength > domain.MaxObjectSize || !validateETag(tag) {
		response.Body.Close()
		return nil, domain.ObjectInfo{}, domain.ErrCorrupt
	}
	return response.Body, domain.ObjectInfo{Key: key, ETag: tag, Size: response.ContentLength}, nil
}

func (s *Store) Head(ctx context.Context, key string) (domain.ObjectInfo, error) {
	if err := domain.ValidateKey(key); err != nil {
		return domain.ObjectInfo{}, err
	}
	response, err := s.do(ctx, http.MethodHead, "objects", url.Values{"key": {key}}, nil, domain.Condition{})
	if err != nil {
		return domain.ObjectInfo{}, err
	}
	defer response.Body.Close()
	tag := response.Header.Get("ETag")
	if response.ContentLength < 0 || response.ContentLength > domain.MaxObjectSize || !validateETag(tag) {
		return domain.ObjectInfo{}, domain.ErrCorrupt
	}
	return domain.ObjectInfo{Key: key, ETag: tag, Size: response.ContentLength}, nil
}

func (s *Store) List(ctx context.Context, prefix, cursor string, limit int) (domain.Page, error) {
	if prefix != "" && domain.ValidateKey(strings.TrimSuffix(prefix, "/")) != nil {
		return domain.Page{}, domain.ErrUnsafePath
	}
	if limit < 1 || limit > 1000 {
		limit = 1000
	}
	response, err := s.do(ctx, http.MethodGet, "objects", url.Values{"prefix": {prefix}, "cursor": {cursor}, "limit": {strconv.Itoa(limit)}}, nil, domain.Condition{})
	if err != nil {
		return domain.Page{}, err
	}
	defer response.Body.Close()
	var result struct {
		Version int `json:"version"`
		domain.Page
	}
	if decodeResponse(response.Body, &result, 2<<20) != nil || result.Version != protocol.Version || len(result.Objects) > limit {
		return domain.Page{}, domain.ErrCorrupt
	}
	for _, o := range result.Objects {
		if !strings.HasPrefix(o.Key, prefix) || domain.ValidateKey(o.Key) != nil || o.Size < 0 || o.Size > domain.MaxObjectSize || !validateETag(o.ETag) {
			return domain.Page{}, domain.ErrCorrupt
		}
	}
	if result.Cursor != "" {
		base := "namespaces/" + string(s.namespace) + "/"
		if !strings.HasPrefix(result.Cursor, base) || domain.ValidateKey(result.Cursor) != nil {
			return domain.Page{}, domain.ErrCorrupt
		}
	}
	return result.Page, nil
}

func (s *Store) Delete(ctx context.Context, key string) error {
	if err := domain.ValidateKey(key); err != nil {
		return err
	}
	response, err := s.do(ctx, http.MethodDelete, "objects", url.Values{"key": {key}}, nil, domain.Condition{})
	if err != nil {
		return err
	}
	return response.Body.Close()
}

var _ domain.ObjectStore = (*Store)(nil)
