package lan

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCertificatePurposesAndBoundedRequests(t *testing.T) {
	identity, err := NewIdentity("")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = identity.TLS(x509.ExtKeyUsageClientAuth); err != nil {
		t.Fatal(err)
	}
	if _, err = identity.TLS(x509.ExtKeyUsageServerAuth); err == nil {
		t.Fatal("client certificate accepted as server")
	}
	request := Request{Version: Version, ID: "11111111111111111111111111111111", Certificate: identity.Certificate, Expires: time.Now().Add(-time.Second)}
	if request.Validate() == nil {
		t.Fatal("expired request accepted")
	}
	request.Expires = time.Now().Add(time.Hour)
	if request.Validate() == nil {
		t.Fatal("unbounded request expiry accepted")
	}
	request.Expires = time.Now().Add(32 * time.Minute)
	if request.Validate() != nil {
		t.Fatal("bounded clock skew not tolerated")
	}
	request.Version = 99
	if request.Validate() == nil {
		t.Fatal("unknown request version accepted")
	}
	var output Request
	if Decode([]byte(`{"version":1,"unknown":true}`), &output) == nil {
		t.Fatal("unknown control field accepted")
	}
	b, _ := json.Marshal(request)
	if Decode(append(b, b...), &output) == nil {
		t.Fatal("trailing document accepted")
	}
}

func TestHostInitializationRejectsSymlinkAncestorWithoutCreatingDirectories(t *testing.T) {
	parent, outside := t.TempDir(), t.TempDir()
	if err := os.Symlink(outside, filepath.Join(parent, "link")); err != nil {
		t.Skip(err)
	}
	if _, err := Init(context.Background(), filepath.Join(parent, "link", "new-host"), "https://127.0.0.1:7443", func() (string, error) { t.Fatal("unsafe host initialization requested a secret"); return "", nil }); err == nil {
		t.Fatal("symlink ancestor accepted")
	}
	files, err := os.ReadDir(outside)
	if err != nil || len(files) != 0 {
		t.Fatal("host initialization modified a path outside the selected tree")
	}
}
