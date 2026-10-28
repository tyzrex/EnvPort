package application

import (
	"bytes"
	"filippo.io/age"
	crypt "github.com/envport-dev/envport/internal/crypto"
	"github.com/envport-dev/envport/internal/domain"
	"github.com/envport-dev/envport/pkg/protocol"
	"os"
	"strings"
	"testing"
)

func TestV1GoldenCiphertext(t *testing.T) {
	base := "../../testdata/protocol/v1/"
	raw, e := os.ReadFile(base + "SYNTHETIC_IDENTITY.txt")
	if e != nil {
		t.Fatal(e)
	}
	identity, e := age.ParseX25519Identity(strings.TrimSpace(string(raw)))
	if e != nil {
		t.Fatal(e)
	}
	cipher, e := os.ReadFile(base + "manifest.age")
	if e != nil {
		t.Fatal(e)
	}
	plain, e := crypt.Decrypt(cipher, identity, domain.MaxObjectSize)
	if e != nil {
		t.Fatal(e)
	}
	expected, e := os.ReadFile(base + "manifest.json")
	if e != nil || !bytes.Equal(plain, expected) {
		t.Fatal("golden protocol changed")
	}
	var m protocol.Manifest
	if e = decode(plain, &m); e != nil {
		t.Fatal(e)
	}
	if e = m.Validate(domain.ID("11111111111111111111111111111111")); e != nil {
		t.Fatal(e)
	}
}
