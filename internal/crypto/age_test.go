package crypto

import (
	"bytes"
	"github.com/envport-dev/envport/internal/domain"
	"testing"
)

func TestAuthenticatedRoundTrip(t *testing.T) {
	a, _ := NewIdentity()
	b, _ := NewIdentity()
	plain := []byte("SYNTHETIC=fixture-only\r\n\x00\xff")
	cipher, e := Encrypt(plain, a.Recipient())
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(cipher, []byte("fixture-only")) {
		t.Fatal("plaintext leaked")
	}
	out, e := Decrypt(cipher, a, domain.MaxFileSize)
	if e != nil || !bytes.Equal(out, plain) {
		t.Fatal("round trip failed")
	}
	if _, e = Decrypt(cipher, b, domain.MaxFileSize); e == nil {
		t.Fatal("wrong key accepted")
	}
	cipher[len(cipher)-1] ^= 1
	if _, e = Decrypt(cipher, a, domain.MaxFileSize); e == nil {
		t.Fatal("tampering accepted")
	}
	if _, e = Decrypt(cipher[:len(cipher)/2], a, domain.MaxFileSize); e == nil {
		t.Fatal("truncation accepted")
	}
}
func TestRecovery(t *testing.T) {
	cipher, e := Seal([]byte("synthetic-key-envelope"), "independent-fixture-passphrase")
	if e != nil {
		t.Fatal(e)
	}
	out, e := Open(cipher, "independent-fixture-passphrase")
	if e != nil || string(out) != "synthetic-key-envelope" {
		t.Fatal("recovery failed")
	}
	if _, e = Open(cipher, "incorrect-fixture-passphrase"); e == nil {
		t.Fatal("wrong passphrase accepted")
	}
	if _, e = Seal(nil, "short"); e == nil {
		t.Fatal("weak passphrase accepted")
	}
}
