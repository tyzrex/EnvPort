package application

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAuthenticatedPairingAndReplay(t *testing.T) {
	ctx := context.Background()
	objects := filepath.Join(t.TempDir(), "objects")
	a := testService(t, objects)
	v := createVault(t, a)
	source := t.TempDir()
	write(t, source, ".env", []byte("FIXTURE=synthetic-pairing\n"))
	if _, e := a.Track(ctx, v, source, true); e != nil {
		t.Fatal(e)
	}
	execute(t, a, v, false, false)
	b := testService(t, objects)
	request := filepath.Join(t.TempDir(), "request.json")
	info, e := b.RequestDevice(ctx, v.ID, request)
	if e != nil {
		t.Fatal(e)
	}
	grant := filepath.Join(t.TempDir(), "grant.age")
	if _, e = a.ApproveDevice(ctx, v, request, grant, "wrong-fingerprint"); e == nil {
		t.Fatal("unconfirmed fingerprint accepted")
	}
	approval, e := a.ApproveDevice(ctx, v, request, grant, info.RequestFingerprint)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.ApproveDevice(ctx, v, request, filepath.Join(t.TempDir(), "replay.age"), info.RequestFingerprint); e == nil {
		t.Fatal("duplicate approval accepted")
	}
	if _, e = b.JoinDevice(ctx, "personal", "shared", grant, "wrong-issuer"); e == nil {
		t.Fatal("untrusted issuer accepted")
	}
	joined, e := b.JoinDevice(ctx, "personal", "shared", grant, approval.IssuerFingerprint)
	if e != nil {
		t.Fatal(e)
	}
	if joined.ID != v.ID {
		t.Fatal("wrong vault joined")
	}
	history, e := b.History(ctx, joined)
	if e != nil || len(history) != 1 {
		t.Fatal("paired device cannot decrypt")
	}
	if _, e = b.JoinDevice(ctx, "replay", "shared", grant, approval.IssuerFingerprint); e == nil {
		t.Fatal("grant replay accepted")
	}
	outsider := testService(t, objects)
	if _, e = outsider.JoinDevice(ctx, "outsider", "shared", grant, approval.IssuerFingerprint); e == nil {
		t.Fatal("different device decrypted grant")
	}
	raw, _ := os.ReadFile(grant)
	if string(raw) == "" {
		t.Fatal("missing grant")
	}
}
func TestExpiredAndTamperedPairingRequest(t *testing.T) {
	ctx := context.Background()
	objects := filepath.Join(t.TempDir(), "objects")
	a := testService(t, objects)
	v := createVault(t, a)
	b := testService(t, objects)
	request := filepath.Join(t.TempDir(), "request.json")
	info, e := b.RequestDevice(ctx, v.ID, request)
	if e != nil {
		t.Fatal(e)
	}
	data, _ := os.ReadFile(request)
	var r JoinRequest
	json.Unmarshal(data, &r)
	r.Expires = time.Now().Add(-time.Minute)
	d, e := b.loadDevice(ctx)
	if e != nil {
		t.Fatal(e)
	}
	r.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(signing(d), requestBytes(r)))
	expired, _ := json.Marshal(r)
	os.WriteFile(request, expired, 0600)
	if _, e = a.ApproveDevice(ctx, v, request, filepath.Join(t.TempDir(), "expired.age"), requestFingerprint(r)); e == nil {
		t.Fatal("expired request accepted")
	}
	r.Expires = time.Now().Add(time.Minute)
	tampered, _ := json.Marshal(r)
	os.WriteFile(request, tampered, 0600)
	if _, e = a.ApproveDevice(ctx, v, request, filepath.Join(t.TempDir(), "tampered.age"), info.RequestFingerprint); e == nil {
		t.Fatal("tampered request accepted")
	}
}
