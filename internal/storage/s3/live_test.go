package s3

import (
	"bytes"
	"context"
	"github.com/envport-dev/envport/internal/crypto"
	"github.com/envport-dev/envport/internal/domain"
	"github.com/envport-dev/envport/internal/storage"
	"io"
	"os"
	"testing"
	"time"
)

// This opt-in test never creates/deletes a bucket and writes only beneath its own random prefix.
func TestLiveS3Compatibility(t *testing.T) {
	bucket := os.Getenv("ENVPORT_LIVE_S3_BUCKET")
	if bucket == "" {
		t.Skip("dedicated live test bucket/credentials required")
	}
	region := os.Getenv("ENVPORT_LIVE_S3_REGION")
	if region == "" {
		region = "auto"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	st, e := Open(ctx, Config{Endpoint: os.Getenv("ENVPORT_LIVE_S3_ENDPOINT"), Bucket: bucket, Region: region, Prefix: "envport-live-tests/" + string(domain.NewID()), PathStyle: true})
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	if _, e = storage.Probe(ctx, st); e != nil {
		t.Fatal(e)
	}
	identity, e := crypto.NewIdentity()
	if e != nil {
		t.Fatal(e)
	}
	plain := []byte("FIXTURE=synthetic-live-test\r\n\x00\xff")
	sealed, e := crypto.Encrypt(plain, identity.Recipient())
	if e != nil {
		t.Fatal(e)
	}
	key := "encrypted-fixture/" + string(domain.NewID()) + ".age"
	defer st.Delete(ctx, key)
	if _, e = st.Put(ctx, key, bytes.NewReader(sealed), domain.Condition{Mode: domain.CreateIfAbsent}); e != nil {
		t.Fatal(e)
	}
	r, _, e := st.Get(ctx, key)
	if e != nil {
		t.Fatal(e)
	}
	got, e := io.ReadAll(io.LimitReader(r, domain.MaxObjectSize+1))
	r.Close()
	if e != nil || !bytes.Equal(got, sealed) {
		t.Fatal("live provider altered ciphertext")
	}
	decoded, e := crypto.Decrypt(got, identity, domain.MaxFileSize)
	if e != nil || !bytes.Equal(decoded, plain) {
		t.Fatal("live provider encrypted round trip failed")
	}
}
