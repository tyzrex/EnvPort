package application

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	sdk "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/envport-dev/envport/internal/domain"
	"github.com/envport-dev/envport/internal/persistence"
	"github.com/envport-dev/envport/internal/storage"
	adapter "github.com/envport-dev/envport/internal/storage/s3"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMinIOEncryptedRecoveryRoundTrip(t *testing.T) {
	endpoint := os.Getenv("ENVPORT_TEST_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("set ENVPORT_TEST_S3_ENDPOINT to test encrypted recovery on MinIO")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	bucket := "envport-test-" + string(domain.NewID())
	cfg, e := config.LoadDefaultConfig(ctx, config.WithRegion("us-east-1"))
	if e != nil {
		t.Fatal("fixture credentials unavailable")
	}
	client := sdk.NewFromConfig(cfg, func(o *sdk.Options) { o.BaseEndpoint = aws.String(endpoint); o.UsePathStyle = true })
	if _, e = client.CreateBucket(ctx, &sdk.CreateBucketInput{Bucket: aws.String(bucket)}); e != nil {
		t.Fatal("create isolated integration bucket failed")
	}
	config := adapter.Config{Endpoint: endpoint, Region: "us-east-1", Bucket: bucket, PathStyle: true, AllowHTTP: true}
	st, e := adapter.Open(ctx, config)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		for {
			p, e := st.List(cleanup, "", "", 1000)
			if e != nil || len(p.Objects) == 0 {
				break
			}
			for _, o := range p.Objects {
				_ = st.Delete(cleanup, o.Key)
			}
		}
		_, _ = client.DeleteBucket(cleanup, &sdk.DeleteBucketInput{Bucket: aws.String(bucket)})
	})
	if _, e = storage.Probe(ctx, st); e != nil {
		t.Fatal(e)
	}
	config.Verified = true
	makeService := func() *Service {
		db, e := persistence.Open(filepath.Join(t.TempDir(), "state"))
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { db.Close() })
		s := New(db, func(ctx context.Context, p Profile) (domain.ObjectStore, error) {
			var c adapter.Config
			if e := json.Unmarshal(p.Options, &c); e != nil {
				return nil, e
			}
			return adapter.Open(ctx, c)
		}, func(kind string) (string, error) {
			if kind == "recovery" {
				return "synthetic-s3-independent-recovery", nil
			}
			return "synthetic-s3-device-unlock", nil
		})
		options, _ := json.Marshal(config)
		if e = s.AddProfile(ctx, Profile{Name: "minio", Driver: "s3", Options: options}); e != nil {
			t.Fatal(e)
		}
		return s
	}
	a, b := makeService(), makeService()
	v, e := a.CreateVault(ctx, "personal", "minio")
	if e != nil {
		t.Fatal(e)
	}
	bundle := filepath.Join(t.TempDir(), "recovery.age")
	if e = a.ExportRecovery(ctx, v, bundle); e != nil {
		t.Fatal(e)
	}
	root := t.TempDir()
	plain := []byte("# synthetic S3 fixture\r\nKEY=fixture-only-value\n\x00\xff")
	write(t, root, "apps/web/.env.local", plain)
	if _, e = a.Track(ctx, v, root, true); e != nil {
		t.Fatal(e)
	}
	out := execute(t, a, v, false, false)
	if out.Uploaded != 1 {
		t.Fatal("S3 backup not committed")
	}
	joined, e := b.Join(ctx, "personal", "minio", bundle)
	if e != nil {
		t.Fatal(e)
	}
	history, e := b.History(ctx, joined)
	if e != nil || len(history) != 1 {
		t.Fatal("S3 history inaccessible")
	}
	target := t.TempDir()
	if e = b.MapProject(ctx, joined, history[0].Projects[0].ID, target); e != nil {
		t.Fatal(e)
	}
	plan, e := b.PlanRestore(ctx, joined, "")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = b.ExecuteRestore(ctx, joined, plan, false); e != nil {
		t.Fatal(e)
	}
	got, e := os.ReadFile(filepath.Join(target, "apps/web/.env.local"))
	if e != nil || !bytes.Equal(got, plain) {
		t.Fatal("S3 recovery changed bytes")
	}
	// Inspect every actual S3 object: neither secret values nor paths may be visible.
	page, e := st.List(ctx, "", "", 1000)
	if e != nil {
		t.Fatal(e)
	}
	for _, o := range page.Objects {
		data, _, e := readObject(ctx, st, o.Key)
		if e != nil {
			t.Fatal(e)
		}
		if bytes.Contains(data, []byte("fixture-only-value")) || bytes.Contains(data, []byte("apps/web/.env.local")) {
			t.Fatal("plaintext leaked into S3 object")
		}
		if bytes.Contains([]byte(o.Key), []byte(".env")) {
			t.Fatal("path leaked in S3 key")
		}
	}
}
