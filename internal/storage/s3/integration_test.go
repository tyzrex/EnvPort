package s3

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	sdk "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/envport-dev/envport/internal/domain"
	"github.com/envport-dev/envport/internal/storage"
	"io"
	"os"
	"testing"
	"time"
)

// Explicit opt-in only. Creates its own random bucket and cleans only that bucket.
func TestMinIOIntegration(t *testing.T) {
	endpoint := os.Getenv("ENVPORT_TEST_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("set ENVPORT_TEST_S3_ENDPOINT for an isolated MinIO test service")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	bucket := "envport-test-" + string(domain.NewID())
	st, e := Open(ctx, Config{Endpoint: endpoint, Region: "us-east-1", Bucket: bucket, Prefix: "synthetic-tests", PathStyle: true, AllowHTTP: true})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = st.client.CreateBucket(ctx, &sdk.CreateBucketInput{Bucket: aws.String(bucket)}); e != nil {
		t.Fatal("create isolated test bucket failed")
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cursor := ""
		for {
			p, e := st.List(cleanup, "", cursor, 1000)
			if e != nil {
				break
			}
			for _, o := range p.Objects {
				_ = st.Delete(cleanup, o.Key)
			}
			if p.Cursor == "" {
				break
			}
			cursor = p.Cursor
		}
		_, _ = st.client.DeleteBucket(cleanup, &sdk.DeleteBucketInput{Bucket: aws.String(bucket)})
	})
	caps, e := storage.Probe(ctx, st)
	if e != nil || !caps.Verified {
		t.Fatalf("conditional-write probe failed: %v", e)
	}
	for _, n := range []int{0, 1, 1024, 2 << 20} {
		key := fmt.Sprintf("round-trip/%d", n)
		body := bytes.Repeat([]byte{0x5a}, n)
		info, e := st.Put(ctx, key, bytes.NewReader(body), domain.Condition{Mode: domain.CreateIfAbsent})
		if e != nil || info.ETag == "" {
			t.Fatalf("upload: %v", e)
		}
		r, _, e := st.Get(ctx, key)
		if e != nil {
			t.Fatal(e)
		}
		got, e := io.ReadAll(r)
		r.Close()
		if e != nil || !bytes.Equal(got, body) {
			t.Fatal("round trip failed")
		}
	}
	cursor := ""
	count := 0
	for {
		p, e := st.List(ctx, "round-trip/", cursor, 2)
		if e != nil {
			t.Fatal(e)
		}
		count += len(p.Objects)
		if p.Cursor == "" {
			break
		}
		if p.Cursor == cursor {
			t.Fatal("pagination did not advance")
		}
		cursor = p.Cursor
	}
	if count != 4 {
		t.Fatal("pagination lost objects")
	}
	canceled, stop := context.WithCancel(ctx)
	stop()
	if _, e = st.Put(canceled, "canceled", bytes.NewReader(nil), domain.Condition{}); !errors.Is(e, context.Canceled) {
		t.Fatal("cancellation was not propagated")
	}
	if _, e = st.Head(ctx, "missing"); !errors.Is(e, domain.ErrNotFound) {
		t.Fatal("404 not mapped")
	}
}
