// Package s3 adapts the AWS SDK v2 to the provider-neutral object-store contract.
package s3

import (
	"bytes"
	"context"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	sdk "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	"github.com/envport-dev/envport/internal/domain"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Config struct {
	Endpoint   string `json:"endpoint,omitempty"`
	Region     string `json:"region"`
	Bucket     string `json:"bucket"`
	Prefix     string `json:"prefix,omitempty"`
	PathStyle  bool   `json:"path_style"`
	AWSProfile string `json:"aws_profile,omitempty"`
	AllowHTTP  bool   `json:"allow_http,omitempty"`
	Verified   bool   `json:"conditional_writes_verified"`
}
type Store struct {
	client *sdk.Client
	config Config
}

func Open(ctx context.Context, c Config) (*Store, error) {
	if c.Bucket == "" || c.Region == "" || strings.ContainsAny(c.Bucket, "/\\\x00") {
		return nil, errors.New("S3 bucket and region are required")
	}
	c.Prefix = strings.Trim(c.Prefix, "/")
	if c.Prefix != "" && domain.ValidateKey(c.Prefix) != nil {
		return nil, domain.ErrUnsafePath
	}
	if c.Endpoint != "" {
		u, e := url.Parse(c.Endpoint)
		if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || (u.Scheme != "https" && !(u.Scheme == "http" && c.AllowHTTP)) {
			return nil, errors.New("S3 endpoint must use HTTPS; local tests require --allow-http")
		}
	}
	client := &http.Client{Timeout: 45 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return errors.New("storage redirects are disabled") }}
	opts := []func(*config.LoadOptions) error{config.WithRegion(c.Region), config.WithHTTPClient(client), config.WithRetryMaxAttempts(3)}
	if c.AWSProfile != "" {
		opts = append(opts, config.WithSharedConfigProfile(c.AWSProfile))
	}
	cfg, e := config.LoadDefaultConfig(ctx, opts...)
	if e != nil {
		return nil, errors.New("S3 credential configuration unavailable")
	}
	cfg.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
	cfg.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenRequired
	s := sdk.NewFromConfig(cfg, func(o *sdk.Options) {
		o.UsePathStyle = c.PathStyle
		if c.Endpoint != "" {
			o.BaseEndpoint = aws.String(c.Endpoint)
		}
	})
	return &Store{s, c}, nil
}
func (s *Store) Close() error { return nil }
func (s *Store) Capabilities() domain.Capabilities {
	return domain.Capabilities{ConditionalCreate: s.config.Verified, ConditionalReplace: s.config.Verified, Verified: s.config.Verified, MaxObjectSize: domain.MaxObjectSize}
}
func (s *Store) key(k string) (string, error) {
	if e := domain.ValidateKey(k); e != nil {
		return "", e
	}
	if s.config.Prefix != "" {
		return s.config.Prefix + "/" + k, nil
	}
	return k, nil
}
func failure(e error) error {
	if e == nil {
		return nil
	}
	if errors.Is(e, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(e, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	var api smithy.APIError
	if errors.As(e, &api) {
		switch api.ErrorCode() {
		case "NoSuchKey", "NotFound", "NoSuchBucket":
			return domain.ErrNotFound
		case "PreconditionFailed", "ConditionalRequestConflict":
			return domain.ErrPrecondition
		case "AccessDenied", "InvalidAccessKeyId", "SignatureDoesNotMatch", "ExpiredToken":
			return errors.New("S3 authorization failed; check credential source and scoped permissions")
		}
	}
	return errors.New("S3 operation failed; check endpoint, permissions and connectivity")
}
func (s *Store) Put(ctx context.Context, k string, r io.Reader, c domain.Condition) (domain.ObjectInfo, error) {
	key, e := s.key(k)
	if e != nil {
		return domain.ObjectInfo{}, e
	}
	if e = c.Validate(); e != nil {
		return domain.ObjectInfo{}, e
	}
	b, e := io.ReadAll(io.LimitReader(r, domain.MaxObjectSize+1))
	if e != nil || int64(len(b)) > domain.MaxObjectSize {
		return domain.ObjectInfo{}, errors.New("object read failed or size limit exceeded")
	}
	in := &sdk.PutObjectInput{Bucket: aws.String(s.config.Bucket), Key: aws.String(key), Body: bytes.NewReader(b), ContentLength: aws.Int64(int64(len(b)))}
	switch c.Mode {
	case domain.CreateIfAbsent:
		in.IfNoneMatch = aws.String("*")
	case domain.IfETagMatch:
		in.IfMatch = aws.String(c.ETag)
	}
	out, e := s.client.PutObject(ctx, in)
	if e != nil {
		return domain.ObjectInfo{}, failure(e)
	}
	if out.ETag == nil {
		return domain.ObjectInfo{}, errors.New("S3 provider omitted ETag")
	}
	return domain.ObjectInfo{Key: k, ETag: *out.ETag, Size: int64(len(b))}, nil
}
func (s *Store) Get(ctx context.Context, k string) (io.ReadCloser, domain.ObjectInfo, error) {
	key, e := s.key(k)
	if e != nil {
		return nil, domain.ObjectInfo{}, e
	}
	out, e := s.client.GetObject(ctx, &sdk.GetObjectInput{Bucket: aws.String(s.config.Bucket), Key: aws.String(key)})
	if e != nil {
		return nil, domain.ObjectInfo{}, failure(e)
	}
	if aws.ToInt64(out.ContentLength) > domain.MaxObjectSize {
		out.Body.Close()
		return nil, domain.ObjectInfo{}, errors.New("remote object exceeds size limit")
	}
	return out.Body, domain.ObjectInfo{Key: k, ETag: aws.ToString(out.ETag), Size: aws.ToInt64(out.ContentLength)}, nil
}
func (s *Store) Head(ctx context.Context, k string) (domain.ObjectInfo, error) {
	key, e := s.key(k)
	if e != nil {
		return domain.ObjectInfo{}, e
	}
	out, e := s.client.HeadObject(ctx, &sdk.HeadObjectInput{Bucket: aws.String(s.config.Bucket), Key: aws.String(key)})
	if e != nil {
		return domain.ObjectInfo{}, failure(e)
	}
	return domain.ObjectInfo{Key: k, ETag: aws.ToString(out.ETag), Size: aws.ToInt64(out.ContentLength)}, nil
}
func (s *Store) List(ctx context.Context, prefix, cursor string, limit int) (domain.Page, error) {
	if limit < 1 || limit > 1000 {
		limit = 1000
	}
	base := ""
	if s.config.Prefix != "" {
		base = s.config.Prefix + "/"
	}
	if prefix != "" && domain.ValidateKey(strings.TrimSuffix(prefix, "/")) != nil {
		return domain.Page{}, domain.ErrUnsafePath
	}
	in := &sdk.ListObjectsV2Input{Bucket: aws.String(s.config.Bucket), Prefix: aws.String(base + prefix), MaxKeys: aws.Int32(int32(limit))}
	if cursor != "" {
		in.ContinuationToken = aws.String(cursor)
	}
	out, e := s.client.ListObjectsV2(ctx, in)
	if e != nil {
		return domain.Page{}, failure(e)
	}
	p := domain.Page{Objects: []domain.ObjectInfo{}, Cursor: aws.ToString(out.NextContinuationToken)}
	for _, o := range out.Contents {
		key := aws.ToString(o.Key)
		if !strings.HasPrefix(key, base+prefix) {
			return domain.Page{}, domain.ErrCorrupt
		}
		p.Objects = append(p.Objects, domain.ObjectInfo{Key: strings.TrimPrefix(key, base), ETag: aws.ToString(o.ETag), Size: aws.ToInt64(o.Size)})
	}
	return p, nil
}
func (s *Store) Delete(ctx context.Context, k string) error {
	key, e := s.key(k)
	if e != nil {
		return e
	}
	_, e = s.client.DeleteObject(ctx, &sdk.DeleteObjectInput{Bucket: aws.String(s.config.Bucket), Key: aws.String(key)})
	return failure(e)
}
