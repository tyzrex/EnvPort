package storage

import (
	"bytes"
	"context"
	"errors"
	"github.com/envport-dev/envport/internal/domain"
	"io"
	"sync"
)

// Probe writes only random synthetic data beneath a dedicated, random namespace.
// It tests sequential conditions and an actual two-writer race before enabling sync.
func Probe(ctx context.Context, s domain.ObjectStore) (domain.Capabilities, error) {
	prefix := "capability-tests/" + string(domain.NewID())
	key := prefix + "/object"
	defer s.Delete(ctx, key)
	first, e := s.Put(ctx, key, bytes.NewReader([]byte("synthetic-one")), domain.Condition{Mode: domain.CreateIfAbsent})
	if e != nil {
		return domain.Capabilities{}, e
	}
	if _, e = s.Put(ctx, key, bytes.NewReader([]byte("must-not-overwrite")), domain.Condition{Mode: domain.CreateIfAbsent}); !errors.Is(e, domain.ErrPrecondition) {
		return domain.Capabilities{}, errors.New("provider does not enforce conditional creation")
	}
	if _, e = s.Put(ctx, key, bytes.NewReader([]byte("must-not-overwrite")), domain.Condition{Mode: domain.IfETagMatch, ETag: "\"invalid-etag\""}); !errors.Is(e, domain.ErrPrecondition) {
		return domain.Capabilities{}, errors.New("provider does not enforce conditional replacement")
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, v := range []string{"synthetic-two", "synthetic-three"} {
		wg.Add(1)
		go func(v string) {
			defer wg.Done()
			_, e := s.Put(ctx, key, bytes.NewReader([]byte(v)), domain.Condition{Mode: domain.IfETagMatch, ETag: first.ETag})
			results <- e
		}(v)
	}
	wg.Wait()
	close(results)
	wins, losses := 0, 0
	for e := range results {
		if e == nil {
			wins++
		} else if errors.Is(e, domain.ErrPrecondition) {
			losses++
		} else {
			return domain.Capabilities{}, e
		}
	}
	if wins != 1 || losses != 1 {
		return domain.Capabilities{}, errors.New("provider failed concurrent CAS safety check")
	}
	r, info, e := s.Get(ctx, key)
	if e != nil {
		return domain.Capabilities{}, e
	}
	b, e := io.ReadAll(io.LimitReader(r, 1024))
	r.Close()
	if e != nil || (string(b) != "synthetic-two" && string(b) != "synthetic-three") || info.ETag == "" {
		return domain.Capabilities{}, errors.New("provider object verification failed")
	}
	h, e := s.Head(ctx, key)
	if e != nil || h.ETag != info.ETag {
		return domain.Capabilities{}, errors.New("provider HEAD verification failed")
	}
	p, e := s.List(ctx, prefix, "", 1)
	if e != nil || len(p.Objects) != 1 || p.Objects[0].Key != key {
		return domain.Capabilities{}, errors.New("provider LIST verification failed")
	}
	if e = s.Delete(ctx, key); e != nil {
		return domain.Capabilities{}, e
	}
	if _, e = s.Head(ctx, key); !errors.Is(e, domain.ErrNotFound) {
		return domain.Capabilities{}, errors.New("provider DELETE verification failed")
	}
	return domain.Capabilities{ConditionalCreate: true, ConditionalReplace: true, Verified: true, MaxObjectSize: domain.MaxObjectSize}, nil
}
