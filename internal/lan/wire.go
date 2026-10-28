package lan

import (
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/envport-dev/envport/internal/domain"
)

func pemCertificate(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func urlQuery(raw string) (url.Values, error) {
	if len(raw) > 8192 {
		return nil, errors.New("query too long")
	}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return nil, err
	}
	for _, v := range values {
		if len(v) != 1 {
			return nil, errors.New("duplicate query field")
		}
	}
	return values, nil
}

func (s *Server) list(w http.ResponseWriter, r *http.Request, base string, q url.Values) {
	for key := range q {
		if key != "prefix" && key != "cursor" && key != "limit" {
			respondError(w, 400, "invalid_query")
			return
		}
	}
	prefix, cursor := q.Get("prefix"), q.Get("cursor")
	if prefix != "" && domain.ValidateKey(strings.TrimSuffix(prefix, "/")) != nil {
		respondError(w, 400, "invalid_prefix")
		return
	}
	if cursor != "" && (!strings.HasPrefix(cursor, base) || domain.ValidateKey(cursor) != nil) {
		respondError(w, 400, "invalid_cursor")
		return
	}
	limit := 1000
	if value := q.Get("limit"); value != "" {
		n, err := strconv.Atoi(value)
		if err != nil || n < 1 || n > 1000 {
			respondError(w, 400, "invalid_limit")
			return
		}
		limit = n
	}
	page, err := s.store.List(r.Context(), base+prefix, cursor, limit)
	if err != nil {
		storageError(w, err)
		return
	}
	for i := range page.Objects {
		if !strings.HasPrefix(page.Objects[i].Key, base) {
			respondError(w, 503, "storage_unavailable")
			return
		}
		page.Objects[i].Key = strings.TrimPrefix(page.Objects[i].Key, base)
		page.Objects[i].ETag = strconv.Quote(page.Objects[i].ETag)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Version int `json:"version"`
		domain.Page
	}{Version, page})
}
