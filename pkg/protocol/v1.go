// Package protocol defines the versioned wire format. All manifest fields are encrypted.
package protocol

import (
	"encoding/hex"
	"errors"
	"github.com/envport-dev/envport/internal/domain"
	"strings"
	"time"
)

const Version = 1

type File struct {
	ID      domain.ID `json:"file_id"`
	Path    string    `json:"relative_path"`
	Blob    domain.ID `json:"blob_id"`
	Digest  string    `json:"content_sha256"`
	Size    int64     `json:"plaintext_length"`
	Deleted bool      `json:"deleted,omitempty"`
}
type Project struct {
	ID       domain.ID `json:"project_id"`
	Identity string    `json:"canonical_remote,omitempty"`
	Files    []File    `json:"files"`
}
type Manifest struct {
	Version    int         `json:"schema_version"`
	Vault      domain.ID   `json:"vault_id"`
	ID         domain.ID   `json:"snapshot_id"`
	Parents    []domain.ID `json:"parent_snapshot_ids"`
	Generation int64       `json:"generation"`
	Author     domain.ID   `json:"author_device_id"`
	Created    time.Time   `json:"created_at"`
	Projects   []Project   `json:"projects"`
	Features   []string    `json:"required_features,omitempty"`
}
type Ref struct {
	Version    int       `json:"schema_version"`
	Vault      domain.ID `json:"vault_id"`
	Snapshot   domain.ID `json:"snapshot_id"`
	Generation int64     `json:"generation"`
}

func (m Manifest) Validate(vault domain.ID) error {
	if m.Version != Version || m.Vault != vault || !vault.Valid() || !m.ID.Valid() || !m.Author.Valid() || m.Generation < 1 || m.Created.IsZero() || len(m.Features) > 0 || len(m.Parents) > 1 || (m.Generation == 1) != (len(m.Parents) == 0) {
		return domain.ErrCorrupt
	}
	for _, p := range m.Parents {
		if !p.Valid() || p == m.ID {
			return domain.ErrCorrupt
		}
	}
	projects := map[domain.ID]bool{}
	files := map[domain.ID]bool{}
	count := 0
	for _, p := range m.Projects {
		if !p.ID.Valid() || projects[p.ID] || len(p.Identity) > 2048 {
			return domain.ErrCorrupt
		}
		projects[p.ID] = true
		paths := map[string]bool{}
		for _, f := range p.Files {
			count++
			folded := strings.ToLower(f.Path)
			if !f.ID.Valid() || files[f.ID] || paths[folded] || domain.ValidateTrackedPath(f.Path) != nil || f.Size < 0 || f.Size > domain.MaxFileSize {
				return domain.ErrCorrupt
			}
			files[f.ID] = true
			paths[folded] = true
			if !f.Deleted {
				d, e := hex.DecodeString(f.Digest)
				if e != nil || len(d) != 32 || !f.Blob.Valid() {
					return domain.ErrCorrupt
				}
			}
		}
	}
	if count > domain.MaxManifestFiles {
		return errors.New("manifest file limit exceeded")
	}
	return nil
}
