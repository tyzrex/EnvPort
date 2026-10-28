package application

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/envport-dev/envport/internal/discovery"
	"github.com/envport-dev/envport/internal/domain"
	"github.com/envport-dev/envport/internal/legacy"
	"github.com/envport-dev/envport/pkg/protocol"
	"sort"
	"time"
)

type MigrationReceipt struct {
	Version                int       `json:"version"`
	LegacySnapshot         domain.ID `json:"legacy_snapshot"`
	LegacyCiphertextSHA256 string    `json:"legacy_ciphertext_sha256"`
	Vault                  domain.ID `json:"new_vault_id,omitempty"`
	Snapshot               domain.ID `json:"new_snapshot_id,omitempty"`
	Files                  int       `json:"files"`
	Verified               bool      `json:"verified"`
	SourcePreserved        bool      `json:"source_preserved"`
}

// MigrateLegacy authenticates the entire source, creates a separate vault, verifies every uploaded blob,
// then atomically publishes the new head. Original AES ciphertext and keys remain untouched.
func (s *Service) MigrateLegacy(ctx context.Context, name, profile, source string, snapshot domain.ID, recoveryOutput, receiptOutput string, dry bool) (MigrationReceipt, error) {
	out := MigrationReceipt{Version: 1, LegacySnapshot: snapshot, SourcePreserved: true}
	old, e := legacy.Open(source)
	if e != nil {
		return out, e
	}
	defer old.Close()
	manifest, sourceHash, e := old.Load(ctx, snapshot)
	if e != nil {
		return out, e
	}
	out.LegacyCiphertextSHA256 = sourceHash
	out.Files = len(manifest.Files)
	for _, f := range manifest.Files {
		if _, e = old.Read(ctx, f); e != nil {
			return out, e
		}
	}
	if dry {
		return out, nil
	}
	if recoveryOutput == "" || receiptOutput == "" {
		return out, errors.New("migration requires new --recovery-output and --receipt files")
	}
	v, e := s.CreateVault(ctx, name, profile)
	if e != nil {
		return out, e
	}
	out.Vault = v.ID
	if e = s.ExportRecovery(ctx, v, recoveryOutput); e != nil {
		return out, e
	}
	st, e := s.OpenStore(ctx, v)
	if e != nil {
		return out, e
	}
	defer st.Close()
	caps := st.Capabilities()
	if !caps.Verified || !caps.ConditionalCreate || !caps.ConditionalReplace {
		return out, errors.New("verify destination storage capabilities before migration")
	}
	device, e := s.Device(ctx)
	if e != nil {
		return out, e
	}
	m := protocol.Manifest{Version: 1, Vault: v.ID, ID: domain.NewID(), Generation: 1, Author: device, Created: time.Now().UTC(), Projects: []protocol.Project{}}
	projects := map[string]int{}
	op := domain.NewID()
	if _, e = s.DB.ExecContext(ctx, "INSERT INTO operations(id,vault_id,snapshot_id,expected_head,state) VALUES(?,?,?,'','staged')", op, v.ID, m.ID); e != nil {
		return out, e
	}
	for _, entry := range manifest.Files {
		pi, ok := projects[entry.Project]
		if !ok {
			identity := ""
			if entry.Repository != "" {
				identity, e = discovery.CanonicalRemote("https://" + entry.Repository)
				if e != nil {
					return out, errors.New("legacy repository identity requires manual export and mapping")
				}
			}
			pi = len(m.Projects)
			projects[entry.Project] = pi
			m.Projects = append(m.Projects, protocol.Project{ID: domain.NewID(), Identity: identity, Files: []protocol.File{}})
		}
		plain, e := old.Read(ctx, entry)
		if e != nil {
			return out, e
		}
		f := protocol.File{ID: domain.NewID(), Path: entry.Relative, Blob: domain.NewID(), Digest: digest(plain), Size: int64(len(plain))}
		if _, e = s.putEncrypted(ctx, v, st, "blobs/"+string(f.Blob)+".age", plain, domain.Condition{Mode: domain.CreateIfAbsent}); e != nil {
			return out, e
		}
		if _, e = s.readBlob(ctx, v, st, f); e != nil {
			return out, e
		}
		m.Projects[pi].Files = append(m.Projects[pi].Files, f)
	}
	sort.Slice(m.Projects, func(i, j int) bool { return m.Projects[i].ID < m.Projects[j].ID })
	for i := range m.Projects {
		sort.Slice(m.Projects[i].Files, func(a, b int) bool { return m.Projects[i].Files[a].Path < m.Projects[i].Files[b].Path })
	}
	if e = m.Validate(v.ID); e != nil {
		return out, e
	}
	plain, _ := json.Marshal(m)
	if _, e = s.putEncrypted(ctx, v, st, "snapshots/"+string(m.ID)+".age", plain, domain.Condition{Mode: domain.CreateIfAbsent}); e != nil {
		return out, e
	}
	if _, e = s.readManifest(ctx, v, st, m.ID); e != nil {
		return out, e
	}
	ref, _ := json.Marshal(protocol.Ref{Version: 1, Vault: v.ID, Snapshot: m.ID, Generation: 1})
	if _, e = s.putEncrypted(ctx, v, st, "refs/main", ref, domain.Condition{Mode: domain.CreateIfAbsent}); e != nil {
		return out, e
	}
	if e = s.record(ctx, v, m, nil, op); e != nil {
		return out, e
	}
	out.Snapshot = m.ID
	out.Verified = true
	b, _ := json.MarshalIndent(out, "", "  ")
	if e = writeArtifact(receiptOutput, b); e != nil {
		return out, errors.New("migration committed and verified, but receipt could not be written; originals remain safe")
	}
	return out, nil
}
