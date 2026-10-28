package protocol

import (
	"github.com/envport-dev/envport/internal/domain"
	"testing"
	"time"
)

func validManifest() Manifest {
	return Manifest{Version: 1, Vault: domain.ID("11111111111111111111111111111111"), ID: domain.ID("22222222222222222222222222222222"), Generation: 1, Author: domain.ID("33333333333333333333333333333333"), Created: time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC), Projects: []Project{{ID: domain.ID("44444444444444444444444444444444"), Files: []File{{ID: domain.ID("55555555555555555555555555555555"), Path: ".env", Blob: domain.ID("66666666666666666666666666666666"), Digest: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", Size: 0}}}}}
}
func TestManifestValidation(t *testing.T) {
	m := validManifest()
	if e := m.Validate(m.Vault); e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*Manifest){func(m *Manifest) { m.Version = 999 }, func(m *Manifest) { m.Vault = domain.NewID() }, func(m *Manifest) { m.Features = []string{"unknown"} }, func(m *Manifest) { m.Generation = 0 }, func(m *Manifest) { m.Parents = []domain.ID{domain.NewID()} }, func(m *Manifest) { m.Projects[0].Files[0].Path = "../.env" }, func(m *Manifest) { m.Projects[0].Files[0].Size = domain.MaxFileSize + 1 }, func(m *Manifest) { m.Projects = append(m.Projects, m.Projects[0]) }, func(m *Manifest) {
		f := m.Projects[0].Files[0]
		f.ID = domain.NewID()
		f.Path = ".ENV"
		m.Projects[0].Files = append(m.Projects[0].Files, f)
	}} {
		m := validManifest()
		vault := m.Vault
		mutate(&m)
		if m.Validate(vault) == nil {
			t.Fatal("malicious manifest accepted")
		}
	}
}
