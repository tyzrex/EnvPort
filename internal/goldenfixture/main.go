// Generates synthetic golden fixtures only. Run explicitly with go run ./internal/goldenfixture.
package main

import (
	"encoding/json"
	"github.com/envport-dev/envport/internal/crypto"
	"github.com/envport-dev/envport/internal/domain"
	"github.com/envport-dev/envport/pkg/protocol"
	"os"
	"time"
)

func main() {
	key, e := crypto.NewIdentity()
	if e != nil {
		panic(e)
	}
	m := protocol.Manifest{Version: 1, Vault: domain.ID("11111111111111111111111111111111"), ID: domain.ID("22222222222222222222222222222222"), Generation: 1, Author: domain.ID("33333333333333333333333333333333"), Created: time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC), Projects: []protocol.Project{{ID: domain.ID("44444444444444444444444444444444"), Identity: "example.test/fixtures/golden", Files: []protocol.File{{ID: domain.ID("55555555555555555555555555555555"), Path: ".env", Blob: domain.ID("66666666666666666666666666666666"), Digest: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", Size: 0}}}}}
	plain, e := json.Marshal(m)
	if e != nil {
		panic(e)
	}
	cipher, e := crypto.Encrypt(plain, key.Recipient())
	if e != nil {
		panic(e)
	}
	for p, b := range map[string][]byte{"testdata/protocol/v1/manifest.json": plain, "testdata/protocol/v1/manifest.age": cipher, "testdata/protocol/v1/SYNTHETIC_IDENTITY.txt": []byte(key.String() + "\n")} {
		if e = os.WriteFile(p, b, 0600); e != nil {
			panic(e)
		}
	}
}
