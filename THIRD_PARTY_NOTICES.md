# Third-party components

The project retains the supplied starter's MIT license and module identity. `internal/legacy` implements its documented AES reader with additional bounds/path/checksum validation. Original starter documentation and encrypted synthetic compatibility fixtures retain attribution.

Runtime dependencies are pinned in go.mod/go.sum. Direct packages include filippo.io/age (BSD-3-Clause), AWS SDK for Go v2 and Smithy (Apache-2.0), Cobra (Apache-2.0), modernc.org/sqlite (BSD-3-Clause; bundled SQLite is public domain), and Go x/sys/x/term (BSD-3-Clause). Review the exact module license files and transitive notices when distributing; this summary is not a substitute for the original license texts.

The MinIO server is AGPL-3.0 external **test tooling**, built and run separately. It is not linked into EnvPort, bundled in CLI archives or deployed by the product. Staticcheck and govulncheck are separately installed development tools. Test identities/ciphertexts are synthetic and intentionally public. No personal key material belongs in the repository.

The local release script produces a CycloneDX dependency inventory and per-binary Go build information. Before a public release, audit that inventory and bundle the full applicable transitive license notices. This final distribution/compliance audit remains a release gate; no legal certification is asserted.
