# Changelog

## Unreleased — 0.1.0-dev experimental

- Built-in LAN host/client adapter with pinned mutual TLS, encrypted transport identities, namespace-scoped authorization, read-only access, persistent revocation, bounded HTTP operations and a complete two-client no-cloud CLI smoke.

- Independent local/S3 vault engine with age-encrypted payloads, manifests and references.
- Private SQLite device state, atomic local CAS, S3 SDK v2 adapter and active concurrent capability probe.
- Portable recovery, signed expiring device requests and recipient-encrypted grants with fingerprint confirmation.
- Explicit-root discovery, Git/UUID mappings, deterministic three-way sync, immutable history and conservative restoration.
- Staged commit journal and authenticated-history reconciliation; explicit tombstones and disabled destructive garbage collection.
- Read-only migration of the supplied AES EVP1 starter into a separately verified age vault.
- CLI, synthetic/security/MinIO tests, protocol fixtures, smoke scripts, unsigned cross-build tooling, CI definitions and runbooks.

No tagged/public release, cloud deployment, desktop package, hosted service, actual macOS/Windows runtime verification or independent security review has been completed.
