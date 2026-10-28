# Built-in LAN storage vertical slice

## Baseline

The engine had local SQLite and generic S3 ObjectStore adapters, recovery and device pairing. No built-in LAN listener/client existed. Baseline `go test ./...` passed before modification.

## Implementation

- `internal/lan`: explicit host initialization, encrypted TLS identity, bounded mutual-TLS server, SQLite namespace grants, signed public enrollment documents, read-only grants and persisted transport revocation.
- `internal/storage/lan`: ObjectStore adapter with exact server trust, private-IP endpoint policy, no DNS/proxy/redirect/cloud chain, typed errors and real conditional writes.
- CLI: `init --lan`, `storage lan request`, `storage add lan`, `storage test`, `serve init/inspect/authorize/namespace create/namespaces/clients/revoke`, plus server startup/shutdown.
- Existing application services and encrypted vault v1 are reused unchanged apart from accepting the additional driver.
- `scripts/smoke_lan.py` runs actual CLI clients/server and is part of CI through `make smoke-lan`.

## Evidence

Adapter tests passed: object round trips, zero/binary/large bodies, stale conditions, two-writer CAS, pagination, authorization, foreign namespaces/cursors, read-only denial, next-request revocation on established connections, wrong server/client identities, modified enrollment documents, private encrypted credentials, malformed/oversized HTTP requests and missing client certificates.

The initial complete CLI LAN smoke passed encrypted recovery/restore byte equality, no-overwrite/preimages, offline edits, restart persistence, transport revocation and operation with unusable proxy settings. The final smoke additionally raced two complete client backups and passed. Full `go test -race ./...`, staticcheck, govulncheck and the original MinIO regression suite passed. All five unsigned cross-platform targets rebuilt. See docs/VALIDATION.md for recorded evidence and the platform limitations.

## Limits / handoff

Only isolated Linux localhost integration has been executed, not a physical NAS/macOS/Windows hardware matrix. No automatic discovery, internet relays, renewal, quotas, background service installer or remote enrollment endpoint is shipped. Enrollment requires explicit public-file transfer and fingerprint comparison. Host/TLS storage authorization never grants vault decryption. No cloud infrastructure or persistent user-network server was configured during implementation.
