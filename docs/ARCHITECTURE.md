# Actual architecture

`cmd/envport` → `internal/transport/cli` → `internal/application` → domain contracts.

The application engine implements enrollment, recovery, snapshot repositories, planning, sync, restore and diagnostics. It receives an ObjectStore factory and a passphrase callback; it does not import Cobra or the AWS SDK. `internal/domain` defines identifiers, portable-path rules, size limits, typed errors and storage contracts. `pkg/protocol` defines versioned manifests. `internal/crypto` uses age; it implements no cryptographic primitives.

The filesystem adapter implements a logical object namespace in `objects.db`, using SQLite atomic conditional INSERT/UPDATE operations across processes. The object database contains ciphertext, opaque keys and ciphertext ETags. This avoids stale lockfiles and non-atomic read-then-write CAS. The S3 adapter implements the same namespace using AWS SDK v2 conditional PutObject. Provider tests must pass before an S3 profile is marked writable.

Device state is a separate private SQLite database with foreign keys, WAL and migration tracking. It is not the authoritative backup. State stores mappings, baselines, nonsecret provider options, trusted checkpoints and transaction journal entries. Encrypted vault keys live in separate age envelopes. Recovery bundles contain only version, vault ID and the private vault identity, encrypted under an independent recovery passphrase. `device.age` separately encrypts an installation X25519 identity and Ed25519 signing key. Pairing uses signed expiring requests, out-of-band fingerprints, encrypted grants and transactionally consumed pending requests. `internal/legacy` is a read-only reader of the audited starter format; migration always writes to a new independent age vault.

Restore uses Go's descriptor-backed os.Root, portable path validation, explicit symlink rejection, destination-local staging, fsync and hard-link no-replace installation. Explicit replacement retains a private copy of original bytes and revalidates target content/inode before rename. Native Windows ACL validation and comprehensive hostile local race validation are release blockers.

The built-in `internal/lan` host and `internal/storage/lan` adapter expose the same ObjectStore over mutually authenticated TLS. A separate host registry checks namespace/certificate grants on every request; ciphertext remains in native-local SQLite behind the server. TLS private identities are encrypted at rest, clients explicitly trust the host, and no vault keys or application-state database are needed on the host. Private-IP-only endpoints avoid DNS/proxy/relay/cloud dependencies. See LAN.md and protocol/lan-v1.md.

There is no hosted account/control-plane service or desktop adapter yet. No telemetry, third-party network calls or fallback storage are part of standalone operation. S3 credential providers may contact AWS identity services when explicitly selected by the SDK credential chain.
