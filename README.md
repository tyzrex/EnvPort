# EnvPort

Encrypted, Git-aware backups for your existing `.env` files. Keep exact file bytes, recover on another installation with a different checkout layout, and review conflicting edits before synchronizing. Use a local encrypted directory, the built-in LAN vault host, or your own S3-compatible bucket. Standalone modes need no EnvPort-hosted account/service and include no telemetry or hidden fallback storage.

**Experimental CLI.** Linux runtime tests and MinIO integration pass. Live R2/AWS, macOS/Windows runtime security, independent security review, desktop and hosted accounts are not complete. Do not use this as your only backup. [Verified implementation status](docs/IMPLEMENTATION_STATUS.md) lists the remaining release gates.

## Build

Requires Go 1.26+ and Git. Linux file reading requires kernel 5.6+ (`openat2`); the tested toolchain is Go 1.27.3. Windows restrictive ACL support is not implemented; cross-compiled binaries are experimental build artifacts, not a support claim.

```bash
go mod download
make check
make build
./bin/envport --help
```

Install locally with `go install ./cmd/envport`. No published GitHub repository or release is assumed. The module identity is inherited from the supplied starter.

## Try it offline

Run against a project you explicitly choose. `scan` is read-only; `track` enrolls files. Passphrases are requested with hidden terminal input; use independent strong unlock and recovery passphrases. The recovery destination directory must already exist.

```bash
./bin/envport init --offline
./bin/envport vault create personal --storage local
./bin/envport keys export --output /secure/off-device/personal-recovery.age
./bin/envport keys verify /secure/off-device/personal-recovery.age
./bin/envport scan /your/Projects
./bin/envport track /your/Projects/my-repository
./bin/envport backup --dry-run
./bin/envport backup
./bin/envport history
./bin/envport doctor
```

For a repository without a remote, use `track /your/project --local` and map its project UUID explicitly on the new installation. Recovery bundles include vault keys; store the bundle and its passphrase independently of the source machine. Losing both the local decryption key and usable recovery/device grants makes the backup unrecoverable.

## Use only your local network

The built-in host needs no S3 service or cloud account. On your NAS/host, choose a real private IP:

```bash
./bin/envport serve init --data ~/.local/state/envport-lan \
  --endpoint https://192.168.1.10:7443
./bin/envport serve --data ~/.local/state/envport-lan --listen 192.168.1.10:7443
```

On each client, `init --lan`, create `storage lan request`, have the host explicitly authorize its confirmed fingerprint, then import the signed connection with `storage add lan` and run `storage test`. Vault recovery/device authorization is separate from this storage authorization. The host receives encrypted objects and has no vault decryption keys.

Follow the complete [LAN setup guide](docs/LAN.md) for exact enrollment, backup, restore, namespaces and revocation commands. The host must be online during transfers; clients can edit offline and resolve conflicts when they reconnect. `--no-network` disables LAN too. The real two-client fixture is `make smoke-lan`.

## Bring your own S3 storage

Configure credentials through the AWS SDK credential chain (environment, AWS credential profiles, or a supported SDK identity provider). Credentials are never CLI arguments or database configuration values. The SDK may contact its configured credential providers; standalone EnvPort never contacts an EnvPort service.

```bash
./bin/envport init --byos
./bin/envport storage add s3 --name personal-r2 \
  --endpoint https://ACCOUNT_ID.r2.cloudflarestorage.com \
  --region auto --bucket YOUR_PRIVATE_BUCKET --prefix envport --path-style
./bin/envport storage test personal-r2
./bin/envport vault create personal --storage personal-r2
./bin/envport keys export --output /secure/off-device/personal-recovery.age
./bin/envport track /your/Projects/my-repository
./bin/envport backup --dry-run
./bin/envport backup
```

`storage test` creates and removes synthetic data under its own random test prefix and verifies conditional creation, stale ETag rejection, and a two-writer CAS race. S3 writes remain disabled until the test passes. [Provider setup and limits](docs/STORAGE_PROVIDERS.md).

## Restore on another installation

Install the CLI, configure storage access separately, and clone the repository yourself. Recovery login does not grant bucket access. For local storage, copy the encrypted object directory to the new installation while writers are stopped, or point both installations at the same private directory.

```bash
./bin/envport init
# Add the same S3 profile, or a filesystem profile pointing to the encrypted objects.
./bin/envport vault join personal --storage personal-r2 \
  --recovery /secure/personal-recovery.age
./bin/envport restore --scan /different/Code --dry-run
./bin/envport restore
./bin/envport status
./bin/envport sync --dry-run
./bin/envport sync
```

Different directories are matched through canonical Git identity, never folder names alone. Ambiguous clones require `project map <project-id> <checkout>`; UUID-only projects always require explicit mapping. Existing files are preserved by default. Explicit `sync --accept-remote` or `restore --accept-remote` retains private `.envport-preimage-*` siblings and checks the observed original before replacement. Stop concurrent local writers before using replacement; review the [filesystem threat limits](docs/threat-model.md).

Both devices modifying the same file produces a conflict (exit 3). `resolve <file-id> --keep-local`, followed by a new sync, explicitly commits local bytes while preserving remote history. A missing local file never deletes remote data. `file remove <file-id> --confirm` stages a remote tombstone, leaving local bytes untouched. Garbage collection is disabled; `prune --dry-run` only previews orphans.

Existing-device pairing is also available: [signed requests, fingerprint confirmation and encrypted grants](docs/DEVICE_PAIRING.md). Copied vault keys cannot be revoked retroactively; rotation and revocation are not implemented.

## Starter compatibility

The supplied AES prototype was audited and its tests/restore reproduced. `migrate-legacy` authenticates a specific original snapshot, imports it into a **new** age vault, verifies all uploaded blobs, atomically publishes the new head and writes a receipt. It never modifies the original key/snapshots. [Migration procedure and rollback](docs/MIGRATION.md). `history` has a `snapshots` alias; other CLI/config changes are documented rather than silently reading old state as v1.

## Development and evidence

```bash
make check                 # formatting, vet, unit/integration tests (external tests skip)
make test-race
make smoke                 # actual offline CLI processes, isolated fixture device homes
make smoke-lan             # built-in TLS host, concurrent clients, restart and revocation
make test-minio             # opt-in isolated MinIO, synthetic credentials
make release-local         # unsigned Linux/macOS/Windows build artifacts + checksums
```

The suite covers 105-file portable recovery, exact CRLF/BOM/binary bytes, wrong keys, tampering, rollback, symlinks/traversal/FIFOs, concurrent CAS, stale plans, crash journaling, pairing expiry/replay, vault isolation and the original starter's encrypted fixture. MinIO tests additionally inspect actual objects for plaintext/path leaks. The scripted smoke test exercises recovery and pairing through real CLI processes without network.

See [architecture](docs/ARCHITECTURE.md), [protocol v1](docs/protocol/v1.md), [CLI reference](docs/CLI_REFERENCE.md), [recovery](docs/KEY_RECOVERY.md), [sync](docs/SYNC_SEMANTICS.md), [security](SECURITY.md) and [contribution guide](CONTRIBUTING.md). MIT license inherited from the starter; dependency notices are in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
