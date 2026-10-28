# EnvPort

**Early working prototype** of a local-first, Git-aware environment-file portability tool. MIT licensed.

> Current status: discovery, tracking, AES-256-GCM encrypted **local** snapshots, restore without overwrite, and tests. **Cloudflare R2, generic S3, hosted accounts, device pairing, and desktop UI are not yet implemented.** Do not use this prototype as your only backup or as a production secret manager.

## Quick start

Requires Go 1.23+. No third-party dependencies required for this prototype.

```bash
go test ./...
go build -o envport ./cmd/envport
./envport init
./envport scan ~/Projects
./envport track ~/Projects
./envport backup
./envport snapshots
./envport restore <snapshot-id> ~/Projects
```

Restore discovers Git repositories even if they have no `.env` files. Projects without a Git remote require a future explicit-mapping feature. Restore never overwrites an existing target. You can use `ENVPORT_HOME` to isolate test vaults.

## Security notes

- Locally generated AES-256-GCM key stored in `~/.config/envport/key.bin` on Unix-like systems (or OS config directory). Back up the key **securely off-device**. Losing it makes encrypted snapshots unrecoverable.
- Encryption is implemented with Go standard-library AEAD; migration to age, per-device key envelopes, and passphrase-protected recovery is planned.
- No plaintext is uploaded by this version; no network requests are implemented.
- Never commit `key.bin`, `.env`, or any vault objects to source control.
- Local storage currently has a single-writer assumption. Cross-device synchronization is not available.

## Planned architecture

`internal/discovery` scans; `internal/vault` encrypts and snapshots; `internal/storage` defines a provider-neutral object store; `internal/storage/s3` will implement generic AWS SigV4 S3 compatibility with AWS SDK v2; `cmd/envport` handles CLI interaction. Desktop can reuse the core through a future secured local service.

See [ARCHITECTURE.md](docs/ARCHITECTURE.md) and [ROADMAP.md](docs/ROADMAP.md).
