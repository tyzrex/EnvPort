# Starter AES migration

The provided starter archive has SHA-256 `a0ced89311a942543275f511802a80b8f82cccbbf0ad6d8a8b3eccf996f8d43b`. Its original source tests passed. The unmodified CLI created and restored the committed synthetic fixture under `testdata/legacy`; both files compared equal across checkout paths.

The legacy format is `EVP1 || 12-byte GCM nonce || AES-256-GCM ciphertext/tag`, with associated data `envport-v1` and a 32-byte `key.bin`. Both manifests (`vault/snapshots/ID.enc`) and file objects (`vault/objects/ID.enc`) use it. The migration package is a **read-only** reader; no new AES objects are written. The existing `key.bin`, config and all encrypted snapshots remain unchanged.

Use a separate new device-state directory and destination storage, not your original starter state directory. Stop the legacy client and preserve an independent copy of its full state first. Never delete the original key.

```bash
# Original client: obtain the exact snapshot ID first.
# The new CLI requires a fresh private state directory.
envport --home /private/new-envport init
envport --home /private/new-envport migrate-legacy \
  --source /private/original-starter-home --snapshot LEGACY_SNAPSHOT_ID --dry-run

envport --home /private/new-envport migrate-legacy \
  --source /private/original-starter-home --snapshot LEGACY_SNAPSHOT_ID \
  --name migrated --storage local \
  --recovery-output /secure/migrated-recovery.age \
  --receipt /private/migration-receipt.json
```

For S3, configure and successfully test the new destination profile first, then select it with `--storage`. The importer authenticates every source object before creating a new vault, creates a separately encrypted recovery bundle, decrypts source bytes only in memory, immediately age-encrypts them, uploads them, reads/decrypts/verifies every new blob and manifest, and atomically publishes a new head. The receipt includes original ciphertext digest, source/destination snapshot IDs, file count and verified status; it contains no secret values or keys.

After migration, use `status` to view unmapped project IDs, `restore --scan ROOT --dry-run` for unambiguous Git projects or `project map ID ROOT` for UUID projects. Legacy Git normalization lowercased repository paths; a case-sensitive remote identity must be reviewed explicitly rather than silently assuming a match. Unsupported/ambiguous legacy identity requires manual export with the original trusted client. V1 accepts only portable `.env` paths and bounds file/object size; malformed or unsupported snapshots fail without altering source.

Verify a restore into a fresh installation using only the new recovery artifact and storage access, compare exact bytes and keep originals until satisfied. Migration preserves one selected snapshot as a new age generation one; it does not pretend to preserve every original snapshot's ancestry. Repeat into independently named vaults if older snapshots must be imported separately.

Rollback: stop using the new vault and return to the original client with its untouched key/objects. Do not copy v1 bytes into the original store. Partial target uploads are unreferenced; `doctor`, `sync` reconciliation and `prune --dry-run` diagnose target state. A failed receipt write after commit is reported explicitly; the new vault may already be verified/committed, so inspect it before retrying with another name.

The CLI and state format are intentionally versioned changes from the prototype. `history` also accepts `snapshots`; the old positional restore syntax and root-enrollment semantics are not claimed as script-compatible. No default auto-migration is performed.

Ciphertext-only migration between storage providers is not yet implemented; retain the original binding and use a separately verified copy procedure with all writers paused. Never switch storage by editing an in-use database.
