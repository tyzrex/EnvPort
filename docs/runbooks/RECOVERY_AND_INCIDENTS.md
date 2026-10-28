# Recovery and incidents

## Lost device/local passphrase

Use independent recovery bundle + recovery passphrase + storage access on a fresh private installation. `vault join`, explicit project mappings, restore preview, byte comparison and doctor are the drill. An available authorized device can also approve a new device with verified fingerprints. No decryption administrator/reset exists.

## Lost recovery and all vault keys

Ciphertext is unrecoverable. Keep independent tested copies of recovery and storage. Storage-account password resets do not recreate decryption keys.

## Compromised device

Revoke provider credentials externally, rotate application secrets that were present on the device, and create a fresh independent vault/key for future data. Current EnvPort has no forward key-epoch rotation or vault-key revocation command. A built-in LAN host can independently revoke subsequent storage requests using `serve revoke CLIENT_FINGERPRINT --namespace ID --confirm`; this does not erase copied vault keys/data. Previously copied keys/plaintext/history cannot be revoked retroactively. Do not confuse deleting a local record with cryptographic revocation.

## Compromised S3 credentials

Rotate/restrict credentials at your provider and update the external SDK credential source. Decryption keys remain separate, but an attacker with write/delete permissions can corrupt/delete/roll back ciphertext. Run doctor, retain independent bucket backups, and compare trusted checkpoints. A returning client may detect rollback; fresh recovery cannot establish newest history without a trusted external witness.

## Bucket deletion/ransomware

Recover an independent ciphertext-store backup and recovery artifact. Do not run garbage collection or overwrite the only remaining copy. Provider versioning/object-lock policies are external choices; EnvPort does not configure or claim them. Live plaintext in compromised repositories may already be lost or disclosed.

## Corrupt object/manifest

Stop writes, preserve copies of storage and local state, run doctor, and inspect authenticated history with the original keys. Restore a known-good historical snapshot into a clean approved checkout. Authentication failures are not bypassable. Never edit encrypted object bytes to make a check pass.

## Interrupted commit/uncertain network outcome

Run `status` and `doctor`, preserve the private state database, then `sync --dry-run`. A real `sync` reconciles staged operations against authenticated ancestry before replanning. A staged transaction may have orphan blobs but is not counted as committed until its manifest appears in history. CAS failure requires a new plan; never force an old head over a new one.

## Conflicts

Review status file IDs/actions. `resolve ID --keep-local` followed by new sync explicitly chooses local bytes while preserving remote history. To choose remote, review restore's full plan, then explicitly accept remote with preimages retained. Stop editors/watchers before replacements; recover local preimages from private `.envport-preimage-*` siblings. Missing local files do not request deletion.

## Partial AES migration

The original source is read-only and remains the rollback. Keep the original key/snapshots. Inspect the independent new vault and receipt before retrying; head commit may have succeeded if receipt/local state failed. Unreferenced target blobs can be previewed with `prune --dry-run`; destructive pruning is disabled.

## Failed update or incompatible protocol

Keep the previous binary and state/ciphertext backups. Never rewrite unknown schemas or downgrade encrypted protocol bytes in place. Reject unknown feature flags and newer SQLite schema versions. Use the original compatible reader and make a separate explicitly verified migration.

No live operations, credential rotation, provider settings or public incident contact were configured by this implementation.

## LAN host loss / compromised transport identity

Stop serving and preserve the complete private host directory, including registry, encrypted TLS key, configuration and ciphertext database/WAL state. Restore a consistent offline copy plus the host unlock passphrase; do not open SQLite over a network share. Revoke compromised client certificate access per namespace, generate a fresh client request/key when re-enrolling, and rotate affected application secrets if an endpoint was compromised. Keep client vault recovery artifacts independent of host state. The host has no vault decryption key and cannot issue one. Certificate renewal/automated service management are not implemented; monitor the one-year certificate validity and plan verified replacement/re-authorization. LAN unavailability makes operations fail rather than select another backend.
