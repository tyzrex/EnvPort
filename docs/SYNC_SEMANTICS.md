# Sync semantics

Sync compares opaque byte digests for the last confirmed common base, current local file and authenticated remote manifest. It never parses/reformats dotenv values. Newline styles, comments, order, BOM and binary bytes survive backup and restore.

| Local relative to base | Remote relative to base | Action |
|---|---|---|
| unchanged | unchanged | clean |
| changed | unchanged | upload |
| unchanged | changed | download preview |
| identical new bytes | identical new bytes | converge |
| differing changes | differing changes | conflict, exit 3 |
| missing | unchanged | missing, no tombstone |
| missing | changed | offer restore/download |
| explicit remove | unchanged | commit tombstone |
| changed | deleted | conflict |
| unchanged | deleted | delete pending; no automatic local deletion |

`status`, `backup --dry-run` and `sync --dry-run` are deterministic views of file actions with vault/backend IDs. They do not print values or plaintext hashes. `backup` only commits uploads/tombstones; pending remote updates are preserved in the manifest and are not silently adopted as a local baseline. `sync` also creates missing destinations. Existing destinations require explicit `--accept-remote`, matching the previewed bytes and preserving private preimages. A reported nonzero `pending` count means work remains; it is not an all-synced claim.

No common base plus differing local/remote bytes is a conflict. Use `resolve FILE_ID --keep-local` to explicitly adopt the observed remote version as the base, then obtain/execute a new sync plan. A concurrent remote change still produces another conflict or failed CAS. Remote history is retained. To use a conflicted remote version, inspect `restore --dry-run` and explicitly `restore --accept-remote` (retains local preimages); then sync again. The experimental restore command restores all mapped files, so review its complete plan.

Commit uploads immutable blobs and an encrypted complete manifest before CAS-updating the encrypted head. A losing writer returns exit 4 and must replan; there is no last-writer-wins retry. Local changes after preview are rejected. A staged journal alone is not proof of backup. An ambiguous response is reconciled by reading authenticated head/history; a later `sync` reconciles interrupted transactions before planning. Failed unreferenced uploads remain harmless orphans.

`file remove FILE_ID --confirm` stages an explicit remote tombstone and leaves the local file intact. There is no automatic local deletion and no remote garbage collection. All historical snapshots are retained. `prune --dry-run` lists orphans while tracing every retained snapshot; deletion is disabled. Restore by `--snapshot ID` reads old snapshots without rewinding the trusted current checkpoint.
