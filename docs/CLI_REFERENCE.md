# CLI reference

`envport --help` and command-specific `--help` describe the shipped surface. All examples below refer to implemented commands. Flags are accepted before or after the command. Most outputs are JSON objects/arrays; default output is indented, `--json` emits compact machine-readable JSON. Non-JSON mutating commands can return empty output. Errors are printed to stderr without secret values.

Global flags: `--home DIR` (private device state; also `ENVPORT_HOME`), `--vault NAME_OR_ID`, `--json`, `--no-network`, `--help`, `--version`. Default state: `$XDG_STATE_HOME/envport` or `~/.local/state/envport`; it intentionally differs from the starter's config directory. Never use the legacy home as new state during migration.

| Command | Behavior |
|---|---|
| `init [--offline\|--byos\|--lan]` | Initialize installation; offline adds a local profile, BYOS/LAN create no fallback vault/profile |
| `scan ROOT...` | Explicit-root read-only discovery; no enrollment or secret-content reads |
| `track PATH [--local]` | Enroll eligible files, resolving Git identity or explicit local UUID |
| `projects` | Local project IDs and checkout mappings |
| `project map ID PATH` | Map a remote project; validate known Git identity |
| `vault create NAME --storage PROFILE` | Independent vault/key, activate it |
| `vault list\|inspect` | Nonsecret local vault metadata |
| `vault use NAME` | Change selected vault |
| `vault join NAME --storage PROFILE --recovery FILE` | Recovery enrollment with separate storage configuration |
| `vault join NAME --storage PROFILE --grant FILE --issuer-fingerprint HEX` | Consume authenticated device grant |
| `storage add filesystem --name NAME --path DIR` | Private offline object directory |
| `storage add s3 --name NAME --bucket BUCKET --region REGION` | Generic S3 profile; optional `--endpoint`, `--prefix`, `--path-style`, `--aws-profile`, test-only `--allow-http` |
| `storage lan request --output FILE` | Generate a client TLS identity locally; export its public request |
| `storage add lan --name NAME --connection FILE --server-fingerprint HEX` | Import signed namespace access using a separately confirmed host fingerprint |
| `serve init --data DIR --endpoint https://PRIVATE_IP:PORT` | Initialize encrypted host TLS identity and personal namespace; no client/vault state |
| `serve --data DIR --listen PRIVATE_IP:PORT` | Run the built-in mutual-TLS ciphertext host; defaults to loopback, wildcard binding refused |
| `serve inspect\|namespaces\|clients --data DIR` | Public host metadata, namespaces and certificate grants |
| `serve namespace create NAME --data DIR` | Create an isolated storage-access namespace |
| `serve authorize REQUEST --data DIR --namespace ID --fingerprint HEX --output FILE [--read-only]` | Explicitly approve a client and export signed public connection material |
| `serve revoke CLIENT_FP --data DIR --namespace ID --confirm` | Revoke subsequent namespace requests, including existing connections; copied vault keys remain usable elsewhere |
| `storage list\|test NAME\|remove NAME` | List profiles, actively probe capabilities, or remove unused profile without touching objects |
| `backup [--dry-run]` | Plan/commit uploads and explicit tombstones |
| `status` | Three-way plan with file IDs, paths, root mappings and actions |
| `sync [--dry-run] [--accept-remote]` | Reconcile journal, replan, CAS commit and safe download; explicit replacement retains preimages |
| `restore [--snapshot ID] [--scan ROOT,...] [--dry-run] [--accept-remote]` | Map/preview/restore authenticated bytes; refuse existing different files by default |
| `history` / `snapshots` | Authenticated history IDs/generations/times, no file values |
| `resolve FILE_ID --keep-local` | Explicit conflict choice; obtain a new sync plan afterward |
| `file remove FILE_ID --confirm` | Stage remote tombstone; leave local file untouched |
| `keys export --output FILE` | Export independently encrypted recovery; destination must not exist |
| `keys verify FILE` | Authenticate/decrypt recovery and compare selected vault identity |
| `devices request --vault-id ID --output FILE` | Signed expiring join request from new installation |
| `devices approve FILE --fingerprint HEX --output FILE` | Confirm request and encrypt signed grant to that device |
| `devices list` | This installation ID and locally observed approvals, not remote membership authority |
| `doctor` | SQLite integrity, local key, recovery verification, authenticated history, all current blob contents and journal checks |
| `prune --dry-run` | Orphan preview only; no deletion |
| `migrate-legacy --source DIR --snapshot ID --dry-run` | Authenticate a legacy snapshot without importing |
| `migrate-legacy ... --name NAME --storage PROFILE --recovery-output FILE --receipt FILE` | Read-only source import into new age vault with verification receipt |
| `completion bash\|zsh\|fish\|powershell` | Cobra-generated shell completion |
| `version` | Version JSON |

Plan JSON: `{vault_id,storage,snapshot_id?,entries:[{project_id,file_id,path,root?,action,size}]}`. Restore plan: `{vault_id,storage,snapshot_id,entries:[{project_id,file_id,path,root?,state,bytes}]}`; states are `create`, `identical`, `exists`, `unmapped`. Result JSON: `{snapshot_id?,uploaded,downloaded,conflicts,pending}`. Internal head tokens/plaintext hashes and bytes are excluded from plan JSON. `--dry-run --scan` may persist explicit local project mappings; it writes neither plaintext files nor remote objects.

Exit codes: 0 command succeeded (inspect pending counts); 1 usage/environment/permission/other failure; 3 unresolved conflict; 4 failed storage precondition requiring replan; 5 corrupt/unauthenticated data or detected rollback. Authentication-specific user-friendly errors may use 1 while underlying typed corruption failures use 5. Cancellation fails without asserting a successful commit.

Environment passphrase variables: `ENVPORT_PASSPHRASE`, `ENVPORT_RECOVERY_PASSPHRASE`, and host-only `ENVPORT_SERVER_PASSPHRASE`. Interactive terminal input hides them. There are no passphrase/credential command-line flags. `--yes` is not implemented and cannot bypass checks. Values/diffs, aliases, untrack, config editing, watcher sync, vault-key rotation/revocation, vault leave, storage migration and destructive pruning are not implemented. Unknown commands/options fail rather than reporting placeholder success.

Built-in LAN setup, protocol trust and limitations are documented in [LAN.md](LAN.md). `--no-network` refuses LAN listeners and remote LAN operations too; public enrollment-file creation/import remains a local operation. LAN transport revocation is separate from vault-key revocation.
