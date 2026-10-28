# Implementation status

Experimental CLI implementation, updated 2026-10-28. This document distinguishes working code/local evidence from the full PROJECT_MASTER_GUIDE.md release contract. **The full product is not complete or production certified.**

## Audited baseline

The workspace initially had only Git/tool metadata. The user subsequently supplied `envport-starter.zip`, SHA-256 `a0ced89311a942543275f511802a80b8f82cccbbf0ad6d8a8b3eccf996f8d43b`. Extracted it separately, read its README/architecture/source, ran passing `go test ./...` and `go vet ./...`, built with `-buildvcs=false`, and ran the original CLI backup/restore across different checkout paths. `cmp` verified both synthetic files. Its module identity/MIT license are retained; original documentation is archived under docs/legacy. Original-client-generated AES fixtures are committed under testdata/legacy.

## Implemented and locally verified

| Area | Evidence / limits |
|---|---|
| Domain/application separation | Application depends on domain ports and an injected storage factory; no Cobra/S3 SDK imports in engine. Validated IDs, typed errors and deterministic plans. Full owner/team domain normalization is deferred. |
| Local state | Private SQLite, migration versions 1→2, foreign keys/WAL, unknown-newer-version rejection, no file contents or raw vault/storage keys. |
| Vault protocol | Independent age X25519 vault identities; encrypted blobs/manifests/head references; bounds/schema/path/duplicate checks; immutable history; checked-in golden encrypted fixture. |
| Local object adapter | SQLite ciphertext namespace, atomic conditional creation/replacement across independent connections. Requires a suitable local filesystem; no live NFS/shared-sync-folder claim. |
| Built-in LAN | `serve` host and `lan` adapter; encrypted mutual-TLS identities, exact host trust, signed explicit enrollment, namespace isolation, read-only grants, per-request transport revocation, real CAS and private-IP-only no-proxy/no-redirect transport. Real two-client CLI recovery/concurrent backups/restart/revocation passed on Linux loopback; native hardware/platform and independent review remain. |
| S3 adapter | AWS SDK v2, SigV4/credential chain, endpoint/TLS/redirect policy, ETags/conditions, cancellation, pagination, bounded objects and timeout/retries. Writes require an active CAS capability probe. |
| Recovery | Separate encrypted recovery bundle, in-memory export verification, explicit verify and fresh-installation import; no source installation dependency. |
| Discovery/mapping | Explicit roots, size/depth/generated/example exclusions, nonsymlink files, nested repos/worktree markers, SSH/HTTPS identity normalization, explicit UUID projects, empty-checkout mapping. Ancestor Git markers cannot expand the chosen root or inject parent identity. |
| Restore | Byte-preserving, descriptor-confined paths, Linux openat2 no-symlink reads/FIFO rejection, local 0600 staging, fsync, atomic no-replace linking. Existing files require explicit replacement with independent private preimages and content/inode rechecks. Residual hostile-local race/platform review remains. |
| Sync | Durable common baselines; deterministic three-way actions; differing concurrent edits conflict; missing files do not delete; explicit tombstones leave local bytes intact; keep-local conflict choice. |
| Commits/journal | Immutable uploads before CAS, exactly one concurrent snapshot winner, losing writer replans into conflict; failed uploads/head writes do not advance checkpoint; ambiguous-response and post-head crash reconciliation tested. |
| History/retention | Historical byte-for-byte restore after tombstoning; all retained snapshots traced by prune preview. Destructive garbage collection remains disabled. |
| Devices | Independent encrypted device encryption/signing keys, signed expiring join requests, explicit fingerprint confirmation, recipient-encrypted signed grants, trusted issuer fingerprint, transactionally consumed requests. Replay/expiry/tampering/foreign-device rejection tests. No vault-key revocation/rotation or remote vault membership authority registry. |
| AES migration | Read-only EVP1 reader, authenticate source, new independent age vault/recovery, upload/read-back verification, atomic head publication, receipt and source-tree equality regression test. One selected snapshot, no fabricated original ancestry. |
| CLI | Init/offline/BYOS/LAN, scan, track, projects/map, multiple vaults, storage add/list/test/remove, backup/restore/sync/status/history, keys, devices, conflicts, doctor, tombstones, prune preview, migration, JSON, stable error exits, signal cancellation and shell completion. Unknown features fail. |

## Validation evidence

- Go 1.27.3 on Linux; pinned runtime graph now requires Go 1.26+.
- Core `go test ./...`, `go vet ./...`, golden protocol, 105-file recovery, original starter migration, tamper/wrong-key/wrong-passphrase/rollback/vault-isolation tests passed during implementation.
- Actual CLI subprocess smoke passed across three isolated installations: recovery, pairing, changed checkout paths, byte equality, default no-overwrite, explicit preimages, conflicts, history and doctor.
- Real MinIO built from pinned official source revision `07c3a429bfed` (`RELEASE.2025-09-07T16-13-09Z`); object operations/CAS/pagination/0–2 MiB objects/cancellation passed. Complete encrypted backup→fresh-install recovery→restore and inspection of actual remote objects for plaintext/path leakage passed, including after dependency updates.
- Initial govulncheck found AWS SDK advisory GO-2026-5764; dependencies were patched. Compatible staticcheck v0.8.2 passed. Govulncheck v1.9.0 reports **0 reachable vulnerabilities**, with one module-only advisory GO-2026-5932 for unimported `x/crypto/openpgp` (no upstream fix; age uses other packages from x/crypto).
- Conservative source secret guard passed; synthetic golden identity explicitly allowlisted. No real secret fixtures used.
- Final full race suite passed (application package 256.876s), including competing snapshot commits and symlink-swap containment. All five patched-graph unsigned cross-build targets passed. Final checks and artifact hashes are recorded separately in docs/VALIDATION.md; a temporary-filesystem quota failure was an environment failure and was not counted as a passing run. Temporary MinIO build dependencies were removed to free space before rerunning.
- CI workflows are authored; no claim they ran on GitHub or that anything was published/deployed. Optional live-provider workflow requires explicit dispatch and dedicated test secrets.

## Milestone coverage and remaining work

| Milestone | Status |
|---|---|
| M0 audit/guardrails | Done locally; audited starter, reproducible fixture baseline, threat model, ADRs and checks. |
| M1 modular core | Implemented CLI engine slice; richer distinct owner/member/domain ports and complete normalized local schema remain incomplete. |
| M2 crypto/recovery/migration | Implemented and locally tested; independent cryptographic review outstanding. |
| M3 discovery/safe restore | Implemented Linux slice; native macOS/Windows ACL/junction/adversarial race/full-disk/interruption matrix incomplete. |
| M4 generic S3 | Implemented and verified on real MinIO; live R2/AWS credentials absent; custom CA/multipart/single-writer fallback not shipped. |
| M5 commits/history | Implemented and tested locally/MinIO; broader failure/provider fault matrix remains. |
| M6 sync/conflicts | Manual sync implemented; automatic local deletion, per-file restore selection, watcher and full conflict UX are deferred. |
| M7 pairing/multiple vaults | Implemented signed file-based pairing/recovery and independent vaults; key epochs/rotation/revocation and remote membership registry not implemented. |
| M8 CLI beta/release tooling | Useful experimental CLI plus docs/CI/unsigned builds. Diff/value reveal, alias/untrack/config editing, storage migration and package distribution not implemented. |
| M9 desktop | Not started; no desktop daemon/IPC/Tauri/Svelte package is claimed; LAN storage hosting is a separate shipped backend. Requires stable exposed engine contracts and remaining core platform/security gates. |
| M10 hosted | Not started; optional account/API/Postgres/managed R2/team authorization not claimed. |
| M11 production | Blocked/incomplete: independent security review, live providers, actual OS recovery matrix, signing/notarization, full license audit and production operations/distribution. |

## Release blockers and exact next actions

1. **Live R2/AWS:** configure a dedicated private test bucket + scoped test credentials locally through the SDK credential provider; never paste credentials into chat. Configure a profile, run `storage test`, run opt-in live workflow/test, then a clean-install recovery/restore drill. Use docs/STORAGE_PROVIDERS.md; no production bucket credentials are needed for local development.
2. **macOS/Windows:** run on actual target systems/CI runners, implement/verify private Windows ACLs, junction handling and OS-specific path/race behavior. Current Windows state initialization is not supported by Unix permission checks. macOS system-path symlink aliases also need native validation. Cross-compilation alone is not runtime verification.
3. **Security:** independent review of shared-key author trust, pairing signing encoding, filesystem races and cryptographic recovery; extend low-disk/interruption and malicious-local-process tests. A copied vault key cannot be revoked retroactively.
4. **Production distribution:** choose/publish the source repository and release channel, complete transitive notices/SBOM review, obtain signing/notarization accounts, and verify upgrade/rollback. No external publish/deploy action was taken.
5. **Later product phases:** complete remaining core contracts and stable authenticated IPC before Tauri/Svelte desktop; optional hosted service needs deny-by-default tenant authorization, separate credentials/keys, real deployment configuration and operations tests.

Local SQLite metadata is protected by private directory permissions, not encrypted at rest. OS keychain integration is not implemented; vault/device identities use explicit passphrase-encrypted envelopes. Storage observes ciphertext sizes/timing. Shared root holders can forge manifest authors. Returning checkpoints detect some rollback; first-join freshness cannot be proven from the bucket alone. See threat-model.md for the actual trust boundary.

## Built-in LAN addition

Explicitly requested and implemented after the initial CLI baseline. See docs/LAN.md, docs/protocol/lan-v1.md and docs/tasks/LAN.md. No existing vault v1 ciphertext or local-state schema changed. Unit/adapter and real CLI tests cover no hidden fallback, encrypted client-origin credentials, independently confirmed host identity, real concurrent client backups, namespace/read-only isolation, oversized/malformed HTTP refusal, wrong identities, offline/restart behavior, transport revocation and operation without a working HTTP proxy. TLS storage authorization is separate from recovery/vault decryption. The final full race suite passed (application 288.470s, LAN adapter 169.410s), static/vulnerability checks passed, original offline/MinIO regressions passed, and all five unsigned cross-platform targets rebuilt. See docs/VALIDATION.md for evidence.
