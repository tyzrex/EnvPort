# ENVPORT — MASTER IMPLEMENTATION GUIDE FOR AI CODING AGENTS

> **Status:** implementation specification, not a claim of completed functionality.  
> **Edition:** 1.0 · 2026-10-28  
> **Audience:** autonomous AI coding agents and human maintainers.  
> **Starting point:** the existing `envport-starter` Go repository.  
> **Goal:** build a reliable, open-source, zero-knowledge, cross-platform environment-file backup and synchronization product with independently usable BYOS and optional hosted service, designed for a later desktop app.

---

## 0. AGENT OPERATING INSTRUCTIONS (READ FIRST)

**You are the lead implementation agent. Implement the project, not just plans or mockups.** Work in the repository, inspect code before editing, make small reviewable changes, execute tests, and record results. Never state that a feature works without having verified it. Never claim to have configured live Cloudflare, AWS, DNS, billing, or hosted infrastructure when credentials/permissions are unavailable; provide reproducible setup documentation instead.

### Mandatory workflow for every milestone

1. Read this guide, `README.md`, `docs/ARCHITECTURE.md`, and the actual repository files. Run baseline tests.
2. Create/maintain `docs/IMPLEMENTATION_STATUS.md` with **Done / In progress / Not started / Blocked** features and evidence.
3. Implement **one coherent vertical slice** at a time: domain contracts → core implementation → CLI adapter → tests → docs.
4. Run formatting, static checks, unit tests, integration tests, and any relevant threat-model/security tests.
5. If an external account, secret, hardware device, store signing key, or production infrastructure is required, **stop that step, mark blocked, give exact user actions**, and continue all work that can be done locally. Do not fake success.
6. Record decisions in `docs/adr/ADR-XXXX-*.md`. Record protocol changes and migrations. Do not silently break old encrypted backups.
7. Produce a concise handoff after each milestone: files changed, functionality tested, commands/output, limitations, and next milestone.
8. Avoid scope creep. Never substitute a pretty UI for a working backup/restore engine.

### Non-negotiable security rules

- Do not log, print, transmit, or commit plaintext secret values, private keys, credentials, or raw `.env` contents. Redact errors and test fixtures.
- Never scan the entire home directory or system disk implicitly. Require explicit scan roots.
- No silent overwrite of local files; no implicit deletion based on absence; no auto-merge of `.env` plaintext.
- Do not follow symlinks into/out of untrusted trees. Avoid TOCTOU path escapes during restore.
- All remote secret payloads and sensitive metadata must be encrypted **before** leaving the client.
- BYOS must operate **without EnvPort-hosted accounts or EnvPort servers**, and should have no hidden fallback to managed storage.
- Do not implement new cryptographic primitives. Use audited/established libraries and carefully defined key envelopes.
- Do not call a provider “multi-writer safe” unless its conditional-write semantics are verified by tests.
- Account login is **not** vault decryption. R2/S3 access is **not** vault decryption. Device identity is **not** user account identity.
- A copied key cannot be cryptographically revoked retroactively. Document this explicitly.
- Treat project names, Git URLs, secret names, filenames, file sizes, and device names as potentially sensitive metadata.
- Never use real personal or production secrets in tests.

### Definition of product completion

A clean installation on Linux can create a vault, enroll projects, securely back them up to a private S3-compatible bucket; a fresh macOS install can be authorized, map clones with different absolute paths, restore byte-for-byte identical environment files, and safely synchronize subsequent changes. The core must also work offline using local encrypted storage. Multiple independent users/vaults must be isolated, optional hosted mode must enforce authorization, and the same engine must power the CLI and desktop. All release blockers in §22 must pass.

---

## 1. PRODUCT REQUIREMENTS AND USER JOURNEYS

### 1.1 Mission

**EnvPort** is a Git-aware, local-first encrypted environment-file portability tool, not a general replacement for Infisical, Vault, SOPS, or application-runtime secret injection. It discovers existing developer secrets files, encrypts them locally, versions their contents, stores encrypted objects in user-chosen storage, and restores them in the correct repository on another machine.

### 1.2 Personas and deployment modes

| Mode | Identity | Storage | Infrastructure required | MVP/phase |
|---|---|---|---|---|
| Offline personal | Local owner + vault/device keys | Local encrypted directory | None | Core MVP |
| Standalone BYOS | Local owner + vault/device keys | User's S3-compatible provider | User's bucket | Core MVP |
| Hosted managed | Hosted user + separate vault keys | EnvPort-managed R2 | Hosted API, Postgres, R2 | Later |
| Hosted with BYOS | Hosted user + separate vault keys | User's S3 bucket, direct client connection | Hosted control plane only | Later |
| Shared/team vault | Multiple authorized principals | Managed or BYOS, subject to policy | Membership and key-grant infrastructure | Later |

### 1.3 Required workflows

**A. Linux → Mac, same developer:** On Linux, `init`, configure BYOS, `scan`, `track`, `backup`. On Mac, install, `vault join`, pair from Linux or import recovery, scan local Git checkouts, preview the restore plan, restore. Directory roots can differ. Then synchronize edits in both directions with conflict safety.

**B. Two distinct developers:** Alice and Bob have separate vault IDs, keys, storage prefixes and grants. Knowing Bob's vault ID or Git URL must not confer access. Hosted authorization must additionally enforce vault membership. BYOS isolation depends on each user's own storage permissions and keys.

**C. Multiple personal/work vaults:** A machine may access several vaults using separate encryption keys, storage backends, configured scan roots and policies. The same repository may be enrolled in different vaults only by explicit action.

**D. Bring your own storage:** User can connect their own Cloudflare R2, AWS S3, MinIO, Backblaze B2, or compatible endpoint. No EnvPort account required. S3 capability tests and secure credentials handling required.

**E. Unavailable origin device:** User restores with securely exported recovery bundle + storage credentials. Recovery testing is mandatory before claiming the backup is recoverable.

**F. Conflicting edits:** Linux and Mac both edit `.env`. No “last writer wins.” Explain base/local/remote and require explicit resolution, retaining history.

**G. No Git remote:** User can explicitly bind a local project UUID to a new location; filename/folder-name matching alone never silently determines identity.

**H. Desktop app:** Reuse the same core services via a secured local IPC transport; do not reimplement encryption or sync in the frontend.

### 1.4 Out of scope for initial release

Secrets rotation, CI secret injection, SSH key sync, team RBAC, commercial billing, organization policy engine, browser extension, code execution in user repositories, automated Git clone, server-side secret parsing, production credential management, and a sophisticated secret editor.

---

## 2. EXISTING REPOSITORY AUDIT AND MIGRATION

### 2.1 Verified starter baseline (inspect again before editing)

Current archive/repository has:

- `cmd/envport/main.go`: prototype CLI commands.
- `internal/discovery/scan.go` and tests: scanning and Git-aware project discovery.
- `internal/vault/vault.go` and tests: **local AES-256-GCM snapshot encryption**.
- `internal/storage/storage.go`, `internal/storage/local.go`: minimal object storage abstraction and local adapter.
- `internal/storage/s3/README.md`: S3 plan only — **not** functional S3 integration.
- `internal/core/config.go`, docs, Go module and GitHub CI workflow.

No assumption that Cobra, SQLite, age, Cloudflare R2, account service, device pairing, CAS concurrency, Tauri, or hosted infrastructure is already implemented.

### 2.2 Bootstrap commands

```bash
unzip envport-starter.zip
cd envport
go version
go test ./...
go vet ./...
go build -o ./bin/envport ./cmd/envport
./bin/envport --help
```

Create `.envport-testdata/` fixture directories (ignored by Git) to exercise actual commands. Inspect and document CLI behavior and existing file formats. Do not delete existing user snapshots or keys.

### 2.3 Migration from prototype encryption

The starter uses AES-256-GCM with a local key file. The target architecture uses age and per-device/recovery envelopes. **Do not silently reinterpret existing snapshot bytes as age data.** Design a versioned legacy reader, introduce format `v1`, and offer an explicit, atomic migration path:

1. Identify original snapshot and key material; verify legacy decryption with original code/tests.
2. Create a **new** vault and recovery bundle using the new protocol.
3. Decrypt legacy objects only locally; immediately re-encrypt under the new vault identity.
4. Verify new backup/restore against fixture and checksum; preserve legacy originals until user confirms.
5. Mark legacy source read-only, create migration receipt and rollback instructions.
6. If legacy snapshot compatibility cannot be guaranteed, communicate that the prototype format is unsupported and offer safe export/import with user-held key. Never promise transparent migration.

---

## 3. HIGH-LEVEL ARCHITECTURE

```text
CLI (Go/Cobra)           Desktop (Tauri/Svelte 5)         Optional hosted UI
      |                      |                                 |
      +----------- application service contracts --------------+
                             |
                    EnvPort Core (Go)
           discovery / resolver / crypto / vault
              snapshot / planner / sync / restore
                             |
                  Encrypted Vault Repository
                             |
                     ObjectStore interface
                  /         |          \
            filesystem   S3-compatible  Managed API
                           |                 |
                  R2/AWS/MinIO/B2      Hosted control plane
                           |                 |
                       User bucket      EnvPort-managed R2

Local: SQLite state + OS keychain/secure key store + authorized filesystem roots
Hosted: Postgres account/control data only (no plaintext project secrets)
```

### 3.1 Architectural constraints

- Dependency direction: `transport → application → domain ports`; infrastructure implements ports.
- Core domain and application must not import Cobra, Tauri, a concrete S3 SDK, HTTP handlers, or UI packages.
- Keep one stable Go engine; CLI and desktop are adapters.
- The optional service owns authorization and storage allocation, **not** plaintext or vault private keys.
- Protocol objects and manifests are versioned and documented independently of implementation.
- Use strongly typed IDs, typed errors, context cancellation, deterministic sync planning, and precise status enums.

### 3.2 Recommended eventual layout

```text
envport/
├── cmd/
│   ├── envport/                     # CLI executable
│   └── envportd/                    # optional local daemon/desktop bridge
├── internal/
│   ├── domain/                      # models, IDs, policies, errors
│   ├── application/                 # use cases: scan, backup, restore, sync, devices
│   ├── discovery/                   # fs scanner, patterns, exclusions
│   ├── projects/                    # Git identity, worktrees, aliases, mapping
│   ├── vault/                       # manifests, snapshots, head refs, repository
│   ├── crypto/                      # age, key wrapping, recovery, signing
│   ├── sync/                        # three-way planner, conflicts, transactions
│   ├── restore/                     # destination verification, atomic writes
│   ├── devices/                     # enrollment requests and grants
│   ├── storage/                     # abstraction and implementations
│   │   ├── s3/                      # generic SDK adapter
│   │   ├── filesystem/
│   │   └── managed/
│   ├── persistence/                 # SQLite migrations and repositories
│   ├── credentials/                 # OS keychain and local secure storage
│   └── transport/
│       ├── cli/
│       └── localipc/
├── pkg/protocol/                    # stable cross-client protocol types
├── apps/desktop/                    # Tauri + Svelte 5
├── apps/web/                        # optional hosted web console
├── services/cloud-api/              # optional hosted control plane
├── docs/
│   ├── adr/
│   ├── protocol/
│   ├── threat-model.md
│   ├── IMPLEMENTATION_STATUS.md
│   └── runbooks/
├── testdata/                         # synthetic only, never live secrets
├── tests/integration/
├── tests/e2e/
├── .github/workflows/
├── Makefile
├── .goreleaser.yaml
└── README.md
```

Refactor gradually; don't rename every package before any value is delivered.

---

## 4. DOMAIN MODEL AND ISOLATION

Use independent concepts:

| Entity | Fields (minimum) | Invariant |
|---|---|---|
| Owner | `owner_id`, auth mode | Local owner may exist without online account |
| User | `user_id`, auth identity | Hosted only; not a decryption key |
| Device | `device_id`, public encryption/signature keys, status | Every install gets its own private keys |
| Vault | `vault_id`, protocol version, key epoch, storage binding | Key and history isolation boundary |
| Vault member | `vault_id`, principal_id, role | Grant needed for account/API access |
| Vault device grant | `vault_id`, `device_id`, encrypted key envelope, epoch | Must be authenticated |
| Project | `project_id`, canonical Git identity or local UUID | Directory name not sufficient identity |
| Tracked file | `file_id`, project ID, repo-relative path, flags | Stable identity across machines |
| Snapshot | ID, parent IDs, generation, author device, timestamp | Immutable, authenticated |
| Head reference | Snapshot ID, ETag/version token | CAS update only |
| Blob | random ID, ciphertext, encrypted content metadata | Immutable ciphertext object |
| Storage profile | adapter, endpoint, bucket, region, prefix, credential reference | No raw secret in config |
| Sync baseline | file ID, base object/content digest, last remote snapshot | Per-device three-way diff |
| Conflict | file ID, base/local/remote states, resolution | No automatic destructive choice |

### Isolation rules

- Every vault has a random, unguessable ID, separate crypto material, and unique object prefix.
- A shared bucket prefix is a namespace, **not authorization**; hosted API enforces vault membership for every operation.
- BYOS credentials are the bucket owner's responsibility; default to bucket-scoped permissions.
- Devices authorized for vault A are not implicitly authorized for vault B.
- One user can have many vaults, each with different storage providers.
- Shared/team vaults must have a dedicated key-grant and membership design; do not infer access from GitHub organization or email domain.

---

## 5. PROTOCOL V1: ENCRYPTED VAULT FORMAT

Create `docs/protocol/v1.md` and golden binary fixtures before making R2 multi-device writes.

### 5.1 Object key layout

```text
<user-configured-prefix>/v1/vaults/<vault-uuid>/
  protocol.json                  # minimal public version/features only
  refs/main                     # opaque reference to encrypted snapshot
  snapshots/<random-id>.age      # encrypted immutable manifest
  blobs/<random-id>.age          # encrypted immutable data
  envelopes/<device-id>/<epoch>  # recipient-wrapped key grants
  recovery/<random-id>.age       # optional encrypted recovery bundle
```

Remote object keys must NOT contain project names, Git URLs, usernames, filenames, or email addresses. The storage provider can still observe access patterns, ciphertext lengths, and timing. Don't claim metadata privacy beyond what is actually implemented; padding is optional later.

### 5.2 Authenticated private manifest (example plaintext structure)

```json
{
  "schema_version": 1,
  "vault_id": "uuid",
  "snapshot_id": "random-id",
  "parent_snapshot_ids": ["previous-id"],
  "generation": 14,
  "author_device_id": "uuid",
  "created_at": "2026-10-28T00:00:00Z",
  "projects": [
    {
      "project_id": "uuid",
      "identity": {"kind": "git", "canonical_remote": "github.com/org/repo"},
      "files": [
        {
          "file_id": "uuid",
          "relative_path": "apps/web/.env.local",
          "blob_id": "random-id",
          "content_sha256": "hex",
          "plaintext_length": 123,
          "deleted": false
        }
      ]
    }
  ]
}
```

All fields above are **inside authenticated encryption**. Never expose raw content hashes in unencrypted object metadata. Validate size limits, IDs, duplicate paths, UTF-8/path rules, impossible generations, and schema versions.

### 5.3 Snapshot commit protocol

1. Fetch `refs/main`, record ETag/opaque version token; fetch and authenticate current snapshot.
2. Verify expected snapshot ancestry against locally trusted checkpoint; reject suspicious rollback when detectable.
3. Calculate plan against last synchronized base and local scan.
4. Encrypt and upload changed immutable blobs with create-if-absent semantics; verify upload results.
5. Create a new immutable encrypted manifest; upload under random ID.
6. CAS-write `refs/main` with `If-Match` (or `If-None-Match: *` on initialization). Both conditions must be evaluated atomically by the provider.
7. On `412`/concurrent conflict: fetch new reference, recompute three-way merge, **do not blindly retry prior head**.
8. Only on successful CAS update local baseline and durable transaction journal.
9. If outcome is ambiguous because network failed, reread/reconcile using transaction identity; avoid duplicate contradictory commits.
10. Orphan blobs are tolerable and cleaned after retention; no active snapshot may reference missing objects.

**Rollback warning:** ETag/CAS prevents some lost updates but does not ensure freshness against a malicious storage administrator. An authenticated snapshot chain and trusted local checkpoints help returning devices; first-time recovery from an untrusted bucket cannot prove no historical rollback without an external trusted witness. Explicitly disclose this limitation.

### 5.4 Forward compatibility

- Every envelope/manifest has a protocol version and required feature flags.
- Reader may accept known older versions; writer refuses incompatible unknown version.
- Never rewrite storage in place during upgrade without validated migration and recoverability.
- Maintain golden fixtures and protocol compatibility matrix across versions.

---

## 6. CRYPTOGRAPHY, RECOVERY AND DEVICE TRUST

### 6.1 Recommended MVP key hierarchy

- Generate a **vault root secret** from secure randomness; derive versioned data-encryption material using a vetted KDF with domain separation, or wrap a random DEK per epoch. Record final cryptographic design in a reviewed ADR.
- Use `filippo.io/age` for encrypted file payloads/key envelopes. Use mature signature support (for example Ed25519) for device-signed grants/checkpoints where needed.
- Device identity: independent encryption public/private keypair and signing keypair; private material stays local.
- Authorized-device envelopes contain appropriate wrapped vault key/epoch material and authenticated grant metadata.
- Use strong recovery code or passphrase-protected recovery bundle with a resource-bounded, vetted KDF. Provide tested restore procedure.
- Do not use an existing SSH key as the default vault key.

### 6.2 First-run initialization

1. Pick standalone or hosted mode (standalone is default).
2. Generate local owner/device and vault identities.
3. Generate vault root material and initial key epoch.
4. Store local private material protected by OS keychain where available, otherwise encrypted at rest with explicit unlock and restricted file permissions; document trade-offs.
5. Generate encrypted recovery bundle; ask user to store independently.
6. Verify recovery decryption in memory before first cloud backup; do not expose recovery material in history/logs.
7. Select filesystem or S3 storage and validate capabilities/permissions.
8. Write first encrypted manifest and record a trusted checkpoint.

### 6.3 Device enrollment: Linux → Mac

1. Mac generates device encryption + signing keypairs locally.
2. Mac creates short-lived, nonce-bearing join request with device public keys and vault binding.
3. User conveys request via QR/paste/invitation transport; **QR is transport, not authentication**.
4. Linux displays request fingerprint, checks out-of-band short authentication string and requires explicit approval.
5. Linux signs approval and encrypts key grant to exactly Mac's encryption public key, with expiry and replay protection.
6. Mac authenticates approval and decrypts grant; stores credentials securely.
7. Mac receives S3 access **separately** (enter credentials/profile, or scoped hosted authorization). Sharing vault key alone does not grant object access.
8. Mac scans checked-out repositories, previews mappings, and restores safely.

Implement recovery-based joining before remote pairing if it gives an earlier secure vertical slice. Avoid shipping an unauthenticated pairing feature.

### 6.4 Revocation and rotation

- Immediate hosted effect: block future API access for revoked device.
- Cryptographic forward effect: generate new key epoch, distribute only to remaining devices, encrypt future snapshots under new epoch.
- Limits: revoked device may have copied previous keys, ciphertext, or plaintext. Revocation cannot undo that. Rotate affected application tokens/DB passwords if device compromised.
- Do not promise retroactive secrecy; re-encryption of history cannot erase previously exported copies.

---

## 7. FILE DISCOVERY AND PROJECT MATCHING

### 7.1 Scanner

Commands accept one or more explicit roots. Default scan roots are configured roots, never the full drive.

Include `.env`, `.env.local`, `.env.production`, `.env.development`, `.env.test`, `.env.staging`, `.env.*.local` and configurable patterns. Exclude `.env.example`, `.env.sample`, `.env.template` by default. Users may explicitly track non-dotenv secret configs later.

Skip `node_modules`, `.git`, build outputs, caches, Python virtual environments, and other known generated directories. Handle hidden roots, filesystem permission errors, unreadable paths, symlinks, git worktrees, submodules, nested repos, and monorepos. Constrain file size (configurable), file types, and traversal depth; report skips. **Scan is read-only.** Track/enroll is explicit.

### 7.2 Canonical identity

- Git repository: canonical remote host/path, normalized HTTPS/SSH and trailing `.git`, with safeguards for host case sensitivity and ports.
- Treat forks and unrelated mirrors as distinct unless user explicitly aliases them.
- If multiple remotes, require configured primary identity or user selection.
- If no remote, create random project UUID with an explicit mapping command.
- Project-local path = repository-relative normalized path; store absolute path only as local device mapping.
- Block traversal (`..`), rooted paths, drive letters in foreign path format, NUL, alternate streams and reserved platform names where relevant.

### 7.3 Commands and acceptance tests

```bash
envport scan ~/Projects ~/Work
envport track ~/Projects/hrms
envport projects
envport project map <project-id> ~/Code/hrms
envport project alias <project-id> <new-canonical-remote>
```

Tests: equivalent Git SSH/HTTPS match; renamed checkout works; nested repos don't collapse; project without remote prompts; malformed remote doesn't crash; symlink escape skipped; repo identity collision asks user, never overwrites.

---

## 8. STORAGE BACKEND: FULL S3 COMPATIBILITY

### 8.1 Storage interface

Implement a provider-neutral Go `ObjectStore` with `Put` (conditional modes), `Get` (streaming), `Head`, `List` (cursor), `Delete`, and `Capabilities`. Prefer `io.Reader` and typed errors. `Put` must support **CreateIfAbsent**, **IfETagMatch**, and **Unconditional** as explicitly separate modes; reject invalid combinations. Return ETag and request metadata without echoing credentials.

Capabilities: conditional creation, conditional replace, strong-enough consistency, multipart support, max object size, credential refresh, optional versioning, optional object lock. Never require unsupported S3 features by default (ACLs, object lock, provider-native features).

### 8.2 Generic S3 adapter

Use **AWS SDK for Go v2** with SigV4 signing and an overridable endpoint resolver. Support:

- AWS S3 (standard regions, default SDK credential chain, STS/profile where available).
- Cloudflare R2 (`https://<ACCOUNT_ID>.r2.cloudflarestorage.com`, region commonly `auto`, scoped token, path-style as appropriate).
- MinIO, Backblaze B2, and custom S3-compatible endpoints with capability validation.
- Endpoint/region/bucket/prefix/addressing-style/CA bundle/credential-source options.
- No TLS bypass by default; explicit warning for `http://localhost` or trusted LAN test endpoints.
- No credential leakage through redirects or untrusted endpoint changes.
- Pagination, timeouts, exponential jitter retries, limits on concurrency, and cancellation.
- AWS profile/session credentials; optional OS keychain secret references, never raw keys in plaintext config.

**Important compatibility detail:** `If-Match` and `If-None-Match` conditional `PutObject` are supported by AWS S3 and Cloudflare R2 as documented, but other S3-compatible services differ. Probe functionality against a dedicated test prefix and record capability results; do not infer it from the provider name. If CAS replace is missing, permit explicitly labeled **single-writer backup/restore mode only**.

### 8.3 Provider setup examples

```bash
# Generic, interactive; credentials are never command-line arguments
envport storage add s3 --name personal-r2
envport storage test personal-r2
envport vault create personal --storage personal-r2

# AWS credentials may come from AWS_PROFILE
envport storage add s3 --name aws-backup --provider aws

# Local offline encrypted storage
envport storage add filesystem --name usb --path /media/backup/envport
```

Example *non-secret* configuration:

```yaml
config_version: 1
active_vault: personal
storage_profiles:
  personal-r2:
    driver: s3
    provider_hint: cloudflare-r2
    endpoint: https://ACCOUNT_ID.r2.cloudflarestorage.com
    region: auto
    bucket: envport-personal
    prefix: envport/
    path_style: true
    credentials:
      source: os-keychain
      reference: envport-r2-personal
```

### 8.4 Provider-test matrix

Verify `Put/Get/Head/List/Delete`, create-only write, ETag conditional replace, CAS collision (`2 writers → exactly 1 winner`), pagination, zero-length object, large object, retries, stale credentials, region/endpoint errors, corruption detection, canceled stream and provider outage.

Run local MinIO integration tests in CI; use an optional live R2/AWS workflow with dedicated test bucket credentials through GitHub Actions secrets. Never hardcode or log tokens. A fake/mocked S3 server does not substitute for live provider testing.

### 8.5 Storage migration

`envport storage migrate --from old --to new --vault personal --dry-run`. Copy ciphertext byte-for-byte, verify referenced objects, freeze/co-ordinate writers, verify full restore from target, switch binding atomically, keep old storage as rollback until explicitly removed. No re-encryption required unless changing crypto identity/policy.

---

## 9. SQLITE AND LOCAL PERSISTENCE

Use migration-managed SQLite for config/index/sync state. Local state is device-specific, not the authoritative remote snapshot.

Tables (minimum): `schema_migrations`, `local_owners`, `devices`, `vaults`, `vault_keys`, `storage_profiles`, `scan_roots`, `projects`, `project_locations`, `tracked_files`, `file_sync_states`, `snapshots`, `snapshot_files`, `operations`, `conflicts`, `trusted_checkpoints`, `device_grants`.

Every table has stable IDs, appropriate foreign keys/unique indexes, timestamps, and explicit cascade policy. No plaintext file contents in SQLite. Never store raw S3 secret keys or unwrapped vault keys as plain DB values. Configure WAL where appropriate and limit connection lifetime; use schema migrations that can be tested from older versions.

Provide `envport doctor` to check DB integrity, key availability, permissions, backup reachability, protocol version and restore readiness. Provide export of non-sensitive diagnostics.

---

## 10. THREE-WAY SYNC, CONFLICTS AND DELETIONS

### 10.1 File state algorithm

For each tracked file maintain `Base` (last confirmed common state), `Local` (filesystem content or absence), `Remote` (current authenticated manifest). Cases:

| Base→Local | Base→Remote | Decision |
|---|---|---|
| unchanged | unchanged | clean |
| changed | unchanged | upload new object/snapshot |
| unchanged | changed | download only if destination approved, otherwise preview |
| same change | same change | converge without conflict |
| differing changes | differing changes | conflict, no overwrite |
| missing locally | unchanged remotely | missing, **not deletion** |
| explicit tombstone | unchanged locally | request confirmation for local deletion |
| remote deleted + local modified | both changed | conflict |

Compare file bytes/hashes, **do not parse and rewrite dotenv files**; newline, formatting, comments, BOM, binary-ish values and order must be preserved byte-for-byte.

### 10.2 Sync transaction

`PlanSync` produces a deterministic preview with actions, source/target object IDs, expected head token, risk flags and conflicts. `ExecuteSync` revalidates preconditions, stages uploads, CAS commits head, updates local baseline transactionally and emits progress events. If another device commits, recompute against fresh remote state. Never assume success from uploaded blobs alone.

### 10.3 Conflict resolution UI

Options: keep local, use remote, save both, show key-name-only diff, skip. Plaintext value comparison must be opt-in and default to redaction, especially on desktop screenshots/terminal history. Mark conflict resolved only when user-selected outcome is committed or safely restored.

### 10.4 Delete and history policy

- Missing local files do not create tombstones.
- Explicit `envport file remove ...` creates authenticated tombstone.
- Retain recoverable historical snapshots and pinned checkpoints.
- Garbage collection mark-and-sweep must trace **all** retained snapshots and key envelopes, use configurable grace periods, and have `--dry-run`.
- No GC enabled by default until crash/concurrency correctness is proved.

---

## 11. RESTORE ENGINE (HIGH-RISK FILESYSTEM CODE)

`PlanRestore` must show project mapping, destination path, whether file exists, conflicts, permissions, expected bytes, snapshot and user action before execution. `ExecuteRestore` must:

1. Match Git roots or explicit project mappings only.
2. Canonicalize and validate destination under approved root; reject traversal, symlink escapes and unsafe alternate path syntax.
3. Download and authenticate ciphertext; decrypt locally into memory or secure temp file with restricted mode, never global temp without controls.
4. Revalidate target directory immediately before write; use safe platform-specific APIs to mitigate symlink swap / TOCTOU.
5. Create temp file in destination filesystem with restrictive permissions; fsync where supported; atomic rename only under safe policy.
6. By default **refuse any existing destination**; optional force overwrite requires preview, explicit flag and preimage backup/snapshot.
7. Preserve exact plaintext bytes; normalize permissions safely (`0600` on Unix, restrictive ACL equivalent on Windows).
8. Journal completion and report per-file outcome. Failure halfway through must not clobber already existing files.

Test malicious manifest, symlinks, junctions, Windows drive paths, case-insensitive collisions, long paths, read-only filesystems, low disk, permission errors, mid-write interruption, and already-existing targets.

---

## 12. CLI PRODUCT CONTRACT

### 12.1 Commands

```text
envport init [--offline|--byos|--hosted]
envport scan [roots...] [--json]
envport track <path>
envport untrack <path>
envport projects
envport project map <id> <path>
envport vault create|list|use|inspect|join|leave
envport storage add|list|test|migrate|remove
envport backup [--dry-run]
envport restore [--snapshot <id>] [--scan <root>] [--dry-run]
envport status [--json]
envport sync [--dry-run]
envport history [project]
envport diff [project/file] [--show-values]
envport devices list|request|approve|revoke
envport keys export|import|verify|rotate
envport doctor [--json]
envport prune --dry-run
envport config get|set|list
envport version
```

Start with current implemented commands and evolve without unnecessarily breaking scripts. Cobra is recommended but not compulsory if a clean equivalent exists.

### 12.2 UX and machine semantics

- Default interactive for dangerous operations; `--json` for machine-readable status; stable exit codes.
- `--yes` can confirm harmless prompts but **must not** bypass destructive checks without dedicated explicit options.
- Show selected vault and backend in every destructive-operation preview.
- Terminal output redacts secret contents and credentials.
- Support command-level `--help`, shell completion, `--version`, and a `--no-network` mode where meaningful.
- Prefer a clean plain-text renderer before elaborate TUI.

### 12.3 Sample personal workflow

```bash
# Linux
envport init --byos
envport storage add s3 --name my-r2
envport storage test my-r2
envport vault create personal --storage my-r2
envport scan ~/Projects
envport track ~/Projects/hrms
envport backup

# Mac, after installing CLI and cloning repositories
envport vault join       # existing-device authorization or recovery bundle
envport scan ~/Code
envport restore --scan ~/Code --dry-run
envport restore --scan ~/Code
envport status
envport sync
```

Document that credentials/bucket location and vault grant are separate prerequisites on Mac.

---

## 13. DESKTOP APPLICATION ARCHITECTURE

Build desktop **after** stable engine contracts, not before. Use Tauri + Svelte 5 + TypeScript for UI, Go core as independently versioned bundled sidecar or daemon. Keep frontend ignorant of private keys and plaintext beyond explicitly authorized, short-lived reveals.

### 13.1 Local IPC

- macOS/Linux: permission-limited Unix domain socket. Windows: access-controlled named pipe.
- Authenticate frontend process to local engine using OS identity/ephemeral capability; reject cross-user access.
- Never expose unauthenticated localhost HTTP APIs. If HTTP is ever used, require explicit token, origin/CSRF defenses, and local binding.
- Versioned request/response contracts; progress event streaming with cancellation.
- Core service provides `Scan`, `ListVaults`, `ListProjects`, `PlanBackup`, `ExecuteBackup`, `PlanRestore`, `ExecuteRestore`, `PlanSync`, `ExecuteSync`, `ListDevices`, `ApproveDevice`, `StorageTest`, and `Doctor`.

### 13.2 Screens

1. Onboarding: Standalone vs Hosted; My S3 vs Managed vs Local.
2. Storage connection wizard: endpoint/bucket/region/credentials, TLS and capability test, no password echo.
3. Recovery setup: generate/verify bundle, clear warnings.
4. Dashboard: vault/device sync health, last committed snapshot, issues.
5. Project explorer: enrolled/untracked/missing, Git mappings, file counts, safe status.
6. Sync review: planned uploads/downloads/conflicts, explain no overwrite.
7. Restore wizard: select vault/snapshot/project/root, preview target paths, execute with progress.
8. History: snapshot list and selective restore.
9. Device management: join, approve, revoke, epoch warnings.
10. Settings: scan roots, ignored patterns, credential references, storage profiles, diagnostics.

Use clean responsive UX, keyboard navigation, screen reader labeling, meaningful empty/error states, dark/light themes, and zero decorative secret reveals. No fabricated “synced” badge without confirmed commit.

### 13.3 Packaging

Tauri signing/notarization requirements are platform-specific. CI can build unsigned test artifacts; publishing signed macOS/Windows binaries may require user-provided certificates/accounts. Document these as external blockers, do not invent access.

---

## 14. OPTIONAL HOSTED CONTROL PLANE (SEPARATE MILESTONE)

Hosted does not replace standalone; it must be optional. Build only after BYOS CLI proves sound.

### 14.1 Components

- Backend: Go service (or Micronaut if explicitly justified), PostgreSQL migrations, REST/OpenAPI endpoints, structured logging.
- Auth: passkeys or secure provider integration; session management, CSRF protections, rate limits, passwordless recovery policy.
- Authorization: memberships checked for every vault operation including presigned URLs, device grants, sync refs and deletion.
- Storage: managed Cloudflare R2, server-held bucket credentials; clients upload encrypted objects through authorization-scoped URLs or API proxy.
- No server-side vault decryption, project names, secret values, or unwrapped keys.

### 14.2 Data model

`users`, `sessions`, `devices`, `vaults`, `vault_members`, `vault_device_grants`, `storage_connections`, `vault_storage_bindings`, `enrollment_requests`, `audit_events`, `usage_metrics`, `billing_accounts` (only if monetized).

Use `vault_id` tenant scoping, foreign keys, least privilege, audit events and negative authorization tests. Consider PostgreSQL RLS as defense in depth, not substitute for application authorization. BYOS credentials **must not be uploaded to hosted API** if direct BYOS mode is promised. If server-mediated BYOS is introduced later, label it explicitly and require deliberate consent.

### 14.3 Managed mode storage operations

Backend issues short-lived, operation-limited presigned URLs or proxies requests. Ensure presigning supports required conditional headers and exact object key; otherwise perform CAS via API proxy with server-side authorization and atomic storage conditional write. Don't return shared long-lived bucket keys to clients.

### 14.4 Threat controls

Rate limiting, abuse protection, session/device revocation, opaque IDs, presigned URL expiration, request-size limits, idempotency keys, storage quota policies, secret-safe observability, deployment isolation, audit trails, account deletion semantics, secure backups, incident response, and penetration testing before public launch.

---

## 15. TEST STRATEGY AND QUALITY GATES

### 15.1 Test pyramid

- Unit: scanner rules, Git canonicalization, manifest validation, cipher interoperability, key envelope verification, sync state machine, path normalization.
- Property-based/fuzz: hostile remote URLs, manifest objects, Windows/Unix paths, conflict planner, file-pattern parser.
- Integration: SQLite migrations, filesystem object store, MinIO S3 adapter, conditional writes, crash journaling.
- Live opt-in: R2 and AWS S3 capability tests using temporary scoped credentials and test prefixes.
- Cross-platform E2E: Linux → Mac/Windows via same vault; fresh installation and recovery.
- Security: symlink/junction races, malicious remote object, rollback, compromised token, revoked grant, leakage through logs.

### 15.2 Essential test scenarios

1. 100+ fixture files of assorted names, size, encoding, newline styles and binary-safe bytes.
2. Git URL SSH/HTTPS equivalence; renamed checkout, monorepo, nested repo, submodules and forks.
3. Two devices concurrently write same head: **only one CAS succeeds**, loser recomputes.
4. Upload succeeds but head update fails; no false “backed up” status.
5. Network timeout leaves uncertain write; reconcile idempotently.
6. Local file deletion is not remote deletion.
7. Both devices edit same file; correct conflict, original bytes retained.
8. Recover with only recovery artifact + storage credentials on clean machine.
9. Wrong recovery secret, tampered ciphertext and malformed manifests fail safely.
10. Permission failures, full disk, stopped process, corrupt DB, keychain unavailable.
11. Malicious `../` path, symlink/junction traversal and case-insensitive filename collision blocked.
12. S3 list pagination, 403/404/412/409 handling and provider-specific failures.
13. Multiple independent vaults/users cannot be cross-accessed.
14. Snapshot history and garbage-collection reachability preserve pinned history.
15. Desktop bridge rejects unauthorized local processes.

### 15.3 Commands in CI

```bash
go fmt ./...
go vet ./...
go test ./...
go test -race ./...          # where supported
# add staticcheck, govulncheck and lint after dependency pinning
# run optional MinIO integration suite via containerized CI service
```

Use fixed synthetic secrets, never production `.env` files. Record CI evidence and release artifacts. Prefer race/fuzz/security tests over arbitrary code coverage targets; aim high coverage for core protocol, crypto adapters and sync planner.

---

## 16. TELEMETRY, PRIVACY AND PRODUCT TRUST

- Offline/BYOS mode must work with network blocked except the user's chosen S3 endpoint.
- Telemetry disabled by default. Never collect filenames, key names, remote URLs, bucket names, file contents, or crypto identity material.
- Diagnostic bundle is opt-in and scrubbed; include explicit user preview.
- Document network destinations for each mode. Expose `envport doctor --network` and optional network debug logging that redacts signed headers.
- Avoid unbounded secret retention in process memory and logs; understand that Go memory zeroization is best-effort.
- Publish plain-language threat model and limits: compromised endpoint, key theft, storage rollback, metadata/timing leakage, compromised S3 write credentials.

---

## 17. DOCUMENTATION DELIVERABLES

Produce and keep current:

- `README.md`: value proposition, installation, mode selection, 5-minute workflow, security caveats.
- `docs/QUICKSTART.md`: Linux/Mac BYOS step-by-step with demo fixtures.
- `docs/ARCHITECTURE.md`: actual component boundaries and dependency graph.
- `docs/protocol/v1.md`: binary/envelope formats, versioning, authentication, metadata exposure.
- `docs/SECURITY.md` and `docs/threat-model.md`: guarantees, limits, reporting vulnerabilities.
- `docs/STORAGE_PROVIDERS.md`: R2, AWS S3, MinIO, custom endpoints, feature matrix.
- `docs/KEY_RECOVERY.md`: loss and recovery walkthrough.
- `docs/MIGRATION.md`: starter AES prototype → new age protocol; storage migration.
- `docs/DEVICE_PAIRING.md`: exact trust assumptions, fingerprints and revocation.
- `docs/SYNC_SEMANTICS.md`: base/local/remote and conflict examples.
- `docs/CLI_REFERENCE.md`: each command, flags, errors and JSON schema.
- `docs/DESKTOP.md`: IPC, security, screens and packaging.
- `docs/HOSTED.md`: hosted service deployment (when built).
- `docs/IMPLEMENTATION_STATUS.md`: verified current truth, not aspirational list.
- `docs/adr/*`: architecture decisions and tradeoffs.

Every example must work against the appropriate committed version or be marked **planned**. Include an example credentials policy using placeholders only.

---

## 18. DEVELOPMENT ENVIRONMENT AND TOOLING

### 18.1 Prerequisites

Go toolchain compatible with pinned `go.mod` (starter currently Go 1.23+); Git; make (optional); Docker/Podman for local MinIO tests; Node.js/bun and Rust for later Tauri desktop; R2/AWS account only for live integration tests, not local development.

Pin dependency versions in Go modules and lockfiles. Avoid unpublished or abandoned crypto libraries. Add Dependabot/Renovate only after dependency baseline reviewed.

### 18.2 Suggested Makefile targets

```make
.PHONY: fmt vet test test-race build test-integration lint docs
auto: fmt vet test build
fmt:
	go fmt ./...
vet:
	go vet ./...
test:
	go test ./...
test-race:
	go test -race ./...
build:
	go build -o bin/envport ./cmd/envport
```

`test-integration` should start MinIO and use dedicated test names/prefixes, with explicit cleanup only inside test scope. Do not auto-delete a user's bucket.

### 18.3 Branch/commit convention

Use small commits (`feat(storage): ...`, `fix(restore): ...`, `test(sync): ...`, `docs(protocol): ...`). Each commit should compile and preserve existing passing tests. Breaking vault migrations require a dedicated change log and fixtures.

---

## 19. FULL EXECUTION PLAN — DEPENDENCY-ORDERED MILESTONES

**Do not skip the earlier security foundations to jump into a hosted UI.** Each milestone produces actual code + tests + docs + an updated implementation status.

### M0 — Audit and guardrails

- [ ] Inspect existing repository, commands, encryption, storage formats and tests.
- [ ] Record exact baseline and caveats in `docs/IMPLEMENTATION_STATUS.md`.
- [ ] Set up lint/static security checks, CI matrix, synthetic fixture repo.
- [ ] Establish `docs/adr/` and initial threat model.
- [ ] Verify starter local backup/restore across distinct paths.

**Exit:** existing prototype behavior reproducible; no regression, safety limitations documented.

### M1 — Domain and modular application core

- [ ] Introduce typed owner/device/vault/project/file/snapshot/storage IDs.
- [ ] Define object-store, vault-repository, credential-store, project-mapper and plan/execution interfaces.
- [ ] Separate CLI parsing from business logic; add structured typed errors.
- [ ] Add versioned settings and initial SQLite migrations.
- [ ] Build deterministic `PlanBackup`/`PlanRestore` contracts.

**Exit:** current CLI uses application services; domain code has no CLI/provider imports.

### M2 — Protocol, age encryption and recovery

- [ ] Write `docs/protocol/v1.md` and golden protocol fixtures.
- [ ] Introduce age cryptography and per-vault keys/envelopes.
- [ ] Implement encrypted recovery bundle and tested import/verify.
- [ ] Implement authenticated, encrypted manifests and immutable blobs.
- [ ] Provide safe starter AES legacy migration and rollback plan.
- [ ] Add tampering/wrong-key/corruption tests.

**Exit:** fresh device can decrypt a portable encrypted local vault via recovery without relying on source machine.

### M3 — Discovery, tracking and safe restore

- [ ] Robust scan exclusions, size limits, symlinks, worktrees, nested repos.
- [ ] Canonical Git remote and explicit no-remote project mapping.
- [ ] Repository-relative file IDs; encrypted metadata.
- [ ] Preview restore plan with precise path mapping and conflicts.
- [ ] Atomic, race-aware, no-overwrite restore implementation for all platforms.
- [ ] Fuzz/path traversal tests and byte-for-byte round trips.

**Exit:** Linux-layout fixture restores into Mac-layout fixture without clobbering existing files.

### M4 — Generic S3 adapter and R2

- [ ] AWS SDK v2 with configurable endpoint, region, addressing, credentials and TLS policy.
- [ ] Secure credential storage references; provider profiles.
- [ ] R2, AWS S3, MinIO connection presets built upon same adapter.
- [ ] Capability detection and safe conditional-`PutObject` implementation.
- [ ] Retry, typed errors, streaming, cancellation, pagination and timeouts.
- [ ] MinIO CI integration; optional real R2/AWS end-to-end tests.
- [ ] `storage add/test/list` commands and docs.

**Exit:** encrypted object round-trip and atomic CAS verified against live R2 test bucket (if credentials provided), without uploading plaintext.

### M5 — Crash-safe snapshot commits

- [ ] Immutable blob/manifest upload and authenticated current-head reference.
- [ ] Implement conditional creation and CAS replacement.
- [ ] Local journaling and uncertain-outcome reconciliation.
- [ ] Trusted checkpoints and explicit rollback limitation.
- [ ] Snapshot list/history and restore by snapshot.
- [ ] Collision, crash, retry and orphan handling tests.

**Exit:** concurrent head writes never silently overwrite each other; recoverable commit state.

### M6 — Multi-device sync and conflicts

- [ ] Durable per-device base/local/remote state.
- [ ] Three-way sync planner and per-file conflict model.
- [ ] Replan on CAS failure; no last-writer-wins.
- [ ] Explicit tombstones; missing local files ignored for deletion.
- [ ] Safe key-name-only diff, no value leaks by default.
- [ ] Manual sync first; optional watcher afterward.
- [ ] Parallel-device and offline-edit E2E suite.

**Exit:** Linux and Mac can alternate changes, detect true conflicts, and preserve history.

### M7 — Device pairing and multiple vaults

- [ ] Per-device keypair persistence and device identifiers.
- [ ] Secure join request, authenticated approval, encrypted grant.
- [ ] Replay prevention, expiry, trusted fingerprint confirmation.
- [ ] Recovery join fallback.
- [ ] Multiple independent vaults, storage profiles, device memberships.
- [ ] Design key epochs/revocation; implement only with honest documented semantics.

**Exit:** Mac authorized from Linux with no shared plaintext private key over messaging; vault isolation tests pass.

### M8 — Developer experience and CLI beta

- [ ] `status`, `doctor`, `history`, `diff`, `devices`, `storage`, JSON output.
- [ ] Helpful error handling, docs, migration guidance and restore previews.
- [ ] Cross-platform release builds and checksums via GoReleaser.
- [ ] Install instructions, package distribution strategy, example demo recording.
- [ ] Run full offline, MinIO, R2, AWS and OS matrix where credentials/platforms available.

**Exit:** publicly usable BYOS CLI beta with recovery and strong warnings for unfinished security properties.

### M9 — Desktop (Tauri + Svelte 5)

- [ ] Document stable Go engine API with generated TypeScript client schema.
- [ ] Add authenticated local IPC service and progress subscriptions.
- [ ] Implement onboarding, storage, projects, vaults, sync, conflict, restore, devices and history screens.
- [ ] Keyboard-accessible states, errors, loading, cancellation and redaction.
- [ ] Package Go sidecar into Tauri builds with version handshake.
- [ ] OS-level security audit of IPC, bundled binaries and update process.

**Exit:** desktop and CLI operate on the exact same vault/protocol; no sync logic duplicated in JS.

### M10 — Optional hosted accounts and managed R2

- [ ] Hosted auth, Postgres schema, vault/device membership and quotas.
- [ ] Deny-by-default authorization tests for every endpoint.
- [ ] Safe managed S3 access through API/proxy/presigning while preserving conditional semantics.
- [ ] Distinguish hosted-managed storage and direct BYOS clearly.
- [ ] Audit logs, rate limiting, abuse defense, deployment/monitoring/runbooks.
- [ ] Independent hosted-to-BYOS migration and account deletion tests.

**Exit:** two unrelated hosted users cannot access each other's vaults; server sees no vault plaintext, hosted BYOS remains direct.

### M11 — Production readiness, release and operations

- [ ] Independent security review/threat-model closure.
- [ ] Backup/restore and lost-device disaster drills.
- [ ] Protocol compatibility golden tests against previous releases.
- [ ] Full signed desktop packaging as permitted by external signing accounts.
- [ ] Dependency vulnerability scanning and public vulnerability reporting policy.
- [ ] Versioned changelog, release notes, docs site, support issue templates.
- [ ] Explicitly labeled GA support matrix, provider limitations, pricing and privacy policy (if hosted).

**Exit:** all §22 release gates pass; publish tagged release and executable install steps.

### Suggested sequencing

Milestones M0–M3 establish safe local-first core; M4–M6 unlock R2-backed multi-device sync; M7–M8 make it a complete CLI product; M9 adds desktop; M10 adds optional SaaS; M11 hardens final release. Timelines are estimates based on actual staffing and security findings, not contractual dates. No external credentials? Complete the MinIO/local implementation and mark live R2 tests blocked.

---

## 20. AI AGENT TASK EXECUTION TEMPLATE

For each milestone create `docs/tasks/MX.md` with:

```markdown
# Milestone MX: <title>
## Baseline
- Current implemented behavior:
- Relevant files:
- Dependencies:
## Acceptance criteria
- [ ] User-visible behavior verified
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Security cases covered
- [ ] Documentation updated
## Implementation tasks
1. ...
2. ...
## Commands run and results
...
## Known blockers and risk
...
## Handoff / next step
...
```

### Agent behavior prompt (can paste into coding-agent instructions)

> You are implementing EnvPort using `PROJECT_MASTER_GUIDE.md` as the source of truth. First read the repository and report verified status. Work on the earliest incomplete milestone, implement the full coherent vertical slice, run its tests and security checks, fix failures, update docs/status, and supply a concise change summary. Do not claim cloud deployments or cross-device verification without actually performing them. Do not print or commit secrets. Preserve legacy backups. Prefer secure, boring, testable architecture over mock features or visual polish. If an external credential is unavailable, mark the live test blocked and proceed with equivalent local MinIO tests. Continue milestone by milestone until blocked or complete, without inventing results.

### Agent checkpoint rules

- If a test fails, fix it before adding the next major component.
- If a feature would reduce security guarantees, write an ADR and keep the weaker mode disabled by default.
- If a design decision affects remote data format, require golden fixture and migration strategy.
- If APIs change, update CLI/desktop clients and backwards-compatibility tests.
- If a dependent external service is missing, keep an honest feature flag/state; never simulate a green status.
- Do not hardcode user identifiers, repository URLs, access keys, deployment endpoints or paths except test fixtures.

---

## 21. DEVELOPMENT/RELEASE PIPELINE

### 21.1 GitHub workflows

1. PR validation: Go format/vet/test/race, static checks, secret scan, dependency audit.
2. S3 integration: MinIO ephemeral container, conditional-concurrency test.
3. Optional external integration: manually triggered R2/AWS test buckets; dedicated scoped CI secrets, cleanup only under controlled prefix.
4. Matrix: Linux/macOS/Windows build and E2E where runners permit.
5. Release: GoReleaser archives, checksums, SBOM, signed artifacts when configured; desktop installers later.

### 21.2 Release channels

- `0.1.x` experimental local encrypted backups (do not market as production safe).
- `0.2.x` generic S3 + R2 and recovery beta.
- `0.3.x` safe multi-device synchronization + pairing beta.
- `0.5.x` desktop preview when core stable.
- `1.0.0` only after comprehensive security and recovery gates.

Version numbers are proposed milestones, not a guarantee all features are shipped at each tag. Publish implementation status per release.

### 21.3 Operations and incident response

Provide guides for key loss, bucket deletion, ransomware, compromised device, compromised S3 credentials, corrupted manifest, stuck CAS conflicts, partial migrations, failed update and privacy report. Keep a clearly documented process for rotating credentials without losing vault-key access.

---

## 22. NON-NEGOTIABLE RELEASE ACCEPTANCE MATRIX

| Gate | Must pass before 1.0 |
|---|---|
| Fresh Linux→Mac restore using approved pairing OR recovery | Verified with different checkout paths |
| Restore correctness | Byte-for-byte verified across representative fixtures |
| Existing local files | Never overwritten without explicit safe action |
| Concurrent commits | One CAS winner; loser re-plans, no silent data loss |
| Recovery | Clean machine can recover with documented prerequisites |
| Key loss | Clear, tested and accurately explained failure behavior |
| Multi-user isolation | Vault cryptography + hosted membership tests (if hosted shipped) |
| BYOS privacy | Network trace confirms no EnvPort-server traffic in standalone BYOS |
| S3 compliance | Live compatibility verification and unsupported-feature fallback |
| Credential safety | No secrets in config, logs, crash reports or CI artifacts |
| Filesystem safety | Traversal, symlink/junction and race tests pass |
| Corruption/tampering | Authentication rejection and recovery options |
| Migration | Existing supported backup format preserved or safely converted |
| History | Verified old-snapshot restore and safe prune dry-run |
| Cross-platform | Linux, macOS, Windows supported release path tested |
| Desktop/core consistency | Same protocol/engine, authenticated local IPC |
| Documentation | Setup, threat model, recovery and troubleshooting current |
| Licensing | Third-party compliance and appropriate open-source license |

**A feature is only complete when its tests, documentation, and safety checks are complete.**

---

## 23. DOCUMENTED EXTERNAL REFERENCES

Use official documentation, and re-verify details when implementing:

- Cloudflare R2 S3 API and support matrix: https://developers.cloudflare.com/r2/api/s3/api/
- Cloudflare R2 extensions / conditional writes: https://developers.cloudflare.com/r2/api/s3/extensions/
- Cloudflare R2 S3 endpoint/get started: https://developers.cloudflare.com/r2/get-started/s3/
- AWS S3 conditional writes: https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html
- AWS SDK for Go v2: https://docs.aws.amazon.com/sdk-for-go/v2/developer-guide/getting-started.html
- age library: https://pkg.go.dev/filippo.io/age
- Cobra: https://cobra.dev/
- SQLite: https://www.sqlite.org/docs.html
- Tauri: https://v2.tauri.app/
- Svelte: https://svelte.dev/docs/svelte/overview
- Go security: https://go.dev/security/

Never treat the reference list as proof of current compatibility across arbitrary providers; CI/provider testing decides that.

---

## 24. FINAL DELIVERY CHECKLIST AND USER HANDOFF

When the project is complete, provide:

- [ ] Public/source repository with meaningful commits and tags.
- [ ] Installable CLI binaries for Linux, macOS and Windows.
- [ ] Desktop builds when that phase is included, with clearly documented signing status.
- [ ] Passing tests and per-provider compatibility report.
- [ ] Official BYOS R2 setup guide and a full Linux→Mac migration tutorial.
- [ ] Optional hosted deployment guide and isolated managed-storage configuration, if implemented.
- [ ] Protocol spec, migration tooling, threat model and recovery runbook.
- [ ] Screenshots/demo using fake fixture repositories and values only.
- [ ] Changelog, license, contribution guide, security policy and issue templates.
- [ ] `docs/IMPLEMENTATION_STATUS.md` with evidence of what is really shipped.

### Immediate next action for the coding agent

**Begin with M0**: run the starter's tests, inspect file formats and current CLI behavior, record baseline, build synthetic fixtures, then complete M1. Do not begin by scaffolding an unrelated React dashboard or deploying an empty cloud backend. The first major proof is secure local recovery and the second is an R2-backed, conflict-safe Linux-to-Mac transfer.

---

*This file is intentionally comprehensive: it serves as the engineering contract, staged execution plan, acceptance checklist, and handoff specification for an AI agent developing EnvPort from the starter repository through a full release.*
