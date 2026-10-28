# Local validation evidence

Date: 2026-10-28. Linux, Go 1.27.3-X:nodwarf5, final module minimum Go 1.26. All fixtures are synthetic. No GitHub workflow, live R2/AWS bucket, actual macOS/Windows runtime or production service was exercised.

The task used isolated temporary module/compiler caches; equivalent developer commands below use your normal Go cache. Build archives are unsigned experimental artifacts under `dist/0.1.0-dev`.

| Command / scenario | Result |
|---|---|
| Original extracted starter `go test ./...`, `go vet ./...` | Passed |
| Starter build `go build -buildvcs=false ...` and original CLI backup/restore across distinct checkouts | Passed; two files compared byte-for-byte with cmp |
| `make check` | Passed: gofmt check, go vet and all local unit/integration tests; opt-in provider tests skip without explicit configuration |
| `staticcheck ./...` (v0.8.2) | Passed |
| `govulncheck -show verbose ./...` (v1.9.0) | Exit 0, zero affected symbols/imported packages; see dependency-only advisory below |
| `python3 scripts/check_secrets.py` | Passed conservative guard; intentionally public golden identity explicitly allowlisted |
| `make smoke` | Passed actual CLI subprocesses across three isolated installations: recovery, exact bytes, mappings, explicit preimages, conflicts, history, doctor and signed pairing |
| `MINIO_BINARY=... make test-minio` | Passed real pinned server: object/CAS/pagination/cancellation/0–2 MiB cases plus encrypted backup/recovery/restore and object leakage inspection |
| `go test -race ./internal/restore -count=1` | Passed including concurrent atomic directory/symlink swaps; no writes escaped the approved root |
| `go test ./internal/discovery -run '^$' -fuzz FuzzCanonicalRemote -fuzztime=3s -parallel=2` | Passed, 198,482 executions in recorded run |
| `go test ./internal/sync -run '^$' -fuzz FuzzPlanner -fuzztime=3s -parallel=2` | Passed, 296,683 executions in recorded run |
| Full `go test -race ./...` | Passed full suite; application package 256.876 seconds under instrumentation |
| `make release-local` | Passed patched-graph builds for Linux amd64/arm64, macOS amd64/arm64, Windows amd64; final archives contain documentation, build info, SBOM and checksums |

## Corrections during validation

An initial vulnerability scan identified AWS SDK advisory GO-2026-5764. Updated/pinned the graph (S3 v1.114.6, EventStream v1.7.25, AWS config v1.33.12, age v1.3.2, SQLite v1.61.0 and supporting packages); the final scanner reports no reachable vulnerability. The remaining module-only advisory is [GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932) for unmaintained `golang.org/x/crypto/openpgp`, with no upstream fix. EnvPort does not import that package; age uses other maintained packages from the module. This is disclosed rather than represented as an entirely advisory-free graph.

Old staticcheck/govulncheck versions could not parse the installed Go toolchain; replaced them with pinned compatible versions. Failed old-tool runs were not counted as passing scans.

Temporary-filesystem quota caused one race/build attempt to fail. Removed only task-generated MinIO source caches and placed release compiler scratch/cache in the ignored `.envport-testdata` directory. Those failed attempts were not passing validation. Race instrumentation made cryptographic test setup exceed an incorrectly scoped test timeout; the timeout now bounds the actual concurrent commit phase rather than password-KDF fixture setup.

Additional full-snapshot concurrency/history tests caught ancestor Git metadata expanding a selected discovery root. Fixed and regression-tested the root authority boundary and independent subdirectory identity. Exactly one snapshot writer now wins the test's real CAS race, and the loser replans into a conflict. Historical restore after tombstoning preserves exact original bytes and retention traces all required blobs.

## Scope of evidence

MinIO was built from official pinned community source revision `07c3a429bfed`; failed registry pulls were not substituted with a mock. The reproducible runner uses synthetic credentials and starts/terminates its own local server, creates isolated random buckets, and never touches a user's bucket. The separate manual fixture server was stopped after testing.

The local recovery layout labeled Linux/Mac in fixtures means **different paths on isolated Linux installations**, not actual macOS runtime verification. Cross-compilation is not an OS security/runtime acceptance result. Signing/notarization, independent security review, real R2/AWS and final license/distribution audit remain release gates. The authored optional workflow/test does not constitute an executed live-provider test.

## Built-in LAN implementation (same date)

After the explicit request for a built-in local-network-only backend, added the mutual-TLS host, namespace registry, signed public enrollment and native LAN ObjectStore adapter without changing the encrypted vault v1 format or runtime dependencies.

- Baseline `go test ./...` passed before modification.
- Updated `make check` passed, including all original engine/golden/AES-recovery cases and LAN unit/adapter/CLI tests.
- Staticcheck v0.8.2 passed after the LAN implementation.
- Govulncheck v1.9.0 passed with zero reachable/imported-package advisories; the previously documented unimported OpenPGP module advisory remains.
- Targeted `go test -race ./internal/lan ./internal/storage/lan ./internal/transport/cli` passed (LAN adapter package 102.219s in that recorded run). The subsequent full `go test -race ./...` passed, including final connection-limit/shutdown and revoked-request replay regressions (application 288.470s, LAN adapter 169.410s).
- `make smoke` passed the original standalone offline workflow unchanged.
- `make smoke-lan` passed actual host and independent client processes: encrypted recovery, byte-for-byte restore, no hidden fallback, default no-overwrite/preimages, simultaneous client backup with exactly one successful commit, conflict replanning/history, host outage, restart persistence, persisted revocation, and `--no-network` refusal. Deliberately unusable HTTP/HTTPS proxy settings were ignored by the LAN transport as intended.
- Adapter cases passed real concurrent CAS, zero/binary/large objects, pagination, cancellation, namespace/foreign cursor isolation, read-only permissions, next-request revocation on an established connection, request replay refusal, wrong server/client identities, modified connection documents, expired/bounded requests, encrypted local credentials, malformed/duplicate conditions, oversized chunked bodies and missing TLS certificates. Host initialization rejects symlink ancestors before creating any outside directories.
- The original real MinIO integration was rerun and passed: adapter 1.817s; encrypted recovery workflow 5.475s.
- All five unsigned cross-platform targets rebuilt with the built-in LAN commands. Archive contents and SHA256SUMS are verified after packaging. Cross-compilation remains distinct from native platform runtime verification.
- No persistent LAN listener or user-data configuration was installed. All fixture servers use isolated loopback ports and are terminated by the runner. A physical LAN/NAS and native macOS/Windows runtime matrix remain unverified.

LAN source: `internal/lan`, `internal/storage/lan`, `internal/transport/cli/lan.go`. Setup/protocol: `docs/LAN.md`, `docs/protocol/lan-v1.md`. CI invokes the reproducible `make smoke-lan`; authored CI is not a claim of a GitHub run.
