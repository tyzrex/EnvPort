# ADR-0004: patched dependency graph and toolchain

Accepted 2026-10-28.

The initial dependency baseline triggered Go vulnerability advisory GO-2026-5764 in AWS SDK EventStream/S3. Update the direct graph to patched current versions and pin the resolved graph in go.mod/go.sum; rerun real MinIO, cryptographic golden fixtures, migration, race tests, static analysis and vulnerability analysis. New dependency minimum requires Go 1.26; local/CI checks use Go 1.27.3.

Older staticcheck v0.6.1 and govulncheck v1.1.4 could not parse this toolchain's compiler/AST output. Replace development tools with pinned staticcheck v0.8.2 and govulncheck v1.9.0. Do not treat their earlier errors as passing checks. These tools are not application runtime dependencies.
