# ADR-0001: bootstrap a verifiable standalone engine

Accepted 2026-10-28.
Later decisions: ADR-0003 supersedes the initial missing-starter limitation; ADR-0004 records the patched dependencies and Go 1.26 minimum.


The expected AES starter is absent. Implement a new experimental v1 age protocol rather than inventing legacy compatibility. Keep CLI concerns separate from the engine, and defer desktop and hosted infrastructure until engine security gates pass. Use Go 1.25+ for descriptor-confined filesystem operations. Use migration-managed modernc SQLite for local state and local object-store CAS, with AWS SDK v2 as an independently injected adapter.

Do not publish, deploy, use personal secret files or create hosted accounts during development. Only synthetic fixtures are exercised. External provider tests require dedicated scoped credentials. The implementation status document distinguishes implemented behavior, tested behavior and release blockers.
