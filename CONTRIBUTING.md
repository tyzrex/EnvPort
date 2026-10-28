# Contributing

Read PROJECT_MASTER_GUIDE.md, docs/IMPLEMENTATION_STATUS.md, docs/ARCHITECTURE.md and docs/threat-model.md first. Keep changes in vertical slices with evidence; avoid UI work that obscures unfinished core security guarantees.

Use Go 1.26+ (current CI 1.27.3), Git and Python 3 for developer scripts. `make check`, `make test-race`, `make smoke`, `make smoke-lan`, `make lint`, `make security` are the core checks. `make test-minio` requires the pinned external MinIO fixture built from source or an explicit MINIO_BINARY; it never uses an existing user bucket. All tests use synthetic data. Do not run broad personal-directory scans or use existing production .env files.

Domain/application code must remain independent of CLI and concrete provider SDKs. Add behavioral/security tests for high-risk engine changes. Update protocol golden fixtures only as a deliberate compatibility decision. Preserve supported encrypted history and legacy originals. New migrations must cover reopen, older-version upgrade and unknown-newer-version refusal.

Record design decisions under docs/adr, milestone evidence under docs/tasks, and keep CLI docs and status accurate. Avoid claiming a cloud deployment, new provider compatibility or platform runtime verification without actual evidence.

Use focused Conventional Commit messages (`feat:`, `fix:`, `test:`, `docs:`, `ci:`, `build:`). Each implementation commit should build and pass its relevant tests. Preserve existing history; do not amend or rebase someone else's work without agreement. Publish branches or create release tags only as part of explicitly authorized release work.

Generated binaries, release archives, private vault/state databases, encrypted credential exports and personal tool configuration are ignored. The only intentionally versioned key material is clearly labeled synthetic compatibility data under `testdata`; never reuse those test keys. `.gitattributes` preserves encrypted/binary fixture bytes and normalizes source/documentation line endings.
