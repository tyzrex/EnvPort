# Architecture and security boundaries

## Domain

Account (optional hosted identity) -> vault membership -> vault -> project -> relative files -> immutable snapshots. Device identity is independent of user identity and repository identity. Every vault has a separate encryption boundary. A named vault can have a user-owned storage connection or EnvPort-managed storage.

## Product modes

- **Standalone BYOS:** local credential provider -> directly connected S3-compatible bucket. No EnvPort API involvement. Supports offline filesystem mode.
- **Managed cloud (future):** users authenticated to hosted control plane; account membership gates access to R2 objects, but client encrypts all project data and manifests.

## Provider contract

`storage.Store` provides object Get, Put (with conditional preconditions), List and Delete. A multi-writer backend MUST implement real atomic compare-and-swap for mutable head references. Never emulate with GET followed by unconditional PUT. S3 adapter will support custom endpoint, region, path-style addressing, SigV4 and credential chain. Verify conditional PUT semantics using an active capability test per provider. Reject multi-writer mode if unsupported.

## Future protocol

Random vault IDs and opaque object keys. Immutable encrypted file blobs and manifests. Small mutable snapshot-head pointer updated conditionally. Three-way comparison of base/local/remote to detect conflicting changes. Private repository names and relative paths only inside encrypted manifests. Explicit tombstones, history retention, no silent deletion. Device-specific filesystem paths never need to be uploaded. Key envelopes allow per-device access; revocation does not revoke previously captured plaintext or past keys.

## Threat model

No plaintext to storage provider, no secrets in application logs, refuse symlink escapes and path traversal, no silent overwrites, no authenticated-decryption bypass. Rollback prevention needs independently trusted checkpoints; encrypted snapshots alone do not prevent malicious replacement with old valid versions. Object store access is not decryption access.

## Current limitations

This initial prototype only supports one local vault on one device, with AES-GCM local snapshots. Storage abstraction and Go package boundaries are groundwork, not claims of implemented multi-user or S3 features. Restore maps Git repositories independent of `.env` files, but projects without a Git remote still need explicit mapping. Harden restoration against symlink races with directory-handle based filesystem APIs before using untrusted manifests in production.
