# Desktop status and boundary

**Not implemented.** No Tauri app, Svelte UI, desktop sidecar or local engine IPC listener is shipped. The built-in LAN ciphertext-storage host is a separate backend, not desktop IPC. The guide places desktop after a stable, verified engine; live provider and platform/security acceptance still needs to pass before extending the exposed attack surface. CLI development did not substitute a mock dashboard for recovery correctness.

The application engine is independent of Cobra and the S3 SDK. A future desktop adapter must call these services rather than reimplement crypto/sync in JavaScript. Plans/results are already serializable with content hashes, tokens and bytes omitted from normal output. This is not yet a stable public IPC API.

Required next work: explicit versioned API schema, permission-limited Unix socket / ACL-protected Windows pipe, OS-identity/ephemeral-capability authentication, cancellation/progress, denied unauthorized-process tests, generated TypeScript client, then Tauri/Svelte screens and packaged version-handshaking Go sidecar. Never expose an unauthenticated localhost HTTP endpoint. Platform installers/signing/notarization require actual platform verification and external signing accounts.
