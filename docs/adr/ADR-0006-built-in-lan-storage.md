# ADR-0006: built-in LAN storage with mutual TLS

Accepted 2026-10-28, explicitly requested by the user.

Add `envport serve` and a `lan` ObjectStore adapter. Reuse client encryption, snapshots, three-way planning, recovery and conditional commit logic. The host owns a native-local SQLite ciphertext object store and a separate namespace/client authorization registry; it has no vault decryption identities and does not initialize application state. This is independent of optional hosted accounts and desktop IPC.

Use standard-library TLS 1.3 with independently generated Ed25519 client/server certificates. Server private identity and client private credentials are age-scrypt encrypted at rest using separate local unlock boundaries. Client keys originate on clients. Public request fingerprints are confirmed by the host administrator; signed public connection documents bind the request, namespace, role and endpoint, with an independently confirmed server certificate fingerprint. Client trust uses a dedicated root pool plus exact certificate verification; system/public CAs and InsecureSkipVerify are not used.

Keep enrollment explicit through public files rather than exposing an unauthenticated enrollment endpoint. Literal private IP endpoints avoid DNS/discovery/relay dependencies; the client transport disables proxies/redirects and dials only its selected endpoint. Public IPs, HTTP and wildcard listeners are rejected. The CLI defaults to loopback until the operator explicitly binds a LAN address.

Authorization is checked per namespace on every request, including established TLS connections. Read-only grants cannot write/delete; revocation affects subsequent requests and persists across restarts. It does not revoke vault decryption or copied data. A new request/key is required to re-enroll a revoked client. Namespaces are storage-access boundaries; multiple vaults within one namespace retain independent decryption keys.

Object keys are prefixed server-side by namespace; users cannot provide filesystem paths. Atomic conditional writes delegate to SQLite operations, never GET-then-unconditional-PUT. The encrypted vault v1 format and old adapters are unchanged; no vault migration is required. The independent LAN wire protocol is versioned in docs/protocol/lan-v1.md.

Bound requests, bodies, connection counts, active object operations and timeouts; sanitize errors and omit HTTP access/TLS diagnostic logging. Capability tests and real two-client CLI integration validate concurrency, recovery, isolation, revocation and no-cloud operation. Local malicious administrators, storage rollback, denial of service, native Windows ACL support, automatic renewal and independent review remain explicit limits.
