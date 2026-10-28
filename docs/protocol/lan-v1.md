# LAN object-store protocol v1

This is an experimental transport wrapping the existing encrypted vault v1. It does not change age payloads/manifests/references or their logical keys. Existing local/S3 vault objects are not reinterpreted or rewritten.

## Identity and enrollment

`server.json` records version, private-IP HTTPS endpoint, server certificate, certificate SHA-256 fingerprint and default namespace. `server-key.age` encrypts version/certificate/PKCS8 private-key JSON using age scrypt. The host's independent `registry.db` schema version is one. It stores namespace ID/name and `(namespace, client-certificate fingerprint, read_only, revoked)` grants; unknown registry versions are refused.

`storage lan request` creates a self-signed Ed25519 client-auth certificate and private key. The private identity remains only in the local age-scrypt `lan-client-<request-id>.age` envelope. Public request JSON contains version 1, random 32-hex request ID, public certificate and UTC expiration (30 minutes). Its fingerprint is SHA-256 of the Go JSON encoding of those fields; the administrator confirms it out of band. The self-signed certificate plus later TLS proves possession of the private key. Request IDs/expiry are bound by fingerprint confirmation, not a separate request signature.

Host authorization signs connection JSON with the Ed25519 TLS private key, covering version, complete request, endpoint, namespace, server certificate and read-only role, with the signature field omitted. The signature is base64 JSON bytes. Import requires an independently trusted server fingerprint, verifies self-signature/lifetime/purpose and grant signature, checks request binding/expiry, and verifies the requesting installation has the matching encrypted private credential. Clock skew is bounded; requests more than 35 minutes in the verifier's future are refused.

Connection files contain public trust material and sensitive connection metadata, not vault keys or TLS private keys. Signature encoding is the exact Go struct JSON contract; future clients must implement it byte-for-byte. Unknown fields, trailing JSON, versions, invalid IDs and oversized control documents (32 KiB) are rejected. Local profile options contain only version, endpoint, namespace, server certificate, credential reference and a tested-capabilities flag.

## TLS and authorization

TLS 1.3 is mandatory. Clients validate the selected server using a dedicated root pool, endpoint IP/SAN and exact certificate identity. No public CA/DNS validation service, proxy, redirect or relay is used. Server client authentication requires exactly one valid self-signed Ed25519 client-auth certificate. Every HTTP request additionally checks certificate validity and the persisted namespace grant. TLS sessions do not cache authorization; revoked clients lose subsequent requests on already established connections. In-flight authorized operations may complete.

Every operation requires `X-EnvPort-Protocol: 1`. Browser Origin/Cookie requests are denied. Missing/unknown/expired client identity is denied; paths are not served before namespace authorization. Host administration (namespaces, approvals, revocation) is local CLI only, not remotely exposed by the storage API.

## Operations

Base: `/lan/v1/namespaces/<32-hex-id>`.

| Method/path | Request/response |
|---|---|
| GET `/capabilities` | `{version:1,capabilities:{...}}`, authenticated and namespace-scoped |
| GET `/objects?key=...` | Binary opaque object; strong quoted ETag, exact Content-Length |
| HEAD `/objects?key=...` | Same ETag/length without a response body |
| PUT `/objects?key=...` | Binary object; conditional headers below; ETag and `X-EnvPort-Object-Size` returned |
| DELETE `/objects?key=...` | Delete inside authorized namespace; read-write grant required |
| GET `/objects?prefix=...&cursor=...&limit=N` | `{version:1,objects:[{key,etag,size}],cursor?}`, 1–1000 entries |

PUT condition modes are explicit: `If-None-Match: *` creates only; `If-Match: "opaque-etag"` replaces only the matching version; `X-EnvPort-Write-Mode: unconditional` explicitly selects unconditional mode. Missing, duplicate, mixed or malformed conditions are rejected with 428. The application engine uses conditional creation/replacement for commits; it never falls back to unconditional head updates. Stale tokens yield 412. The active capability probe actually exercises rejected stale tokens and a two-writer CAS race.

The host prefixes each validated logical object key with `namespaces/<authorized-id>/` inside its local object database. Clients cannot choose/escape this prefix. Listed keys are stripped back to logical keys; cursors remain opaque and are bound to the authorized namespace. Paths with traversal, foreign cursors, duplicate query parameters or unknown list parameters are refused. No filesystem path is derived from remote keys.

ETags reflect ciphertext SHA-256 from the existing SQLite adapter, quoted on the wire. Raw plaintext hashes remain inside encrypted manifests. The storage endpoint treats bodies as opaque; the audited client engine performs encryption. Synthetic capability probes intentionally use nonsecret plaintext fixtures. The server cannot prove a custom client encrypted its own submitted bytes.

Success uses 200/204. Errors return fixed codes without request paths, credentials or raw backend errors: 400 invalid input; 401 missing identity; 403 denied; 404 missing; 412 stale condition; 413 excessive object; 428 missing/invalid condition; 429 busy; 503 storage unavailable. Object size is capped at 16 MiB, list responses at a client-accepted 2 MiB, headers 16 KiB, open connections 32, simultaneous authorized object operations 8. Read/write/header/idle/handshake timeouts are bounded. No automatic write retry can replace a newer head; uncertain outcomes use the existing application reconciliation rules.

## Compatibility and limits

LAN storage access is independent of vault decryption access. A compromised/revoked transport identity does not revoke copied vault keys or data. Namespace administrators can deny service/delete/roll back ciphertext. Existing authenticated ancestry/checkpoint limits apply, including the first-join freshness limitation. TLS certificates expire after one year; automatic renewal/discovery/quotas are not implemented. Native cross-platform security review and an independent security audit remain required before production support claims.
