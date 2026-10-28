# ADR-0002: age identities, encrypted references and portable recovery

Accepted 2026-10-28; independent review remains outstanding.
Later decisions: ADR-0003 supersedes the initial missing-starter limitation; ADR-0004 records the patched dependencies and Go 1.26 minimum.


Each vault has a random ID and independent age X25519 identity. The identity is the epoch-one shared vault decryption secret, an established age identity rather than a custom derived cipher. Encrypt each blob, manifest and head reference using age to this identity. Random object IDs hide project names and plaintext hashes from object keys. Local private identities are age-scrypt encrypted under an explicit unlock passphrase; exported recovery uses an independent passphrase and is decrypted for verification before backup is enabled.

The provider sees lengths, access patterns and opaque object relationships. Sharing a root identity does not authenticate individual authors, and possession of a root key cannot be revoked retroactively. Signing, per-device grants and future key epochs require additional contracts; no current claim of cryptographic device revocation is made. Account authentication and storage access remain separate from vault decryption.

AES starter snapshots cannot be decoded without the original format and fixtures. Never reinterpret their bytes as age. Preserve originals and use a trusted old client for local export followed by verified import into a new vault.
