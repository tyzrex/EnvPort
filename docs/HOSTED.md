# Hosted service status

**Not implemented; optional later milestone.** There is no hosted account API, cloud control-plane server, Postgres schema, managed R2 service, billing, hosted deployment or hosted UI to configure. Standalone offline/BYOS has no dependency on these services and sends no requests to an EnvPort service.

The guide's hosted mode requires deny-by-default tenant/vault authorization on every storage/grant endpoint, scoped expiring object access preserving CAS conditions, quotas/rate limits, session controls, privacy-preserving audit events, operational runbooks and isolation/security tests. Servers must never receive vault identities, plaintext .env content or direct-BYOS credentials. Storage credentials, account identity and decryption grants must remain independent. Do not deploy a placeholder server as a working hosted product.

The shipped built-in LAN host is a separate standalone ciphertext backend. It requires neither this proposed hosted service nor an EnvPort account. See [LAN.md](LAN.md).
