# Built-in LAN vault

EnvPort includes its own ciphertext-storage server and `lan` adapter. No S3 service, AWS account, cloud storage, public certificate authority, telemetry, DNS discovery or internet relay is required. A NAS, mini PC or one of your computers can host it. The host must be online when clients transfer data; the clients do not have to be online at the same time.

The client encrypts vault payloads and metadata before sending them. The host receives opaque encrypted objects and enforces namespace-scoped storage access. Vault decryption keys stay on authorized clients. TLS authorization and vault decryption are **separate**: approving a storage client does not give it the vault key.

## Start the host

Build/install the CLI first. The current Linux runtime requires kernel 5.6+, including on NAS hosts; native macOS/Windows support has the limitations listed in the implementation status.

Use an actual private IP belonging to the host; reserve it in DHCP if needed. The endpoint must be an HTTPS literal private/loopback/link-local IP with an explicit port. Hostnames, public IPs, HTTP, wildcard listening and redirects are rejected. IPv6 zone identifiers are not supported; use private IPv4 or routable ULA IPv6. The examples use `192.168.1.10`; replace it with your host's address.

```bash
# Run on the NAS/host. Choose an independent host unlock passphrase when prompted.
envport serve init --data ~/.local/state/envport-lan \
  --endpoint https://192.168.1.10:7443
```

Keep the printed `server_fingerprint` and `default_namespace`. These are public identifiers, not decryption keys. The `personal` namespace is created automatically. Start the server in a dedicated terminal:

```bash
envport serve --data ~/.local/state/envport-lan --listen 192.168.1.10:7443
```

The default listener is loopback `127.0.0.1:7443`; explicitly choose your private IP for other computers to connect. Allow the chosen TCP port through the host firewall for your trusted LAN. No router port forwarding is needed. Stop with Ctrl-C; shutdown closes the listener and drains requests. The server does not initialize a client vault database or acquire any vault decryption key.

Noninteractive service startup can receive `ENVPORT_SERVER_PASSPHRASE` from a protected secret source. Do not put real passphrases in command arguments, shell history, configuration JSON or logs. The TLS private key is age-scrypt encrypted on disk in `server-key.age`; all host state lives in a private 0700 directory.

## Authorize each client

On the new client:

```bash
envport init --lan
envport storage lan request --output /private/laptop.request.json
```

Choose the client installation unlock passphrase when prompted. Its private TLS key is generated on that client and saved only in a local encrypted envelope. The request file contains public certificate material and a 30-minute request expiry. It prints `request_fingerprint` and `client_fingerprint`.

Transfer the public request file to the host using your preferred LAN file transfer or removable media. Compare the **request fingerprint** in person or over another trusted channel. In another terminal on the host:

```bash
envport serve --data ~/.local/state/envport-lan authorize /private/laptop.request.json \
  --namespace NAMESPACE_ID --fingerprint CONFIRMED_REQUEST_FINGERPRINT \
  --output /private/laptop.connection.json
```

Replace `NAMESPACE_ID` with the host's `default_namespace` (or another explicitly created namespace). The host unlocks its own identity, authorizes exactly that client certificate and signs the connection document. Transfer this public connection document back to the client. Independently compare the host fingerprint with the host's original `serve init`/`serve inspect` output:

```bash
envport storage add lan --name home --connection /private/laptop.connection.json \
  --server-fingerprint TRUSTED_HOST_FINGERPRINT
envport storage test home
```

Import verifies the host signature/fingerprint, expiry and local client identity. A connection file alone cannot authorize another computer; its corresponding private TLS key remains on the requesting installation. The profile stores public trust material and an opaque credential reference, never a raw private key. `storage test` performs real object round trips and a two-writer CAS race before enabling backups.

Repeat authorization separately for each client. Public enrollment documents expose connection metadata; keep them private for privacy. Requests expire, and imported profiles remain usable until their certificate expires or access is revoked. Reasonably synchronized device clocks are required; bounded request-clock skew is tolerated.

## Back up and restore

On the source client after adding/testing `home`:

```bash
envport vault create personal --storage home
envport keys export --output /secure/personal-recovery.age
envport keys verify /secure/personal-recovery.age
envport track /your/Projects/my-repo
envport backup --dry-run
envport backup
```

On the destination, authorize its own TLS client and configure/test `home`, then separately obtain vault decryption access through recovery or the existing signed device-pairing workflow:

```bash
envport vault join personal --storage home --recovery /secure/personal-recovery.age
envport restore --scan /different/Code --dry-run
envport restore
envport sync --dry-run
envport sync
```

Repository paths can differ. Existing files are preserved by default. Explicit `sync --accept-remote` retains private preimages before replacing unchanged existing files. Concurrent differing edits produce a conflict; use the documented explicit resolution workflow. No last-writer-wins behavior is added by LAN transport.

`--no-network` disables LAN traffic too. LAN mode needs the local network, while requiring no public internet. When the host is unavailable, backup/sync fail without claiming success or switching to cloud/local fallback. Files can still be edited offline; reconnect and replan to detect conflicting changes. Automatic background queuing/watching is not implemented.

## Independent users and revocation

Use separate namespaces for unrelated users or storage-access groups. Each namespace can contain multiple independently encrypted vaults; a certificate authorized for one namespace has no access to another.

```bash
envport serve --data ~/.local/state/envport-lan namespace create work
envport serve --data ~/.local/state/envport-lan namespaces
envport serve --data ~/.local/state/envport-lan clients
```

Authorize a client explicitly for the intended namespace. `serve authorize ... --read-only` permits reads/restores but refuses writes/deletes. A read-only profile cannot pass the write-capability probe or create backups; restores can read without marking write capabilities verified.

Revoke a certificate's namespace access using its **client certificate fingerprint**, not the request fingerprint:

```bash
envport serve --data ~/.local/state/envport-lan revoke CLIENT_FINGERPRINT \
  --namespace NAMESPACE_ID --confirm
```

Every request checks persisted authorization, including requests on existing TLS connections, so the next request is denied after revocation. Already authorized in-flight operations may finish. Other clients remain unaffected; revocation survives restart. Duplicate authorization does not reactivate revoked certificates; generate a fresh request/key if re-enrollment is intended.

This revokes LAN storage access only. It cannot erase copied vault keys, ciphertext or plaintext. Vault key rotation/revocation is not implemented; rotate affected application credentials after endpoint compromise.

## Storage, backups and limits

The host owns `registry.db`, `server.json`, encrypted `server-key.age`, and `objects/objects.db` (including SQLite WAL state when present). Stop the server and all host administration writers before copying the entire host directory for an independent backup. Retain the host unlock passphrase independently. Keep vault recovery artifacts separately on the client side; host TLS material cannot decrypt a vault.

SQLite files stay on the host's native local filesystem. Never open the live object database over SMB/NFS or sync its WAL between computers. Clients use authenticated storage operations over TLS instead.

TLS 1.3, Ed25519 certificates, exact server certificate trust, no HTTP proxy/redirects, 16 KiB request headers, 16 MiB objects, eight concurrent authenticated object operations, 32 open connections and bounded network timeouts are enforced. Certificates last one year; automated certificate renewal, mDNS discovery, quotas and an installer/service manager are not implemented. Plan certificate replacement/re-authorization before expiry; never bypass verification to reconnect. The host and namespace administrator can delete/corrupt/roll back ciphertext; independent backups and existing checkpoint limitations still apply.

This is an experimental Linux-verified feature, not an independent security audit or native macOS/Windows support certification. Run `make smoke-lan` for a fully synthetic, real-server/two-client demonstration. It verifies exact bytes, default no-overwrite, concurrent offline conflicts, restart persistence, revoked access, and operation with deliberately unusable proxy settings. It starts only loopback fixture listeners and stops them before returning.
