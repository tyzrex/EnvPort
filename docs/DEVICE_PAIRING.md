# Existing-device authorization

Recovery join is available independently. Pairing avoids transmitting an unwrapped root key and does not transfer bucket credentials. Requests and grants are files; any transport may carry them. The transport itself is not authentication.

On the new installation, after `init` and adding its storage profile:

```bash
envport devices request --vault-id VAULT_ID --output /private/request.json
```

The output includes a full request fingerprint. Compare/convey it over a trusted independent channel or in person. The signed request binds the vault, fresh device encryption/signing keys, random nonce and a 30-minute expiry. Do not approve an unverified request sent by someone claiming to be your device.

On the existing authorized installation:

```bash
envport devices approve /private/request.json \
  --fingerprint CONFIRMED_REQUEST_FINGERPRINT --output /private/grant.age
```

The command requires an exact fingerprint, verifies the request signature/expiry/vault, and produces a signed grant encrypted to the requesting device. It outputs the issuer's signing-key fingerprint. Authenticate that fingerprint independently to the new installation.

On the new installation:

```bash
envport vault join personal --storage my-storage \
  --grant /private/grant.age --issuer-fingerprint TRUSTED_ISSUER_FINGERPRINT
```

Joining verifies the issuer signature/fingerprint, device/vault/request binding, expiry and locally pending request. A successful join consumes the pending request transactionally; another device cannot decrypt the grant. Duplicate approvals are rejected by the approving installation. Invalid, tampered, expired, untrusted-issuer and replayed grants fail tests.

`devices list` shows this installation's ID and approvals observed locally. It is not an authoritative remote membership registry. Manifests use shared-key age authentication and author IDs, not individually signed author proofs. A root key holder can forge authors. Rotation, key epochs and revocation are not shipped. A copied root key cannot be revoked retroactively; removing bucket access only limits access through those credentials. Rotate affected application credentials after a compromised endpoint.

Pending requests are public metadata in the private state database; private device encryption/signing keys are only in `device.age`, encrypted with the installation unlock passphrase. No unauthenticated localhost server or hosted invitation service is used.

For a LAN profile, first authorize the separate client TLS identity on the host; then obtain vault decryption via this pairing procedure or recovery. `serve clients` / `serve revoke` manage LAN namespace transport access only. `devices list` describes vault-device pairing state. Neither form of removing transport access erases copied vault keys. See [LAN.md](LAN.md).
