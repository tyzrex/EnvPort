# Key recovery

A bucket credential allows ciphertext access, not decryption. Account login does not recover a vault key. You need a usable encrypted recovery bundle plus its passphrase, or a currently authorized device that can approve a new device. Recovery also needs the actual ciphertext objects and separate storage access.

1. `keys export --output /secure/new-file.age` unlocks the selected vault, encrypts its ID/private age identity under an independent recovery passphrase, verifies decryption in memory, and creates a 0600 file without overwriting.
2. Store that file independently of the originating installation and storage bucket. Keep its passphrase in a separate secure location.
3. `keys verify /secure/new-file.age` authenticates the bundle against the currently selected vault. Test recovery into an isolated installation before trusting the backup.
4. A fresh installation uses `vault join NAME --storage PROFILE --recovery BUNDLE`. It generates independent local device state and encrypts the imported vault key under its local unlock passphrase.
5. Map repositories, preview restore, compare recovered bytes, and run `doctor`.

Passphrases are entered through hidden terminal input. Automation can inject `ENVPORT_PASSPHRASE` and `ENVPORT_RECOVERY_PASSPHRASE` from a protected secret source; environment exposure and process memory remain endpoint risks. They must be 12–1024 bytes; length alone does not establish entropy. Recovery uses age scrypt with a maximum accepted work factor of 18, not a custom password cipher.

Wrong passphrases, wrong-vault bundles, corruption and missing local key envelopes fail closed. Losing the local key/passphrase is recoverable if the independent recovery bundle/passphrase or a functioning authorized device remains. Losing all usable vault key material makes ciphertext permanently unrecoverable. No administrator can reset decryption. Recovery alone cannot restore a deleted bucket; keep independent ciphertext backups.

Source device absence is covered by recovery integration tests. Original AES `key.bin` is a separate format and must be preserved until a verified migration succeeds. Never import it as an age identity.
