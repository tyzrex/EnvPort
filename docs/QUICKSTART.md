# Recovery between different checkout layouts

The automated runnable demonstration is `make smoke`. It uses synthetic values, three device homes, different absolute checkout paths, independent recovery, signed pairing, byte comparisons, explicit replacement, conflicts and doctor. It never scans personal directories.

For real use, build the CLI and configure a private storage profile on each installation. Read the threat model before relying on experimental backups. Store recovery artifacts independently of both device state and the bucket.

On the source installation:

```bash
envport init --byos
envport storage add s3 --name my-r2 \
  --endpoint https://ACCOUNT_ID.r2.cloudflarestorage.com \
  --bucket YOUR_BUCKET --region auto --prefix envport
envport storage test my-r2
envport vault create personal --storage my-r2
envport keys export --output /secure/personal-recovery.age
envport keys verify /secure/personal-recovery.age
envport scan /your/Projects
envport track /your/Projects/my-repo
envport backup --dry-run
envport backup
envport doctor
```

Use interactive passphrase entry. AWS credentials come from a separately configured SDK profile/environment/identity provider, never pass them on command lines. A high-entropy vault unlock passphrase and an independent recovery passphrase must both be retained securely. `ENVPORT_PASSPHRASE` and `ENVPORT_RECOVERY_PASSPHRASE` are available for automation; do not put real values in shell history.

On the destination, install the same protocol-compatible CLI and clone your repositories yourself. Configure bucket access independently, then:

```bash
envport init --byos
envport storage add s3 --name my-r2 \
  --endpoint https://ACCOUNT_ID.r2.cloudflarestorage.com \
  --bucket YOUR_BUCKET --region auto --prefix envport
envport storage test my-r2
envport vault join personal --storage my-r2 --recovery /secure/personal-recovery.age
envport restore --scan /different/Code --dry-run
envport restore
envport status
envport sync --dry-run
```

The new device creates its own identity and re-encrypts the imported vault identity under its local unlock passphrase. Git SSH/HTTPS remotes are canonicalized; directory names are irrelevant. Multiple different remotes require explicit local UUID enrollment, and multiple matching checkouts require an explicit project mapping. If a project has no remote, obtain its ID through `status` on a joined vault, then `project map ID /approved/checkout`.

For offline transfer, `storage add filesystem --name portable --path /private/encrypted-objects` on both installations. Copy the entire encrypted object directory with no writers running; include SQLite WAL files if present or stop all processes first. Configure each vault to use that profile. Recovery bundles and storage access are still separate.

This workflow has been verified between isolated Linux installations and against MinIO, not on actual macOS/Windows hardware or live R2. Their runtime acceptance remains blocked/unverified in the implementation status.
