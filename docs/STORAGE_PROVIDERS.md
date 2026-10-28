# Storage providers

A filesystem profile is a private directory containing SQLite ciphertext objects. Use a native local filesystem with correct SQLite locking/WAL semantics; live NFS/network filesystems and cloud-synced database folders are not verified. Copy an offline object directory only with all writers stopped. A generic S3 profile supplies nonsecret endpoint, region, bucket, prefix, addressing style and an optional AWS profile name. Independent vaults always use independent random prefixes and keys. A prefix is not authorization; scope bucket credentials appropriately.

## Built-in LAN host

Use `storage add lan` with an explicitly trusted signed connection from `envport serve`. It reuses the same engine without S3, cloud accounts or third-party storage software. The host owns its local SQLite database and clients access only namespace-scoped TLS operations. See [LAN.md](LAN.md) for enrollment/startup and [LAN wire v1](protocol/lan-v1.md) for the protocol.

## Cloudflare R2

Create a private bucket and a scoped S3 API token with object read/write/list/delete access only where needed. Obtain the account-specific HTTPS endpoint from the R2 dashboard. Configure AWS environment credentials using protected tooling, or a named shared credentials profile outside EnvPort configuration. Never put secret keys in command-line flags, repository files or copied diagnostic output.

```bash
envport storage add s3 --name r2 \
  --endpoint https://ACCOUNT_ID.r2.cloudflarestorage.com \
  --region auto --bucket YOUR_PRIVATE_BUCKET --prefix envport --path-style
envport storage test r2
```

Region/endpoint and conditional-write behavior must match [R2 S3 documentation](https://developers.cloudflare.com/r2/api/s3/api/) and [R2 conditional-write extensions](https://developers.cloudflare.com/r2/api/s3/extensions/). These docs are setup references, not proof that this installation was tested against your bucket. No live R2 credentials were supplied during development; R2 compatibility remains unverified until the capability test and a fresh-install recovery drill pass.

## AWS S3

Use a private bucket, region and the SDK credential chain (profile, environment or appropriate role). EnvPort does not store credential values. SDK credential providers can contact AWS identity/metadata services. Disable metadata probing with `AWS_EC2_METADATA_DISABLED=true` where not wanted.

```bash
envport storage add s3 --name aws --region us-east-1 \
  --bucket YOUR_PRIVATE_BUCKET --prefix envport --aws-profile YOUR_PROFILE --path-style=false
envport storage test aws
```

A starting IAM policy (adapt bucket/prefix and credential lifecycle to your account):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect":"Allow","Action":["s3:ListBucket"],"Resource":"arn:aws:s3:::YOUR_BUCKET","Condition":{"StringLike":{"s3:prefix":["envport/*"]}}},
    {"Effect":"Allow","Action":["s3:GetObject","s3:PutObject","s3:DeleteObject"],"Resource":"arn:aws:s3:::YOUR_BUCKET/envport/*"}
  ]
}
```

The capability probe uses a random namespace beneath the configured prefix. Application garbage collection is disabled, but the probe needs deletion for its own synthetic objects. [AWS conditional-write semantics](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html) and [SDK configuration](https://docs.aws.amazon.com/sdk-for-go/v2/developer-guide/configure-gosdk.html) are authoritative setup references. No live AWS test was performed here.

## MinIO and custom services

`make test-minio` starts an isolated server, chooses a localhost port, supplies synthetic credentials, creates random test buckets and cleans only those buckets. Supply an installed `minio` or `MINIO_BINARY`. The fixture source revision is `RELEASE.2025-09-07T16-13-09Z` / `07c3a429bfed`. MinIO is only a test service, not linked or bundled with EnvPort. Its archived community distribution no longer supplied usable images in this environment; CI builds the pinned source.

```bash
go install github.com/minio/minio@RELEASE.2025-09-07T16-13-09Z
make test-minio
```

An explicitly isolated manual service can use `--endpoint http://127.0.0.1:9000 --region us-east-1 --allow-http`. HTTP is disabled by default; enabling it prints a warning because credentials and traffic cross the network without TLS. Never enable it for production traffic. B2/custom endpoints are configurable but unverified; no provider-name shortcut grants write safety.

## What is implemented

SigV4 through AWS SDK v2, custom HTTPS endpoints, default TLS validation, no redirects, credential-chain refresh, bounded objects, cancellation, request timeouts, SDK retries, ETags, conditional create/replace, Get/Head/List/Delete and pagination. Maximum plaintext file: 8 MiB. Maximum object: 16 MiB. No multipart, custom CA bundles, object lock, storage migration or fallback single-writer mode is shipped.

S3 writes require a successful stored capability probe. The probe verifies object operations, rejected duplicate creation, rejected stale replacement and **two contenders with exactly one CAS winner**. This is evidence about a tested endpoint at that time, not an assurance against a malicious provider or later configuration changes. On failure, writes remain disabled; no hidden fallback backend is selected. Re-run after provider/endpoint policy changes.

## Actual compatibility report

| Backend | Result |
|---|---|
| SQLite filesystem objects | Local unit/integration/CAS tests passed |
| Built-in LAN host | Real two-client TLS CLI recovery, concurrency/conflicts, restart persistence, revocation, namespace isolation and object round trips passed on Linux loopback |
| Pinned real MinIO server | Object operations, concurrent CAS, pagination, empty/2 MiB objects and cancellation passed |
| MinIO encrypted application workflow | Backup, fresh-device recovery, restore byte equality and object plaintext/path leakage checks passed |
| Cloudflare R2 | Blocked: dedicated bucket credentials not supplied |
| AWS S3 | Blocked: dedicated bucket credentials not supplied |
| Backblaze B2 / other S3 services | Not verified |

Credentials for live tests must be dedicated/scoped test credentials. Never infer a successful deployment or production compatibility from this table.
