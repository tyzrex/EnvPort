# Security policy

EnvPort is experimental. No release is certified for production or as a sole backup. The threat model and implementation status are maintained in `docs/threat-model.md` and `docs/IMPLEMENTATION_STATUS.md`.

Do not publish real secret files, private keys, credentials, recovery bundles, bucket names, signed request headers or confidential project metadata in issues. For a suspected vulnerability, use private vulnerability reporting on the source repository if enabled, or contact its maintainer privately through an established channel. No security contact address or hosted service is invented by this repository. Public issue reports should contain synthetic reproducers only.

Use supported Go/dependency patches and run `govulncheck ./...`, `staticcheck ./...`, race/security tests and the source secret guard before release. A passing scan is not an independent audit. Historical test-only MinIO is external fixture software and is not distributed with the CLI; do not expose it on public networks.

Never promise copied-key revocation, first-join freshness, key reset without recovery material, endpoint-compromise protection or untested platform/provider support. There is no telemetry, hosted account backend, production signing or automatic updater in this implementation.
