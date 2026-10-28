#!/usr/bin/env python3
"""Run opt-in S3 tests against a real isolated MinIO server, never a user bucket."""
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request

binary = os.environ.get("MINIO_BINARY") or shutil.which("minio")
if not binary:
    raise SystemExit("Install the pinned MinIO test server first: go install github.com/minio/minio@RELEASE.2025-09-07T16-13-09Z; then set MINIO_BINARY if needed")
with tempfile.TemporaryDirectory(prefix="envport-minio-") as directory:
    root = Path(directory)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    endpoint = f"http://127.0.0.1:{port}"
    env = dict(os.environ)
    for key in list(env):
        if key.startswith("AWS_") or key.startswith("MINIO_"):
            del env[key]
    # MinIO treats any username starting with 'env' as an environment URL.
    env.update(MINIO_ROOT_USER="miniofixture", MINIO_ROOT_PASSWORD="synthetic-minio-fixture-password",
               MINIO_BROWSER="off", MINIO_UPDATE="off", AWS_ACCESS_KEY_ID="miniofixture",
               AWS_SECRET_ACCESS_KEY="synthetic-minio-fixture-password", AWS_EC2_METADATA_DISABLED="true",
               ENVPORT_TEST_S3_ENDPOINT=endpoint)
    empty = root / "empty-aws-config"
    empty.write_text("")
    env.update(AWS_CONFIG_FILE=str(empty), AWS_SHARED_CREDENTIALS_FILE=str(empty))
    with (root / "server.log").open("wb") as log:
        process = subprocess.Popen([binary, "server", "--address", f"127.0.0.1:{port}", str(root / "data")],
                                   env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        try:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError("MinIO exited before becoming healthy")
                try:
                    with opener.open(endpoint + "/minio/health/live", timeout=1) as response:
                        if response.status == 200:
                            break
                except (OSError, urllib.error.URLError):
                    time.sleep(0.1)
            else:
                raise RuntimeError("MinIO health timeout")
            subprocess.run(["go", "test", "-count=1", "-v", "./internal/storage/s3", "./internal/application",
                            "-run", "TestMinIO"], env=env, check=True)
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
