#!/usr/bin/env python3
"""Exercise real CLI processes using synthetic data and two isolated device homes."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

binary = Path(os.environ.get("ENVPORT_BINARY", "bin/envport")).resolve()
fixture_env = dict(os.environ, ENVPORT_PASSPHRASE="synthetic-smoke-unlock-passphrase",
                   ENVPORT_RECOVERY_PASSPHRASE="synthetic-smoke-independent-recovery")

def command(home, *args, expected=0):
    result = subprocess.run([str(binary), "--home", str(home), "--json", "--no-network", *args],
                            env=fixture_env, capture_output=True, text=True)
    if result.returncode != expected:
        raise RuntimeError(f"{args[0]} exited {result.returncode}; expected {expected}: {result.stderr}")
    if "synthetic-fixture-value" in result.stdout + result.stderr:
        raise RuntimeError("plaintext fixture leaked into CLI output")
    return json.loads(result.stdout) if result.stdout.strip() else None

def repo(path):
    path.mkdir(parents=True)
    for args in [["init", str(path)], ["-C", str(path), "remote", "add", "origin", "git@example.test:smoke/project.git"]]:
        subprocess.run(["git", *args], capture_output=True, check=True)

with tempfile.TemporaryDirectory(prefix="envport-smoke-") as temp:
    root = Path(temp)
    a, b, c = root / "device-a", root / "device-b", root / "device-c"
    source, target = root / "linux/Projects/checkout", root / "mac/Code/renamed"
    objects, recovery = root / "encrypted-objects", root / "recovery.age"
    repo(source)
    repo(target)
    original = b"\xef\xbb\xbf# fixture\r\nKEY=synthetic-fixture-value\r\n\x00\xff"
    (source / ".env").write_bytes(original)
    command(a, "init")
    command(a, "storage", "add", "filesystem", "--name", "shared", "--path", str(objects))
    command(a, "vault", "create", "personal", "--storage", "shared")
    command(a, "keys", "export", "--output", str(recovery))
    command(a, "track", str(source))
    preview = command(a, "backup", "--dry-run")
    assert [e["action"] for e in preview["entries"]] == ["upload"]
    first = command(a, "backup")
    assert first["uploaded"] == 1
    command(b, "init")
    command(b, "storage", "add", "filesystem", "--name", "shared", "--path", str(objects))
    command(b, "vault", "join", "personal", "--storage", "shared", "--recovery", str(recovery))
    command(b, "restore", "--scan", str(target.parent), "--dry-run")
    restored = command(b, "restore")
    assert restored["downloaded"] == 1 and (target / ".env").read_bytes() == original
    (target / ".env").write_bytes(b"KEY=synthetic-mac-update\n")
    command(b, "backup")
    assert command(a, "sync")["pending"] == 1
    assert (source / ".env").read_bytes() == original
    assert command(a, "sync", "--accept-remote")["downloaded"] == 1
    assert (source / ".env").read_bytes() == b"KEY=synthetic-mac-update\n"
    backups = list(source.glob(".envport-preimage-*"))
    assert len(backups) == 1 and backups[0].read_bytes() == original
    (source / ".env").write_bytes(b"KEY=linux-conflict\n")
    (target / ".env").write_bytes(b"KEY=mac-conflict\n")
    command(a, "backup")
    command(b, "sync", expected=3)
    status = command(b, "status")
    file_id = status["entries"][0]["file_id"]
    command(b, "resolve", file_id, "--keep-local")
    command(b, "sync")
    command(b, "doctor")
    assert len(command(b, "history")) == 4
    # A third device uses authenticated pairing, without the recovery passphrase.
    command(c, "init")
    command(c, "storage", "add", "filesystem", "--name", "shared", "--path", str(objects))
    vault_id = command(a, "vault", "inspect")["id"]
    request, grant = root / "request.json", root / "grant.age"
    request_info = command(c, "devices", "request", "--vault-id", vault_id, "--output", str(request))
    approval = command(a, "devices", "approve", str(request), "--fingerprint", request_info["request_fingerprint"], "--output", str(grant))
    command(c, "vault", "join", "personal", "--storage", "shared", "--grant", str(grant), "--issuer-fingerprint", approval["issuer_fingerprint"])
    assert len(command(c, "history")) == 4
    print("PASS: CLI recovery, byte equality, safe replacement, conflicts, history, doctor and authenticated pairing")
