#!/usr/bin/env python3
"""Real CLI clients + built-in mTLS server; synthetic data, loopback, no cloud service."""
import json
import os
from pathlib import Path
import selectors
import socket
import subprocess
import tempfile

binary = Path(os.environ.get("ENVPORT_BINARY", "bin/envport")).resolve()
environment = dict(os.environ,
    ENVPORT_PASSPHRASE="synthetic-lan-client-unlock-passphrase",
    ENVPORT_SERVER_PASSPHRASE="synthetic-lan-host-unlock-passphrase",
    ENVPORT_RECOVERY_PASSPHRASE="synthetic-lan-independent-recovery",
    HTTP_PROXY="http://127.0.0.1:9", HTTPS_PROXY="http://127.0.0.1:9", NO_PROXY="",
    AWS_EC2_METADATA_DISABLED="true")
marker = "SYNTHETIC_LAN_VALUE_MUST_STAY_ENCRYPTED"


def command(home, *args, expected=0):
    result = subprocess.run([str(binary), "--home", str(home), "--json", *map(str, args)],
                            env=environment, capture_output=True, text=True, timeout=60)
    for private in [marker, "BEGIN PRIVATE KEY", "AGE-SECRET-KEY-"]:
        if private in result.stdout + result.stderr:
            raise RuntimeError("private fixture material leaked to CLI output")
    if result.returncode != expected:
        raise RuntimeError(f"{args[0]} exited {result.returncode}; expected {expected}: {result.stderr}")
    return json.loads(result.stdout) if result.stdout.strip() else None


def repo(path):
    path.mkdir(parents=True)
    for args in [["init", str(path)], ["-C", str(path), "remote", "add", "origin", "git@example.test:lan/fixture.git"]]:
        subprocess.run(["git", *args], check=True, capture_output=True)


with tempfile.TemporaryDirectory(prefix="envport-lan-smoke-") as temporary:
    root = Path(temporary)
    host_home, host_data = root / "host-home", root / "host-storage"
    a, b = root / "client-a", root / "client-b"
    source, target = root / "linux/Projects/source", root / "other/Code/renamed"
    recovery = root / "independent-recovery.age"
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    endpoint = f"https://127.0.0.1:{port}"
    host_info = command(host_home, "serve", "--data", host_data, "init", "--endpoint", endpoint)
    assert not (host_home / "state.db").exists(), "storage host initialized application/decryption state"
    process = None
    stderr_log = (root / "host-stderr.log").open("wb")

    def start():
        global process
        process = subprocess.Popen([str(binary), "--home", str(host_home), "--json", "serve", "--data",
                                    str(host_data), "--listen", f"127.0.0.1:{port}"], env=environment,
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=stderr_log, text=True)
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            if not selector.select(timeout=30):
                raise RuntimeError("LAN server startup timeout")
        ready = process.stdout.readline()
        if not ready:
            raise RuntimeError("LAN server exited during startup")
        assert json.loads(ready)["state"] == "listening"

    def stop():
        global process
        if process is None:
            return
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        if process.stdout:
            process.stdout.close()
        process = None

    def enroll(home, label):
        command(home, "init", "--lan")
        assert command(home, "storage", "list") == [], "LAN init selected a hidden fallback profile"
        request_file, connection = root / f"{label}.request.json", root / f"{label}.connection.json"
        request = command(home, "storage", "lan", "request", "--output", request_file)
        approval = command(host_home, "serve", "--data", host_data, "authorize", request_file,
                           "--namespace", host_info["default_namespace"], "--fingerprint",
                           request["request_fingerprint"], "--output", connection)
        command(home, "storage", "add", "lan", "--name", "home", "--connection", connection,
                "--server-fingerprint", host_info["server_fingerprint"])
        assert command(home, "storage", "test", "home")["verified"]
        return approval["client_fingerprint"]

    try:
        start()
        a_fingerprint = enroll(a, "a")
        enroll(b, "b")
        command(a, "vault", "create", "personal", "--storage", "home")
        command(a, "keys", "export", "--output", recovery)
        repo(source)
        repo(target)
        original = ("# synthetic fixture\r\nKEY=" + marker + "\r\n").encode() + b"\x00\xff"
        (source / ".env").write_bytes(original)
        command(a, "track", source)
        assert command(a, "backup")["uploaded"] == 1
        command(b, "vault", "join", "personal", "--storage", "home", "--recovery", recovery)
        preview = command(b, "restore", "--scan", target.parent, "--dry-run")
        assert preview["entries"][0]["state"] == "create"
        assert command(b, "restore")["downloaded"] == 1
        assert (target / ".env").read_bytes() == original
        (target / ".env").write_bytes(b"KEY=synthetic-remote-update\n")
        command(b, "backup")
        assert command(a, "sync")["pending"] == 1
        assert (source / ".env").read_bytes() == original
        assert command(a, "sync", "--accept-remote")["downloaded"] == 1
        assert list(source.glob(".envport-preimage-*"))[0].read_bytes() == original
        stop()
        (source / ".env").write_bytes(b"KEY=synthetic-offline-a\n")
        (target / ".env").write_bytes(b"KEY=synthetic-offline-b\n")
        command(a, "backup", expected=1)
        assert (source / ".env").read_bytes() == b"KEY=synthetic-offline-a\n"
        start()
        contenders = [(home, subprocess.Popen([str(binary), "--home", str(home), "--json", "backup"],
                       env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)) for home in (a, b)]
        outcomes = []
        for home, contender in contenders:
            out, error = contender.communicate(timeout=60)
            assert marker not in out + error and "BEGIN PRIVATE KEY" not in out + error
            outcomes.append((home, contender.returncode))
        assert sorted(code for _, code in outcomes) in ([0, 3], [0, 4]), "concurrent clients lost an update"
        loser = next(home for home, code in outcomes if code != 0)
        conflict = command(loser, "status")
        assert conflict["entries"][0]["action"] == "conflict"
        file_id = conflict["entries"][0]["file_id"]
        command(loser, "resolve", file_id, "--keep-local")
        command(loser, "sync")
        assert len(command(b, "history")) == 4
        command(b, "doctor")
        command(b, "--no-network", "status", expected=1)
        # Host files must contain neither plaintext fixtures nor vault private identities.
        for path in host_data.rglob("*"):
            if path.is_file():
                data = path.read_bytes()
                assert marker.encode() not in data and b"AGE-SECRET-KEY-" not in data
        assert not list(host_data.glob("key-*.age"))
        command(host_home, "serve", "--data", host_data, "revoke", a_fingerprint,
                "--namespace", host_info["default_namespace"], "--confirm")
        command(a, "status", expected=1)
        command(b, "doctor")
        stop()
        start()
        command(a, "status", expected=1)
        command(b, "doctor")
        print("PASS: built-in LAN host, independent TLS clients, encrypted recovery, exact bytes, concurrent offline conflicts, restart persistence, revocation and no cloud/proxy dependency")
    finally:
        stop()
        stderr_log.close()
