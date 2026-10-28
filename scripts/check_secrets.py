#!/usr/bin/env python3
"""Small conservative source guard; complements external secret scanning/review."""
from pathlib import Path
import re
import subprocess

patterns = [re.compile(rb"AGE-SECRET-KEY-1[0-9A-Z]{20,}"),
            re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
            re.compile(rb"\bAKIA[0-9A-Z]{16}\b")]
allowed = {"testdata/protocol/v1/SYNTHETIC_IDENTITY.txt"}
files = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
                       capture_output=True, check=True).stdout.split(b"\0")
failed = False
for raw in files:
    if not raw:
        continue
    path = Path(raw.decode())
    if path.as_posix() in allowed or path.as_posix().startswith((".claude/", ".agents/", ".codex/", ".aws/")) or not path.is_file():
        continue
    data = path.read_bytes()
    if any(pattern.search(data) for pattern in patterns):
        print(f"Potential private material in {path}; contents redacted")
        failed = True
if failed:
    raise SystemExit(1)
print("PASS: conservative source secret guard (synthetic golden identity explicitly allowed)")
