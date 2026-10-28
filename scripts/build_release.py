#!/usr/bin/env python3
"""Build unsigned experimental cross-platform archives; never publishes anything."""
import hashlib
import json
from datetime import datetime, timezone
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import zipfile

version = os.environ.get("ENVPORT_RELEASE_VERSION", "0.1.0-dev")
if not version or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_" for c in version):
    raise SystemExit("Invalid release version")
out = Path("dist") / version
out.mkdir(parents=True, exist_ok=True)
raw_modules = subprocess.check_output(["go", "list", "-deps", "-json", "./cmd/envport"], text=True)
decoder, modules, remainder = json.JSONDecoder(), [], raw_modules.strip()
while remainder:
    item, position = decoder.raw_decode(remainder)
    remainder = remainder[position:].lstrip()
    if "Module" in item and item["Module"]["Path"] not in {m["Path"] for m in modules}:
        modules.append(item["Module"])
sbom = out / f"envport_{version}.cdx.json"
sbom.write_text(json.dumps({"bomFormat":"CycloneDX", "specVersion":"1.6", "version":1,
    "metadata":{"timestamp":datetime.now(timezone.utc).isoformat(),
                "component":{"type":"application","name":"envport","version":version}},
    "components":[{"type":"library","name":m["Path"],"version":m.get("Version",version),
                   "purl":"pkg:golang/"+m["Path"]+"@"+m.get("Version",version)} for m in modules]}, indent=2)+"\n")
checksums = [f"{hashlib.sha256(sbom.read_bytes()).hexdigest()}  {sbom.name}"]
for system, arch in [("linux", "amd64"), ("linux", "arm64"), ("darwin", "amd64"), ("darwin", "arm64"), ("windows", "amd64")]:
    name = f"envport_{version}_{system}_{arch}"
    directory = out / name
    directory.mkdir(exist_ok=True)
    binary = directory / ("envport.exe" if system == "windows" else "envport")
    env = dict(os.environ, GOOS=system, GOARCH=arch, CGO_ENABLED="0")
    subprocess.run(["go", "build", "-trimpath", "-ldflags",
                    f"-s -w -X github.com/envport-dev/envport/internal/transport/cli.Version={version}",
                    "-o", str(binary), "./cmd/envport"], env=env, check=True)
    (directory / "BUILDINFO.txt").write_bytes(subprocess.check_output(["go", "version", "-m", str(binary)]))
    shutil.copyfile(sbom, directory / "SBOM.cdx.json")
    for doc in ["LICENSE", "README.md", "THIRD_PARTY_NOTICES.md", "SECURITY.md"]:
        shutil.copyfile(doc, directory / doc)
    shutil.copytree("docs", directory / "docs", dirs_exist_ok=True)
    if system == "windows":
        archive = out / f"{name}.zip"
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as z:
            for file in sorted(directory.rglob("*")):
                if file.is_file():
                    z.write(file, file.relative_to(directory).as_posix())
    else:
        archive = out / f"{name}.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            for file in sorted(directory.iterdir()):
                tar.add(file, arcname=file.name)
    checksums.append(f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}")
    print(f"Built {archive}; unsigned, runtime support requires platform verification")
(out / "SHA256SUMS").write_text("\n".join(checksums) + "\n")
