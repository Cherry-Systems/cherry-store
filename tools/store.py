#!/usr/bin/env python3
"""The Cherry Store's intake: checks an uploaded .deb, virus-scans it and keeps index.json.

Nobody reviews apps. What this does:
  - the .deb must be signed by its publisher's Ed25519 key, and later versions by the same key;
  - it's virus-scanned with ClamAV; a hit is shown as a warning, not a refusal;
  - anything unusual a .deb can do (install scripts, files outside /opt and /usr, setuid programs,
    replacing Debian packages) is written down as a warning that Cherry shows before installing.
The .deb files themselves live in this repository's GitHub Releases.

  store.py check DEB REQUEST.json --via github:USER|cherry:USER --out RESULT.json [--no-scan]
  store.py add RESULT.json URL               record an accepted upload (after the release is made)
  store.py tag NAME VERSION                  the release tag / file name for a version
  store.py yank REQUEST.json                 withdraw a version (signed by the package's key)
  store.py takedown NAME REASON | restore NAME
  store.py rescan                            scan every package's newest version again
Standard library, plus python3-cryptography, dpkg-deb and clamscan.
"""
from __future__ import annotations

import base64
import hashlib
import json
import lzma
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
INDEX = Path(os.environ.get("CHERRY_STORE_INDEX", HERE / "index.json"))
DEBIAN_CACHE = Path(os.environ.get("DEBIAN_NAMES_CACHE", Path(tempfile.gettempdir()) / "debian-names.txt"))
DEBIAN_SUITE = "trixie"
MAX_SIZE = 1024 * 1024 * 1024
NAME_RE = re.compile(r"[a-z0-9][a-z0-9.+-]{1,62}")
VERSION_RE = re.compile(r"[0-9][0-9A-Za-z.+~-]{0,63}")
RESERVED = re.compile(r"^(cherry($|-)|admin$|root$|system$|official$|debian$|apt$)")
OFFICIAL_KEYS = HERE / "tools/official-keys.txt"  # Cherry OS's release keys; only they may use cherry-* names
ARCHES = {"amd64", "arm64", "all"}
SCRIPTS = ("preinst", "postinst", "prerm", "postrm", "config", "triggers")
USUAL_PLACES = ("/opt/", "/usr/bin/", "/usr/games/", "/usr/lib/", "/usr/libexec/", "/usr/share/")


class Rejected(Exception):
    pass


def signing_message(name: str, version: str, sha256: str) -> bytes:
    return f"cherry-package\n{name}\n{version}\n{sha256}".encode()


def yank_message(name: str, version: str) -> bytes:
    return f"cherry-yank\n{name}\n{version}".encode()


def key_id_for(public_b64: str) -> str:
    return hashlib.sha256(base64.b64decode(public_b64)).hexdigest()[:16]


def verify(public_b64: str, message: bytes, signature_b64: str) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(public_b64)).verify(base64.b64decode(signature_b64), message)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def official(public_key: str) -> bool:
    try:
        keys = {line.split("#")[0].strip() for line in OFFICIAL_KEYS.read_text().splitlines()}
    except OSError:
        return False
    return bool(public_key) and public_key in keys


def tag_for(name: str, version: str) -> str:
    """Git tags can't hold '~' or ':'."""
    return f"{name}_{version}".replace("~", "-").replace(":", "-")


# ---------------------------------------------------------------- index.json

def load_index() -> dict:
    try:
        return json.loads(INDEX.read_text())
    except FileNotFoundError:
        return {"format": 1, "packages": {}}


def save_index(index: dict) -> None:
    index["updated"] = int(time.time())
    INDEX.write_text(json.dumps(index, indent=1, sort_keys=True, ensure_ascii=False) + "\n")


def newest(versions: dict) -> str | None:
    live = [v for v, info in versions.items() if not info.get("yanked")]
    if not live:
        return None
    best = live[0]
    for v in live[1:]:
        if subprocess.run(["dpkg", "--compare-versions", v, "gt", best]).returncode == 0:
            best = v
    return best


# ---------------------------------------------------------------- looking inside a .deb

def control_fields(deb: Path) -> dict:
    out = subprocess.run(["dpkg-deb", "-f", str(deb)], capture_output=True, text=True)
    if out.returncode:
        raise Rejected(f"not a valid .deb: {out.stderr.strip()[:300]}")
    fields, key = {}, None
    for line in out.stdout.splitlines():
        if line[:1] in (" ", "\t") and key:
            fields[key] += "\n" + line[1:]
        elif ":" in line:
            key, value = line.split(":", 1)
            fields[key] = value.strip()
    return fields


def control_members(deb: Path) -> list[str]:
    with tempfile.TemporaryDirectory() as tmp:
        if subprocess.run(["dpkg-deb", "-e", str(deb), tmp], capture_output=True).returncode:
            raise Rejected("can't read the .deb's control files")
        return sorted(p.name for p in Path(tmp).iterdir())


def contents(deb: Path) -> list[tuple[str, str]]:
    """(permissions, path) for every file in the package."""
    out = subprocess.run(["dpkg-deb", "-c", str(deb)], capture_output=True, text=True)
    if out.returncode:
        raise Rejected("can't list the .deb's files")
    rows = []
    for line in out.stdout.splitlines():
        parts = line.split(None, 5)
        if len(parts) == 6:
            rows.append((parts[0], parts[5].split(" -> ")[0].lstrip(".")))
    return rows


def debian_names() -> set[str]:
    if DEBIAN_CACHE.exists() and time.time() - DEBIAN_CACHE.stat().st_mtime < 7 * 86400:
        return set(DEBIAN_CACHE.read_text().split())
    names = set()
    for comp in ("main", "contrib", "non-free", "non-free-firmware"):
        url = f"https://deb.debian.org/debian/dists/{DEBIAN_SUITE}/{comp}/binary-amd64/Packages.xz"
        with urllib.request.urlopen(url, timeout=120) as res:
            for line in lzma.decompress(res.read()).decode(errors="replace").splitlines():
                if line.startswith("Package: "):
                    names.add(line[9:].strip())
    DEBIAN_CACHE.write_text("\n".join(sorted(names)))
    return names


def scan(deb: Path) -> dict:
    """ClamAV over the .deb and everything unpacked from it."""
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run(["dpkg-deb", "-x", str(deb), tmp], capture_output=True)
        res = subprocess.run(["clamscan", "-r", "--infected", "--no-summary", "--max-filesize=1000M",
                              "--max-scansize=2000M", str(deb), tmp], capture_output=True, text=True)
    if res.returncode == 0:
        return {"status": "clean", "detail": "", "at": int(time.time())}
    if res.returncode == 1:
        hits = sorted({line.rsplit(": ", 1)[-1].removesuffix(" FOUND") for line in res.stdout.splitlines() if "FOUND" in line})
        return {"status": "flagged", "detail": ", ".join(hits)[:300], "at": int(time.time())}
    return {"status": "error", "detail": res.stderr.strip()[-300:], "at": int(time.time())}


def warnings_for(fields: dict, members: list[str], files: list[tuple[str, str]], debian: set[str]) -> list[str]:
    out = []
    scripts = [m for m in members if m in SCRIPTS]
    if scripts:
        out.append(f"Runs its own install scripts as administrator ({', '.join(scripts)}).")
    if fields["Package"] in debian:
        out.append(f"Has the same name as Debian's '{fields['Package']}' package and replaces it.")
    for field in ("Replaces", "Conflicts", "Breaks", "Provides"):
        others = {re.split(r"[\s(:]", p.strip())[0] for p in fields.get(field, "").split(",") if p.strip()}
        touched = sorted(o for o in others & debian if o != fields["Package"])
        if touched and field in ("Replaces", "Conflicts", "Breaks"):
            out.append(f"Can remove or replace Debian packages: {', '.join(touched[:8])}.")
            break
    elsewhere = sorted({path for mode, path in files if not mode.startswith("d") and path
                        and not path.startswith(USUAL_PLACES)})
    if elsewhere:
        out.append(f"Puts files outside the usual app folders: {', '.join(elsewhere[:5])}"
                   f"{' and more' if len(elsewhere) > 5 else ''}.")
    setuid = sorted(path for mode, path in files if len(mode) > 6 and mode[3] in "sS" or len(mode) > 6 and mode[6] in "sS")
    if setuid:
        out.append(f"Has programs that run with extra privileges (setuid): {', '.join(setuid[:5])}.")
    if fields.get("Pre-Depends"):
        out.append("Needs other packages set up before it can even unpack (Pre-Depends).")
    return out


# ---------------------------------------------------------------- commands

def check(deb: Path, request: dict, via: str, no_scan: bool = False) -> dict:
    name, version = str(request.get("name", "")), str(request.get("version", ""))
    if not NAME_RE.fullmatch(name):
        raise Rejected("names are 2-63 lowercase letters, numbers, '.', '+' or '-'")
    if not VERSION_RE.fullmatch(version):
        raise Rejected("versions start with a number and use letters, numbers, '.', '+', '~' or '-' (no epochs)")
    size = deb.stat().st_size
    if size > MAX_SIZE:
        raise Rejected(f"packages can be up to {MAX_SIZE // 2**20} MB")
    sha = hashlib.sha256(deb.read_bytes()).hexdigest()
    if sha != request.get("sha256"):
        raise Rejected("the file doesn't match its sha256")
    public_key = str(request.get("public_key", ""))
    if not verify(public_key, signing_message(name, version, sha), str(request.get("signature", ""))):
        raise Rejected("the publisher's signature doesn't match the file")
    fields = control_fields(deb)
    if fields.get("Package") != name or fields.get("Version") != version:
        raise Rejected(f"the .deb is {fields.get('Package')} {fields.get('Version')}, not {name} {version}")
    if fields.get("Architecture") not in ARCHES:
        raise Rejected(f"architecture must be one of {', '.join(sorted(ARCHES))}")

    index = load_index()
    pkg = index["packages"].get(name)
    if pkg:
        if pkg.get("taken_down"):
            raise Rejected(f"'{name}' was taken down: {pkg['taken_down'].get('reason', '')}")
        if pkg["key_id"] != key_id_for(public_key):
            raise Rejected(f"'{name}' belongs to another publisher (it's signed with a different key)")
        if version in pkg["versions"]:
            raise Rejected(f"{name} {version} is already published; bump the version")
    elif RESERVED.match(name) and not (name.startswith("cherry") and official(public_key)):
        raise Rejected("that name is reserved for Cherry OS itself")

    members, files = control_members(deb), contents(deb)
    warnings = warnings_for(fields, members, files, debian_names())
    result = {
        "name": name, "version": version, "via": via, "sha256": sha, "size": size,
        "signature": request["signature"], "public_key": public_key, "key_id": key_id_for(public_key),
        "architecture": fields["Architecture"], "depends": fields.get("Depends", ""),
        "summary": fields.get("Description", "").split("\n")[0][:200],
        "description": "\n".join(fields.get("Description", "").split("\n")[1:]).replace("\n.\n", "\n\n").strip()[:8000],
        "homepage": fields.get("Homepage", request.get("homepage", ""))[:300],
        "license": str(request.get("license", ""))[:100],
        "kind": "windows" if request.get("kind") == "windows" else "native",
        "icon_url": str(request.get("icon_url", ""))[:300] if str(request.get("icon_url", "")).startswith("https://") else "",
        "warnings": warnings,
        "scan": {"status": "pending", "detail": ""} if no_scan else scan(deb),
        "tag": tag_for(name, version),
    }
    return result


def add(result: dict, url: str) -> None:
    index = load_index()
    name = result["name"]
    pkg = index["packages"].setdefault(name, {
        "name": name, "publisher": "Cherry OS" if official(result["public_key"]) else result["via"], "key_id": result["key_id"], "public_key": result["public_key"],
        "created": int(time.time()), "versions": {},
    })
    pkg["versions"][result["version"]] = {
        "url": url, "size": result["size"], "sha256": result["sha256"], "signature": result["signature"],
        "architecture": result["architecture"], "depends": result["depends"], "warnings": result["warnings"],
        "scan": result["scan"], "via": result["via"], "created": int(time.time()), "yanked": False,
    }
    if newest(pkg["versions"]) == result["version"]:
        for key in ("summary", "description", "homepage", "license", "kind", "icon_url"):
            pkg[key] = result[key]
    pkg["latest"] = newest(pkg["versions"])
    save_index(index)


def yank(request: dict) -> str:
    index = load_index()
    name, version = str(request.get("name")), str(request.get("version"))
    pkg = index["packages"].get(name)
    if not pkg or version not in pkg["versions"]:
        raise Rejected(f"{name} {version} isn't in the store")
    if not verify(pkg["public_key"], yank_message(name, version), str(request.get("signature", ""))):
        raise Rejected("only the publisher can withdraw a version (the signature doesn't match)")
    pkg["versions"][version]["yanked"] = True
    pkg["latest"] = newest(pkg["versions"])
    save_index(index)
    return f"Withdrew {name} {version}"


def takedown(name: str, reason: str) -> None:
    index = load_index()
    index["packages"][name]["taken_down"] = {"reason": reason, "at": int(time.time())}
    save_index(index)


def restore(name: str) -> None:
    index = load_index()
    index["packages"][name].pop("taken_down", None)
    save_index(index)


def rescan() -> None:
    index = load_index()
    for name, pkg in index["packages"].items():
        version = pkg.get("latest")
        if not version or pkg.get("taken_down"):
            continue
        info = pkg["versions"][version]
        with tempfile.TemporaryDirectory() as tmp:
            deb = Path(tmp) / "p.deb"
            try:
                urllib.request.urlretrieve(info["url"], deb)
            except OSError as err:
                print(f"{name}: can't download: {err}", file=sys.stderr)
                continue
            if hashlib.sha256(deb.read_bytes()).hexdigest() != info["sha256"]:
                info["scan"] = {"status": "error", "detail": "the stored file changed", "at": int(time.time())}
            else:
                info["scan"] = scan(deb)
        print(f"{name} {version}: {info['scan']['status']} {info['scan']['detail']}")
    save_index(index)


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    cmd, args = argv[0], argv[1:]
    try:
        if cmd == "check":
            deb, req = Path(args[0]), json.loads(Path(args[1]).read_text())
            via = args[args.index("--via") + 1]
            out = Path(args[args.index("--out") + 1])
            try:
                result = check(deb, req, via, "--no-scan" in args)
                out.write_text(json.dumps({"ok": True, **result}, indent=1))
            except Rejected as err:
                out.write_text(json.dumps({"ok": False, "message": str(err)}))
                print(f"rejected: {err}", file=sys.stderr)
                return 1
        elif cmd == "add":
            add(json.loads(Path(args[0]).read_text()), args[1])
        elif cmd == "tag":
            print(tag_for(args[0], args[1]))
        elif cmd == "yank":
            print(yank(json.loads(Path(args[0]).read_text())))
        elif cmd == "takedown":
            takedown(args[0], " ".join(args[1:]) or "reported")
        elif cmd == "restore":
            restore(args[0])
        elif cmd == "rescan":
            rescan()
        else:
            print(__doc__)
            return 2
    except Rejected as err:
        print(f"rejected: {err}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
