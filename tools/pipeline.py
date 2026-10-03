#!/usr/bin/env python3
"""Runs one store request inside GitHub Actions: pipeline.py EVENT.json

Requests come in three ways:
  - an issue titled "Publish: NAME VERSION" or "Withdraw: NAME VERSION" with the request as a
    ```json block (what `cherry publish --github` opens; the issue's author is the publisher);
  - a repository_dispatch from Cherry Cloud (cherry-upload / cherry-yank) for people who publish
    with a Cherry account; the .deb waits on Cherry Cloud until this fetches it;
  - a manual workflow_dispatch to take a package down or bring it back.
Everything from the request is treated as untrusted text and never reaches a shell.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import store  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
CLOUD = os.environ.get("CHERRY_CLOUD_URL", "").rstrip("/")
STORE_TOKEN = os.environ.get("STORE_TOKEN", "")
PER_DAY = 20
TITLE_RE = re.compile(r"(Publish|Withdraw):\s*(\S+)\s+(\S+)\s*$")


def gh(*args: str, input: str | None = None) -> str:
    return subprocess.run(["gh", *args], check=True, capture_output=True, text=True, input=input).stdout.strip()


def git(*args: str) -> None:
    subprocess.run(["git", "-C", str(REPO), *args], check=True)


def download(url: str, dest: Path, headers: dict | None = None) -> None:
    if not url.startswith("https://"):
        raise store.Rejected("the package link must start with https://")
    req = urllib.request.Request(url, headers={"User-Agent": "cherry-store", **(headers or {})})
    got = 0
    with urllib.request.urlopen(req, timeout=300) as res, dest.open("ab") as out:
        while chunk := res.read(1 << 20):
            got += len(chunk)
            if got > store.MAX_SIZE:
                raise store.Rejected(f"packages can be up to {store.MAX_SIZE // 2**20} MB")
            out.write(chunk)


def commit(message: str) -> None:
    git("add", "index.json")
    git("-c", "user.name=Cherry Store", "-c", "user.email=store@cherry-systems.invalid", "commit", "-q", "-m", message)
    for _ in range(5):
        if subprocess.run(["git", "-C", str(REPO), "push", "-q"]).returncode == 0:
            return
        git("pull", "-q", "--rebase")
    raise RuntimeError("couldn't push index.json")


def recent_uploads(via: str) -> int:
    since = time.time() - 86400
    return sum(1 for pkg in store.load_index()["packages"].values() for v in pkg["versions"].values()
               if v.get("via") == via and v.get("created", 0) > since)


def publish(deb: Path, request: dict, via: str) -> str:
    if recent_uploads(via) >= PER_DAY:
        raise store.Rejected(f"you can publish {PER_DAY} versions a day; try again tomorrow")
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "result.json"
        code = store.main(["check", str(deb), _write(Path(tmp) / "req.json", request), "--via", via, "--out", str(out)])
        result = json.loads(out.read_text())
        if code:
            raise store.Rejected(result["message"])
        tag = result["tag"]
        asset = Path(tmp) / f"{tag}_{result['architecture']}.deb"
        asset.write_bytes(deb.read_bytes())
        if subprocess.run(["gh", "release", "view", tag], capture_output=True).returncode == 0:
            gh("release", "delete", tag, "--yes", "--cleanup-tag")
        notes = (f"{result['summary']}\n\nPublished by {via}. sha256 `{result['sha256']}`\n\n"
                 f"Virus scan: {result['scan']['status']} {result['scan']['detail']}\n\n"
                 + "".join(f"- {w}\n" for w in result["warnings"]))
        gh("release", "create", tag, str(asset), "--title", f"{result['name']} {result['version']}", "--notes-file", "-",
           input=notes)
        url = json.loads(gh("release", "view", tag, "--json", "assets"))["assets"][0]["url"]
        store.add(result, url)
    commit(f"Publish {result['name']} {result['version']} ({via})")
    lines = [f"Published **{result['name']} {result['version']}**. Install it with `cherry install {result['name']}`.",
             f"Virus scan: {result['scan']['status']} {result['scan']['detail']}".rstrip()]
    if result["warnings"]:
        lines.append("Cherry will show these warnings before installing:\n" + "".join(f"- {w}\n" for w in result["warnings"]))
    return "\n\n".join(lines)


def withdraw(request: dict) -> str:
    message = store.yank(request)
    commit(message)
    return message + "."


def _write(path: Path, data: dict) -> str:
    path.write_text(json.dumps(data))
    return str(path)


def request_from_issue(issue: dict) -> tuple[str, dict]:
    m = TITLE_RE.fullmatch(issue.get("title", "").strip())
    if not m:
        raise store.Rejected('the title should be "Publish: NAME VERSION" or "Withdraw: NAME VERSION"')
    block = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", issue.get("body") or "", re.S)
    if not block:
        raise store.Rejected("the issue needs the request as a ```json block (cherry publish writes it)")
    request = json.loads(block.group(1))
    if (request.get("name"), request.get("version")) != (m.group(2), m.group(3)):
        raise store.Rejected("the title and the request disagree about the name or version")
    return m.group(1).lower(), request


def cloud_done(upload: str, ok: bool, message: str) -> None:
    if not (CLOUD and upload):
        return
    body = json.dumps({"ok": ok, "message": message}).encode()
    req = urllib.request.Request(f"{CLOUD}/api/handoff/{upload}/done", data=body, method="POST", headers={
        "Authorization": f"Bearer {STORE_TOKEN}", "Content-Type": "application/json", "User-Agent": "cherry-store"})
    try:
        urllib.request.urlopen(req, timeout=60).read()
    except OSError as err:
        print(f"couldn't tell Cherry Cloud: {err}", file=sys.stderr)


def main(event_path: str) -> int:
    event = json.loads(Path(event_path).read_text())
    name = os.environ.get("GITHUB_EVENT_NAME", "")
    work = Path(tempfile.mkdtemp())
    deb = work / "package.deb"

    if name == "issues":
        issue = event["issue"]
        number = str(issue["number"])
        try:
            action, request = request_from_issue(issue)
            if action == "publish":
                download(str(request.get("url", "")), deb)
                reply = publish(deb, request, f"github:{issue['user']['login']}")
            else:
                reply = withdraw(request)
            ok = True
        except (store.Rejected, json.JSONDecodeError, OSError) as err:
            reply, ok = f"Not published: {err}", False
        gh("issue", "comment", number, "--body-file", "-", input=reply)
        gh("issue", "close", number, "--reason", "completed" if ok else "not planned")
        print(reply)
        return 0

    if name == "repository_dispatch":
        payload = event.get("client_payload") or {}
        upload, request = str(payload.get("upload", "")), payload.get("request") or {}
        via = f"cherry:{payload.get('username', '')}"
        try:
            if event["action"] == "cherry-upload":
                if not re.fullmatch(r"[A-Za-z0-9_-]{8,64}", upload):
                    raise store.Rejected("bad upload id")
                for i in range(int(payload.get("chunks", 0))):
                    download(f"{CLOUD}/api/handoff/{upload}/chunks/{i}", deb, {"Authorization": f"Bearer {STORE_TOKEN}"})
                reply = publish(deb, request, via)
            else:
                reply = withdraw(request)
            ok = True
        except (store.Rejected, OSError, ValueError) as err:
            reply, ok = f"Not published: {err}", False
        except Exception:
            cloud_done(upload, False, "The store had a problem; try again later.")
            raise
        cloud_done(upload, ok, reply)
        print(reply)
        return 0

    if name == "workflow_dispatch":
        inputs = event.get("inputs") or {}
        pkg = inputs.get("name", "")
        if inputs.get("action") == "restore":
            store.restore(pkg)
            commit(f"Restore {pkg}")
        else:
            store.takedown(pkg, inputs.get("reason", ""))
            commit(f"Take down {pkg}")
        return 0

    print(f"nothing to do for {name}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else os.environ["GITHUB_EVENT_PATH"]))
