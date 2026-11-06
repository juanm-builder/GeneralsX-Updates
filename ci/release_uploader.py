#!/usr/bin/env python3
"""Prepare/verify this release; remote writes require --upload or --publish.

Authentication comes only from git credential fill and stays in process memory.
No existing asset is deleted or replaced, even after an interrupted upload.
"""

import argparse
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import plistlib
import re
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlencode, urlsplit

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
REPO = "juanm-builder/GeneralsX-Updates"
VERSION = "1.0.5.11"
TAG = "v" + VERSION
API = "https://api.github.com/repos/" + REPO
TITLE = "Generals X Suite " + VERSION
PARTS = [f"GeneralsX-{VERSION}-macos-arm64.dmg.part{i:02d}" for i in range(1, 4)]
SOURCE = f"GeneralsX-{VERSION}-source.tar.gz"
IMAGE = f"GeneralsX-{VERSION}-macos-arm64.dmg"
SMALL = ["SHA256SUMS.txt", "suite-update.json", "suite-update.json.sig"]
NAMES = PARTS + [SOURCE] + SMALL
CHUNK = 4 * 1024 * 1024
SMALL_LIMIT = 1024 * 1024


class ReleaseError(Exception):
    pass


class HTTPFailure(ReleaseError):
    def __init__(self, status):
        self.status = status
        super().__init__(f"GitHub request returned HTTP {status}; response body withheld.")


def require(condition, message):
    if not condition:
        raise ReleaseError(message)


def stamp(path):
    stat = path.stat()
    return (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns)


def local_assets(directory):
    require(directory.is_dir(), f"Missing asset directory: {directory}")
    actual = {p.name for p in directory.iterdir() if not p.name.startswith(".")}
    require(actual == set(NAMES), f"Expected exactly seven assets; missing={sorted(set(NAMES)-actual)}, unexpected={sorted(actual-set(NAMES))}")
    result = {}
    image_hash = hashlib.sha256()
    for name in NAMES:
        path = directory / name
        require(path.is_file() and not path.is_symlink(), f"Asset must be a regular file: {name}")
        before = stamp(path)
        require(before[2] > 0, f"Empty asset: {name}")
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            while block := stream.read(CHUNK):
                digest.update(block)
                if name in PARTS:
                    image_hash.update(block)
        require(stamp(path) == before, f"Asset changed while hashing: {name}")
        result[name] = {"name": name, "size": before[2], "sha256": digest.hexdigest(), "path": path, "stamp": before}
    require(all(result[n]["size"] <= SMALL_LIMIT for n in SMALL), "Small metadata asset unexpectedly exceeds 1 MiB")
    manifest = json.loads((directory / "suite-update.json").read_text())
    require(manifest.get("schema") == 1 and manifest.get("version") == VERSION, "Manifest schema/version mismatch")
    require(manifest.get("architecture") == "arm64", "Manifest architecture mismatch")
    require(manifest.get("bundleIdentifier") == "local.generalsx.portable.launcher", "Manifest bundle identifier mismatch")
    require(manifest.get("parts") == [{"name": name, "size": result[name]["size"], "sha256": result[name]["sha256"]} for name in PARTS], "Manifest part names/order/size/digests mismatch")
    require(manifest.get("imageSize") == sum(result[n]["size"] for n in PARTS), "Reconstructed image size mismatch")
    require(manifest.get("imageSHA256") == image_hash.hexdigest(), "Reconstructed image SHA256 mismatch")
    checksums = {}
    for line in (directory / "SHA256SUMS.txt").read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([^/\\]+)", line)
        require(match is not None, "Malformed SHA256SUMS.txt entry")
        digest, name = match.groups()
        require(name not in checksums, f"Duplicate checksum: {name}")
        checksums[name] = digest
    expected = {n: result[n]["sha256"] for n in PARTS + [SOURCE]}
    expected[IMAGE] = image_hash.hexdigest()
    require(checksums == expected, "SHA256SUMS.txt must match all three parts, reconstructed image, and source archive")
    return result


def verify_signature(directory, installed_app):
    info = plistlib.loads((installed_app / "Contents/Info.plist").read_bytes())
    require(info.get("SuiteUpdateRepository") == REPO, "Installed launcher's update repository mismatch")
    key = info.get("SuiteUpdatePublicKey", "")
    try:
        decoded = base64.b64decode(key, validate=True)
    except (ValueError, TypeError):
        raise ReleaseError("Installed launcher's public key is malformed") from None
    require(len(decoded) == 32, "Installed launcher's Ed25519 key has wrong length")
    swift = '''import Foundation
import CryptoKit
let args = CommandLine.arguments
let message = try Data(contentsOf: URL(fileURLWithPath: args[1]))
let text = try String(contentsOfFile: args[2], encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
guard let signature = Data(base64Encoded: text), let bytes = Data(base64Encoded: args[3]),
      try Curve25519.Signing.PublicKey(rawRepresentation: bytes).isValidSignature(signature, for: message)
else { exit(1) }
'''
    with tempfile.TemporaryDirectory(prefix="generalsx-public-signature-") as temp:
        script = Path(temp) / "verify.swift"
        script.write_text(swift)
        proc = subprocess.run(["/usr/bin/swift", str(script), str(directory / "suite-update.json"), str(directory / "suite-update.json.sig"), key], capture_output=True)
    require(proc.returncode == 0, "Manifest signature does not verify against the installed launcher's pinned public key")
    return hashlib.sha256(decoded).hexdigest()


def credential():
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    proc = subprocess.run(["git", "-c", "credential.interactive=false", "credential", "fill"], input="protocol=https\nhost=github.com\n\n", text=True, capture_output=True, env=env, cwd=ROOT)
    require(proc.returncode == 0, "git credential fill failed; helper output withheld")
    fields = dict(line.split("=", 1) for line in proc.stdout.splitlines() if "=" in line)
    token = fields.get("password", "")
    require(bool(token) and "\n" not in token and "\r" not in token, "Git credential helper returned no usable credential")
    return token


class GitHub:
    def __init__(self, token):
        self._token = token

    def request(self, method, url, *, payload=None, asset=None, binary=False, authenticated=True):
        parts = urlsplit(url)
        require(parts.scheme == "https" and not parts.username and not parts.password and parts.port in (None, 443), "Refusing unsafe request URL")
        if authenticated:
            require(parts.hostname in {"api.github.com", "uploads.github.com"}, "Refusing to send credentials outside GitHub API/upload hosts")
        else:
            require(parts.hostname in {"api.github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com", "github.com"}, "Unexpected asset-download redirect host")
        headers = {"User-Agent": "GeneralsX-Release-Verification", "Accept": "application/octet-stream" if binary else "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "Cache-Control": "no-cache"}
        if authenticated:
            headers["Authorization"] = "Bearer " + self._token
        body = None if payload is None else json.dumps(payload).encode()
        if body is not None:
            headers.update({"Content-Type": "application/json", "Content-Length": str(len(body))})
        if asset:
            require(stamp(asset["path"]) == asset["stamp"], f"Asset changed before upload: {asset['name']}")
            headers.update({"Content-Type": "application/octet-stream", "Content-Length": str(asset["size"])})
        connection = http.client.HTTPSConnection(parts.hostname, timeout=180)
        try:
            path = parts.path + (("?" + parts.query) if parts.query else "")
            connection.putrequest(method, path)
            for key, value in headers.items():
                connection.putheader(key, value)
            connection.endheaders()
            if asset:
                digest = hashlib.sha256()
                total = 0
                with asset["path"].open("rb") as stream:
                    while block := stream.read(CHUNK):
                        connection.send(block)
                        digest.update(block)
                        total += len(block)
                require(total == asset["size"] and digest.hexdigest() == asset["sha256"] and stamp(asset["path"]) == asset["stamp"], f"Asset changed during upload: {asset['name']}; release remains unpublished")
            elif body is not None:
                connection.send(body)
            response = connection.getresponse()
            status = response.status
            location = response.getheader("Location")
            limit = SMALL_LIMIT if binary else 8 * SMALL_LIMIT
            data = response.read(limit + 1)
            require(len(data) <= limit, "Unexpectedly large API/download response")
            return status, location, data
        except ReleaseError:
            raise
        except Exception:
            # Never include request headers, credentials, signed URLs, or server bodies.
            raise ReleaseError("GitHub transport failed; remote state may have changed. Re-run verification or upload to reconcile safely.") from None
        finally:
            connection.close()

    def json(self, method, url, payload=None):
        status, _, data = self.request(method, url, payload=payload)
        if not 200 <= status < 300:
            raise HTTPFailure(status)
        return json.loads(data)

    def pages(self, url):
        result = []
        for page in range(1, 101):
            batch = self.json("GET", f"{url}?per_page=100&page={page}")
            require(isinstance(batch, list), "Expected paginated API list")
            result.extend(batch)
            if len(batch) < 100:
                return result
        raise ReleaseError("Pagination exceeded safety bound")

    def release(self):
        # Listing includes drafts visible to this authenticated account.
        matches = [r for r in self.pages(API + "/releases") if r.get("tag_name") == TAG]
        require(len(matches) <= 1, "Multiple releases match the tag; manual review required")
        return matches[0] if matches else None

    def assets(self, release):
        return self.pages(f"{API}/releases/{release['id']}/assets")

    def upload(self, release, asset):
        base = release["upload_url"].split("{", 1)[0]
        endpoint = urlsplit(base)
        require(endpoint.hostname == "uploads.github.com" and endpoint.path == f"/repos/{REPO}/releases/{release['id']}/assets" and not endpoint.query, "Unexpected upload endpoint")
        status, _, data = self.request("POST", base + "?" + urlencode({"name": asset["name"]}), asset=asset)
        if status != 201:
            raise HTTPFailure(status)
        return json.loads(data)

    def download_small(self, remote):
        url = f"{API}/releases/assets/{remote['id']}"
        authenticated = True
        for _ in range(5):
            status, location, data = self.request("GET", url, binary=True, authenticated=authenticated)
            if status == 200:
                return data
            if status in {301, 302, 303, 307, 308} and location:
                # Never forward the GitHub credential across a redirect.
                url, authenticated = location, False
                continue
            raise HTTPFailure(status)
        raise ReleaseError("Too many asset download redirects")


def check_release(release, notes):
    require(release.get("tag_name") == TAG, "Release tag mismatch")
    require(not release.get("prerelease"), "Release is unexpectedly marked prerelease")
    require(release.get("body", "") == notes, "Release notes differ from the local notes; review them before continuing")


def remote_index(api, release, local, require_complete):
    indexed = {}
    for asset in api.assets(release):
        name = asset.get("name")
        require(name in local and name not in indexed, f"Unexpected/duplicate remote asset: {name}")
        expected = local[name]
        require(asset.get("state") == "uploaded" and asset.get("size") == expected["size"] and asset.get("digest") == "sha256:" + expected["sha256"], f"Existing remote asset is incomplete or differs: {name}. Nothing will be replaced; manual review required.")
        indexed[name] = asset
    if require_complete:
        require(set(indexed) == set(local), "Remote release does not contain all seven verified assets")
    return indexed


def verify_remote(api, release, local, notes):
    check_release(release, notes)
    for name, asset in local.items():
        require(stamp(asset["path"]) == asset["stamp"], f"Local asset changed after validation: {name}")
    indexed = remote_index(api, release, local, True)
    for name in SMALL:
        require(stamp(local[name]["path"]) == local[name]["stamp"], f"Local metadata changed: {name}")
        downloaded = api.download_small(indexed[name])
        require(downloaded == local[name]["path"].read_bytes(), f"Downloaded metadata differs: {name}")
    return [{"name": name, "size": local[name]["size"], "sha256": local[name]["sha256"], "asset_id": indexed[name]["id"], "remote_digest_verified": True, "download_exact_match": name in SMALL} for name in NAMES]


def upload_draft(api, local, notes):
    release = api.release()
    if release is None:
        try:
            release = api.json("POST", API + "/releases", {"tag_name": TAG, "name": TITLE, "body": notes, "draft": True, "prerelease": False})
        except HTTPFailure as exc:
            if exc.status != 422:
                raise
            release = api.release()
            require(release is not None, "Draft creation failed; no matching release found")
    check_release(release, notes)
    existing = remote_index(api, release, local, False)
    missing = [name for name in NAMES if name not in existing]
    require(not missing or release.get("draft") is True, "Refusing to add assets to an already published release")
    for name in missing:
        print(f"Uploading {name} ({local[name]['size']} bytes)", flush=True)
        uploaded = api.upload(release, local[name])
        require(uploaded.get("state") == "uploaded" and uploaded.get("name") == name and uploaded.get("size") == local[name]["size"] and uploaded.get("digest") == "sha256:" + local[name]["sha256"], f"Upload confirmation differs: {name}; release remains unpublished")
    return release, verify_remote(api, release, local, notes)


def publish(api, local, notes):
    release = api.release()
    require(release is not None, "No release exists; run --upload first")
    verified = verify_remote(api, release, local, notes)
    if release.get("draft"):
        release = api.json("PATCH", f"{API}/releases/{release['id']}", {"draft": False, "prerelease": False, "make_latest": "true"})
    require(release.get("draft") is False, "Release did not become public")
    verified = verify_remote(api, release, local, notes)
    latest = api.json("GET", API + "/releases/latest")
    require(latest.get("id") == release["id"] and latest.get("tag_name") == TAG, "Release is public but not latest; manual review required")
    return release, verified


def write_report(path, payload):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2) + "\n")
    temporary.replace(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--check-local", action="store_true", help="Local-only checks (default); no credential access")
    modes.add_argument("--upload", action="store_true", help="Create/reuse draft, upload missing assets, verify; never publish")
    modes.add_argument("--verify", action="store_true", help="Read-only verification of existing release")
    modes.add_argument("--publish", action="store_true", help="Re-verify all assets, then explicitly publish draft as latest")
    parser.add_argument("--assets", type=Path, default=ROOT / "Output" / ("GitHub-" + VERSION))
    parser.add_argument("--notes", type=Path, default=HERE / "release-notes.txt")
    parser.add_argument("--installed-app", type=Path, default=Path("/Applications/Generals X Launcher.app"))
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    mode = "upload" if args.upload else "publish" if args.publish else "verify" if args.verify else "local"
    local = local_assets(args.assets.resolve())
    key_hash = verify_signature(args.assets.resolve(), args.installed_app.resolve())
    report = {"repository": REPO, "tag": TAG, "mode": mode, "checked_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "installed_public_key_sha256": key_hash, "manifest_signature_verified": True, "assets": [{k: v for k, v in local[n].items() if k not in {"path", "stamp"}} for n in NAMES], "remote_mutations_requested": mode in {"upload", "publish"}}
    if mode != "local":
        notes = args.notes.read_text()
        require(bool(notes.strip()), "Release notes must not be empty")
        api = GitHub(credential())
        if mode == "upload":
            release, verified = upload_draft(api, local, notes)
        elif mode == "publish":
            release, verified = publish(api, local, notes)
        else:
            release = api.release()
            require(release is not None, "No matching release exists")
            verified = verify_remote(api, release, local, notes)
        report.update({"release_id": release["id"], "release_url": release.get("html_url"), "draft": release.get("draft"), "assets": verified, "large_asset_verification": "GitHub server SHA256 + size; large assets are not downloaded again", "small_asset_verification": "Authenticated asset download; exact local byte comparison; manifest signature checked against installed public key"})
    output = args.report or HERE / ("release-" + mode + "-verification.json")
    write_report(output, report)
    print(f"PASS: {mode} verification; report {output}", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (ReleaseError, OSError, ValueError, KeyError) as exc:
        # Exception messages from our code contain no credential material.
        if isinstance(exc, ReleaseError):
            print("ERROR: " + str(exc), file=sys.stderr)
        else:
            print("ERROR: local input/API schema could not be read; check files and metadata.", file=sys.stderr)
        sys.exit(1)
