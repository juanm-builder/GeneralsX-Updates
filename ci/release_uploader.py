#!/usr/bin/env python3
"""Scoped release transport; credentials stay in memory. No automatic CLI writes."""
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import plistlib
import subprocess
import tempfile
from urllib.parse import urlencode,urlsplit
from release_config import API,REPO,TAG
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
CHUNK=4*1024*1024
SMALL_LIMIT=1024*1024

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

def write_report(path, payload):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2) + "\n")
    temporary.replace(path)
