#!/usr/bin/env python3
"""Scoped GitHub release transport. No CLI side effects; credentials stay in memory.

Copied from the reviewed suite release transport. All mutations require explicit
caller actions; uploaded bytes, HTTPS origins and server digests are checked.
"""
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import plistlib
import subprocess
import tempfile
import time
from urllib.parse import urlencode,urlsplit
REPO = "juanm-builder/GeneralsX-Updates"
API = "https://api.github.com/repos/" + REPO
HERE=Path(__file__).resolve().parent
ROOT=HERE.parent
CHUNK=4*1024*1024
SMALL_LIMIT=4*1024*1024

class ReleaseError(Exception):
    pass

class HTTPFailure(ReleaseError):
    def __init__(self, status, retryable=False, retry_after=0):
        self.status = status
        self.retryable = retryable or status in {408, 429, 500, 502, 503, 504}
        self.retry_after = min(30, max(0, retry_after))
        super().__init__(f"GitHub request returned HTTP {status}; response body withheld.")

class TransportFailure(ReleaseError):
    pass

def require(condition, message):
    if not condition:
        raise ReleaseError(message)

def stamp(path):
    stat = path.stat()
    return (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns)

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
        require(method == "GET" or (authenticated and bool(self._token)), "GitHub mutations require an explicit credential")
        if authenticated and self._token:
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
            retry_header = response.getheader("Retry-After", "")
            self._retry_after = min(30, int(retry_header)) if retry_header.isdecimal() else 0
            status = response.status
            location = response.getheader("Location")
            limit = SMALL_LIMIT if binary else 8 * SMALL_LIMIT
            data = response.read(limit + 1)
            require(len(data) <= limit, "Unexpectedly large API/download response")
            return status, location, data
        except ReleaseError:
            raise
        except Exception as error:
            # Never include request headers, credentials, signed URLs, or server bodies.
            raise TransportFailure(f"GitHub transport failed ({type(error).__name__}); remote state must be reconciled before retry.") from None
        finally:
            connection.close()

    def json(self, method, url, payload=None):
        for attempt in range(4):
            try:
                status, _, data = self.request(method, url, payload=payload)
                if not 200 <= status < 300:
                    raise self.http_failure(status, data)
                try: return json.loads(data)
                except (ValueError, UnicodeError): raise ReleaseError("GitHub returned invalid metadata; response body withheld.") from None
            except (TransportFailure, HTTPFailure) as error:
                if method != "GET" or attempt == 3 or (isinstance(error, HTTPFailure) and not error.retryable): raise
                time.sleep(max(2 ** attempt, getattr(error, 'retry_after', 0)))

    def http_failure(self, status, data):
        try: message = json.loads(data).get('message', '').lower()
        except (ValueError, AttributeError, UnicodeError): message = ''
        limited = status == 403 and ('rate limit' in message or 'abuse' in message)
        return HTTPFailure(status, retryable=limited, retry_after=getattr(self, '_retry_after', 0))

    def pages(self, url):
        result = []
        for page in range(1, 101):
            batch = self.json("GET", f"{url}?per_page=100&page={page}")
            require(isinstance(batch, list), "Expected paginated API list")
            result.extend(batch)
            if len(batch) < 100:
                return result
        raise ReleaseError("Pagination exceeded safety bound")

    def assets(self, release):
        return self.pages(f"{API}/releases/{release['id']}/assets")

    def upload(self, release, asset):
        base = release["upload_url"].split("{", 1)[0]
        endpoint = urlsplit(base)
        require(endpoint.hostname == "uploads.github.com" and endpoint.path == f"/repos/{REPO}/releases/{release['id']}/assets" and not endpoint.query, "Unexpected upload endpoint")
        status, _, data = self.request("POST", base + "?" + urlencode({"name": asset["name"]}), asset=asset)
        if status != 201:
            raise self.http_failure(status, data)
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


def incomplete_asset(asset, expected_names):
    """Only a named, preserved partial transfer created by this uploader."""
    if type(asset.get('id')) is not int or asset['id'] <= 0: return False
    suffix = '.incomplete-' + str(asset['id'])
    name = asset.get('name', '')
    original = name[:-len(suffix)] if name.endswith(suffix) else ''
    if asset.get('label') != 'Incomplete uploader transfer; not used' or original not in expected_names: return False
    if asset.get('state') == 'starter' and asset.get('size') == 0: return True
    expected = expected_names.get(original) if isinstance(expected_names, dict) else None
    return bool(expected and asset.get('state') == 'uploaded' and asset.get('size') == expected['size'] and
                asset.get('digest') == 'sha256:' + expected['sha256'])

_UNKNOWN_ASSET = object()


def upload_verified(api, release, asset, attempts=4, known_asset=_UNKNOWN_ASSET):
    """Reconcile lost upload responses; never overwrite or delete existing bytes.

    A GitHub `starter` placeholder is retained under an explicitly labelled name
    before retrying. Completed uploads are accepted only with the exact digest.
    """
    def matches(remote):
        require(remote.get('state') == 'uploaded' and remote.get('size') == asset['size'] and
                remote.get('digest') == 'sha256:' + asset['sha256'], 'Existing/uploaded asset checksum mismatch; nothing overwritten')
        return remote
    def find(current):
        candidates = [a for a in api.assets(current) if a.get('name') == asset['name']]
        require(len(candidates) <= 1, 'Duplicate asset names')
        return candidates[0] if candidates else None
    for attempt in range(attempts):
        try:
            current = api.json('GET', f'{API}/releases/{release["id"]}')
            require(current.get('tag_name') == release.get('tag_name'), 'Upload release identity changed')
            existing = known_asset if attempt == 0 and known_asset is not _UNKNOWN_ASSET else find(current)
            if existing and existing.get('state') == 'uploaded': return matches(existing)
            require(current.get('draft') is True, 'New uploads require an unpublished draft')
            if existing:
                require(existing.get('state') == 'starter' and type(existing.get('id')) is int,
                        'Conflicting asset state; manual review needed')
                # Renaming is reversible and preserves any received bytes.
                api.json('PATCH', f'{API}/releases/assets/{existing["id"]}',
                    {'name': asset['name'] + '.incomplete-' + str(existing['id']),
                     'label': 'Incomplete uploader transfer; not used'})
            return matches(api.upload(current, asset))
        except (TransportFailure, HTTPFailure) as error:
            retryable = isinstance(error, TransportFailure) or error.retryable or error.status == 422
            if not retryable: raise
            # The server may have committed all bytes before the response was lost.
            try:
                recovered = find(release)
                if recovered and recovered.get('state') == 'uploaded': return matches(recovered)
            except (TransportFailure, HTTPFailure): pass
            if attempt == attempts - 1: raise
            print(f'Reconciling interrupted upload, retry {attempt + 1}/{attempts - 1}', flush=True)
            time.sleep(max(2 ** attempt, getattr(error, 'retry_after', 0)))
