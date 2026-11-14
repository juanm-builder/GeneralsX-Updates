"""Prepare a signed file snapshot and ONLY new immutable gzip objects.

No network or uploads. Keep previous public object releases: snapshots can refer
to them indefinitely. --previous-manifest requires its detached signature. CI may
prepare an unsigned snapshot; private release keys never need to enter CI.
"""
from pathlib import Path
import argparse
import base64
import gzip
import hashlib
import json
import os
import plistlib
import re
import stat
import subprocess
import tempfile
import unicodedata

ROOT = Path(__file__).resolve().parents[1]
MAX_MANIFEST = 4 * 1024 * 1024
MAX_ASSET = 2 * 1024**3


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + '\n')


def valid_path(path):
    return isinstance(path, str) and (path == '.' or (
        0 < len(path.encode()) <= 1024 and not path.startswith('/') and '\\' not in path
        and not any(ord(c) < 32 or ord(c) == 127 for c in path)
        and len(path.split('/')) <= 32 and all(p not in ('', '.', '..') for p in path.split('/'))))


def valid_tag(tag):
    return isinstance(tag, str) and re.fullmatch(r'(files-)?v[0-9][A-Za-z0-9._-]{0,90}', tag) is not None


def validate_files(files, expanded):
    require(isinstance(files, list) and 0 < len(files) <= 4096, 'Invalid file count')
    paths, folded, objects = {}, set(), {}
    logical_size = 0
    for item in files:
        path = item.get('path'); require(valid_path(path), 'Unsafe update path')
        canonical = unicodedata.normalize('NFD', path).casefold()
        require(canonical not in folded, 'Case-insensitive/canonical path collision')
        folded.add(canonical); paths[path] = item
        kind = item.get('kind'); mode = item.get('mode')
        require(type(mode) is int, 'Invalid permissions')
        base = {'path', 'kind', 'mode'}
        if kind == 'directory':
            require(set(item) == base and mode == 0o755, 'Invalid directory')
        elif kind == 'symlink':
            require(set(item) == base | {'target'} and mode == 0o755 and isinstance(item['target'], str), 'Invalid link')
        else:
            require(kind in ('file', 'hardlink') and path != '.' and mode in (0o644, 0o755), 'Unsupported file type/mode')
            size, digest = item.get('size'), item.get('sha256')
            require(type(size) is int and 0 <= size <= 8 * 1024**3 and isinstance(digest, str) and re.fullmatch('[0-9a-f]{64}', digest), 'Invalid file identity')
            logical_size += size
            base |= {'size', 'sha256'}
            if kind == 'hardlink':
                require(set(item) == base | {'target'} and valid_path(item.get('target')), 'Invalid shared file')
            else:
                require(set(item) == base | {'tag', 'asset', 'downloadSize', 'downloadSHA256'}, 'Invalid file fields')
                require(valid_tag(item['tag']) and item['asset'] == 'gx-' + digest + '.gz', 'Unsafe object identity')
                require(type(item['downloadSize']) is int and 0 < item['downloadSize'] < MAX_ASSET and
                        re.fullmatch('[0-9a-f]{64}', item['downloadSHA256']), 'Invalid object size/hash')
                identity = (size, item['tag'], item['asset'], item['downloadSize'], item['downloadSHA256'])
                require(digest not in objects or objects[digest] == identity, 'Conflicting object references')
                objects[digest] = identity
    require(paths.get('.', {}).get('kind') == 'directory' and logical_size == expanded and 0 < expanded <= 100 * 1024**3, 'Invalid complete file snapshot')
    require(sum(value[3] for value in objects.values()) <= 32 * 1024**3, 'Too much download data')
    for path, item in paths.items():
        if path == '.': continue
        parent = Path(path).parent
        while parent != Path('.'):
            require(paths.get(parent.as_posix(), {}).get('kind') == 'directory', 'Path traverses a missing directory or link')
            parent = parent.parent
        if item['kind'] == 'hardlink':
            target = paths.get(item['target'], {})
            require(target.get('kind') == 'file' and all(item.get(k) == target.get(k) for k in ('mode', 'size', 'sha256')), 'Invalid shared-file target')
        elif item['kind'] == 'symlink':
            target = item['target']
            require(target and not target.startswith('/') and '\\' not in target and not any(ord(c) < 32 or ord(c) == 127 for c in target), 'Unsafe link target')
            resolved = os.path.normpath(os.path.join(os.path.dirname(path), target))
            require(valid_path(resolved) and paths.get(resolved, {}).get('kind') in ('file', 'hardlink'), 'Escaping/dangling/link-chain target')


def signing_tool():
    source = ROOT / 'tools/SignSuiteUpdate.swift'
    executable = ROOT / 'build/SignSuiteUpdate'
    if not executable.exists() or executable.stat().st_mtime_ns < source.stat().st_mtime_ns:
        cache = ROOT / 'build/swift-module-cache'; cache.mkdir(parents=True, exist_ok=True)
        subprocess.run(['xcrun', 'swiftc', '-module-cache-path', str(cache), '-target', 'arm64-apple-macos11.0', str(source), '-o', str(executable)], check=True)
    return executable


def previous_objects(manifest, signature, public_key, info):
    require((manifest is None) == (signature is None), 'Previous manifest and signature must be supplied together')
    if manifest is None: return {}
    require(manifest.stat().st_size <= MAX_MANIFEST, 'Previous snapshot is too large')
    with tempfile.TemporaryDirectory(prefix='generalsx-file-signature-') as work:
        key_path = Path(work) / 'public-key.txt'; key_path.write_text(public_key + '\n')
        subprocess.run([str(signing_tool()), 'verify', str(manifest), str(key_path), str(signature)], check=True)
    value = json.loads(manifest.read_text())
    require(value.get('schema') == 2 and value.get('bundleIdentifier') == info['CFBundleIdentifier'] and
            value.get('architecture') == 'arm64' and type(value.get('sequence')) is int and
            0 < value['sequence'] < info['SuiteUpdateSequence'], 'Previous snapshot identity/sequence mismatch')
    validate_files(value.get('files'), value.get('expandedSize'))
    return {item['sha256']: item for item in value['files'] if item['kind'] == 'file'}


def scan(app):
    items, inodes, hashes = [], {}, {}
    for path in [app] + sorted(app.rglob('*'), key=lambda p: p.relative_to(app).as_posix()):
        relative = path.relative_to(app).as_posix(); info = path.lstat()
        item = {'path': relative, 'kind': '', 'mode': stat.S_IMODE(info.st_mode)}
        if stat.S_ISLNK(info.st_mode):
            item.update(kind='symlink', mode=0o755, target=os.readlink(path))
        elif stat.S_ISDIR(info.st_mode):
            require(item['mode'] == 0o755, f'Unexpected directory mode: {relative}')
            item['kind'] = 'directory'
        else:
            require(stat.S_ISREG(info.st_mode) and item['mode'] in (0o644, 0o755), f'Unsupported app item: {relative}')
            inode = (info.st_dev, info.st_ino)
            if inode not in hashes: hashes[inode] = sha(path)
            item.update(kind='file', size=info.st_size, sha256=hashes[inode])
            if inode in inodes: item.update(kind='hardlink', target=inodes[inode])
            else: inodes[inode] = relative
        items.append(item)
    return items


def prepare(app, output, tag, *, previous_manifest=None, previous_signature=None, signing_key=None):
    require(valid_tag(tag), 'Invalid object release tag')
    app = app.resolve(strict=True)
    subprocess.run(['codesign', '--verify', '--deep', '--strict', str(app)], check=True)
    info = plistlib.loads((app / 'Contents/Info.plist').read_bytes())
    public_key = info['SuiteUpdatePublicKey']
    require(len(base64.b64decode(public_key, validate=True)) == 32, 'Invalid pinned update key')
    require(re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', info['SuiteUpdateRepository']) and
            all(p not in ('.', '..') for p in info['SuiteUpdateRepository'].split('/')), 'Invalid update repository')
    require(type(info['SuiteUpdateSequence']) is int and info['SuiteUpdateSequence'] > 0, 'Invalid update sequence')
    version = info['SuiteBuildLabel'].split()[-1]
    require(re.fullmatch('[0-9.]+', version) and tag == 'files-v' + version, 'Object tag must identify this app version')
    old = previous_objects(previous_manifest, previous_signature, public_key, info)
    require(not output.exists() or not any(output.iterdir()), 'Output must be empty; never overwrite published objects')
    output.mkdir(parents=True, exist_ok=True); blobs = output / 'objects'; blobs.mkdir()
    files = scan(app); objects, uploaded, reused = {}, [], set()
    for item in files:
        if item['kind'] != 'file': continue
        digest = item['sha256']; prior = old.get(digest)
        if prior is not None:
            require(prior['size'] == item['size'], 'Previous object identity conflict')
            reference = {key: prior[key] for key in ('tag', 'asset', 'downloadSize', 'downloadSHA256')}; reused.add(digest)
        elif digest in objects:
            reference = objects[digest]
        else:
            source = app / item['path']; name = 'gx-' + digest + '.gz'; destination = blobs / name
            raw_hash = hashlib.sha256(); count = 0
            with source.open('rb') as stream, destination.open('xb') as result:
                with gzip.GzipFile(filename='', fileobj=result, mode='wb', compresslevel=6, mtime=0) as compressed:
                    while data := stream.read(1024 * 1024):
                        raw_hash.update(data); count += len(data); compressed.write(data)
            require(count == item['size'] and raw_hash.hexdigest() == digest, 'The staged app changed during packaging')
            length = destination.stat().st_size
            require(0 < length < MAX_ASSET, 'Object exceeds GitHub asset size limit')
            reference = {'tag': tag, 'asset': name, 'downloadSize': length, 'downloadSHA256': sha(destination)}
            uploaded.append({'name': name, 'size': length, 'sha256': reference['downloadSHA256']})
        objects[digest] = reference; item.update(reference)
    expanded = sum(item.get('size', 0) for item in files)
    validate_files(files, expanded)
    codesign = subprocess.run(['codesign', '-d', '--verbose=4', str(app)], capture_output=True, text=True, check=True)
    identity = re.search(r'^CDHash=([0-9a-f]{40})$', codesign.stderr, re.MULTILINE)
    require(identity is not None, 'Signed app identity missing')
    value = {'schema': 2, 'sequence': info['SuiteUpdateSequence'], 'version': version,
        'bundleVersion': info['CFBundleVersion'], 'bundleIdentifier': info['CFBundleIdentifier'],
        'minimumSystemVersion': info['LSMinimumSystemVersion'], 'architecture': 'arm64',
        'appName': app.name, 'appCDHash': identity[1], 'expandedSize': expanded, 'files': files}
    manifest = output / 'suite-files.json'; write_json(manifest, value)
    require(manifest.stat().st_size <= MAX_MANIFEST, 'Snapshot exceeds updater metadata limit')
    if signing_key is not None:
        signature = output / 'suite-files.json.sig'
        subprocess.run([str(signing_tool()), 'sign', str(manifest), str(signing_key), str(signature)], check=True)
        with tempfile.TemporaryDirectory(prefix='generalsx-new-file-signature-') as work:
            key = Path(work) / 'public-key.txt'; key.write_text(public_key + '\n')
            subprocess.run([str(signing_tool()), 'verify', str(manifest), str(key), str(signature)], check=True)
    references = sorted({(item['tag'], item['asset'], item['downloadSize'], item['downloadSHA256']) for item in files if item['kind'] == 'file'})
    plan = {'schema': 1, 'repository': info['SuiteUpdateRepository'], 'version': version,
        'sequence': info['SuiteUpdateSequence'], 'objectTag': tag, 'manifestSHA256': sha(manifest),
        'appCDHash': identity[1], 'fileEntries': len(files), 'newObjects': uploaded,
        'reusedObjects': len(reused), 'newUploadBytes': sum(item['size'] for item in uploaded),
        'requiredObjects': [{'tag': tag, 'name': name, 'size': size, 'sha256': digest} for tag, name, size, digest in references],
        'previousManifestSHA256': sha(previous_manifest) if previous_manifest else None,
        'signed': signing_key is not None, 'privateKeyIncluded': False}
    write_json(output / 'upload-plan.json', plan)
    print(json.dumps({key: plan[key] for key in ('version', 'fileEntries', 'reusedObjects', 'newUploadBytes', 'signed')}, indent=2))
    return value, plan


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--app', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--object-tag', required=True)
    parser.add_argument('--previous-manifest', type=Path)
    parser.add_argument('--previous-signature', type=Path)
    parser.add_argument('--signing-key', type=Path)
    args = parser.parse_args()
    prepare(args.app, args.output, args.object_tag, previous_manifest=args.previous_manifest,
            previous_signature=args.previous_signature, signing_key=args.signing_key)
