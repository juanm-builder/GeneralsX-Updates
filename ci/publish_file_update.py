"""Verify, upload, and optionally publish a complete file update on GitHub.

Default: read-only remote validation. --upload writes verified assets to EXISTING
drafts. --publish publishes the object release first and the app release last,
only after every old/new object, source archive and signed manifest is present.
No remote deletion/overwriting. Never delete referenced object releases.
"""
from pathlib import Path
import argparse
import base64
import hashlib
import json
import os
import plistlib
import re
import subprocess
import tempfile
import time

from github_release_store import API, REPO, GitHub, credential, require, stamp, upload_verified, incomplete_asset
from prepare_file_update import sha, signing_tool, validate_files, valid_tag, scan


def asset_map(api, release):
    values = api.assets(release)
    mapped = {value['name']: value for value in values}
    require(len(mapped) == len(values), 'Duplicate release asset names')
    return mapped


def check_remote(remote, expected):
    require(remote is not None and remote.get('state') == 'uploaded' and
            remote.get('size') == expected['size'] and remote.get('digest') == 'sha256:' + expected['sha256'],
            'A required GitHub asset is missing, incomplete or has an unexpected checksum')


def local_asset(path, name=None):
    require(path.is_file() and not path.is_symlink(), 'Upload input must be a regular file')
    before = stamp(path); digest = sha(path)
    require(before == stamp(path), 'Upload input changed while being checked')
    return {'name': name or path.name, 'path': path, 'size': before[2], 'sha256': digest, 'stamp': before}


def local_plan(app, directory, source_archive):
    manifest, signature = directory / 'suite-files.json', directory / 'suite-files.json.sig'
    require(manifest.is_file() and manifest.stat().st_size <= 4 * 1024 * 1024 and signature.is_file(), 'Signed file snapshot is required')
    info = plistlib.loads((app / 'Contents/Info.plist').read_bytes())
    require(info.get('SuiteUpdateRepository') == REPO, 'Only this suite update repository is allowed')
    subprocess.run(['codesign', '--verify', '--deep', '--strict', str(app)], check=True)
    with tempfile.TemporaryDirectory(prefix='generalsx-publish-key-') as work:
        key = Path(work) / 'public-key.txt'; key.write_text(info['SuiteUpdatePublicKey'] + '\n')
        subprocess.run([str(signing_tool()), 'verify', str(manifest), str(key), str(signature)], check=True)
    value = json.loads(manifest.read_text()); plan = json.loads((directory / 'upload-plan.json').read_text())
    require(value['schema'] == 2 and value['sequence'] == info['SuiteUpdateSequence'] and
            value['bundleIdentifier'] == info['CFBundleIdentifier'] and value['bundleVersion'] == info['CFBundleVersion'] and
            value['minimumSystemVersion'] == info['LSMinimumSystemVersion'] and value['architecture'] == 'arm64', 'Snapshot app identity mismatch')
    signed = subprocess.run(['codesign', '-d', '--verbose=4', str(app)], capture_output=True, text=True, check=True)
    match = re.search(r'^CDHash=([0-9a-f]{40})$', signed.stderr, re.MULTILINE)
    require(match and match[1] == value['appCDHash'], 'Snapshot does not match staged app code signature')
    validate_files(value['files'], value['expandedSize'])
    content_fields = ('path', 'kind', 'mode', 'size', 'sha256', 'target')
    recorded_tree = [{k: item[k] for k in content_fields if k in item} for item in value['files']]
    require(recorded_tree == scan(app), 'Snapshot files do not match the staged app')
    version = value['version']; tag = 'files-v' + version
    require(valid_tag(tag) and re.fullmatch('[0-9.]+', version), 'Unsafe release version')
    require(plan['schema'] == 1 and plan['repository'] == REPO and plan['version'] == version and
            plan['objectTag'] == tag and plan['sequence'] == value['sequence'] and plan['manifestSHA256'] == sha(manifest), 'Upload plan mismatch')
    required = {(item['tag'], item['asset']): {'name': item['asset'], 'size': item['downloadSize'], 'sha256': item['downloadSHA256']}
                for item in value['files'] if item['kind'] == 'file'}
    declared = {(item['tag'], item['name']): {k: item[k] for k in ('name', 'size', 'sha256')} for item in plan['requiredObjects']}
    require(required == declared and len(declared) == len(plan['requiredObjects']), 'Upload dependencies do not match signed snapshot')
    new = {name: item for (source, name), item in required.items() if source == tag}
    require({item['name']: item for item in plan['newObjects']} == new and len(new) == len(plan['newObjects']), 'New object list mismatch')
    require({path.name for path in (directory / 'objects').iterdir()} == set(new), 'Unexpected upload file in object directory')
    objects = []
    for name, expected in new.items():
        asset = local_asset(directory / 'objects' / name)
        require(asset['size'] == expected['size'] and asset['sha256'] == expected['sha256'], 'Local object changed after packaging')
        objects.append(asset)
    require(source_archive.name == f'GeneralsX-{version}-source.tar.gz', 'Corresponding source archive identity mismatch')
    metadata = [local_asset(manifest), local_asset(signature), local_asset(source_archive)]
    return value, required, objects, metadata, info['SuiteUpdatePublicKey'], plan.get('previousManifestSHA256') is None


def verify_bridge(api, release, value, public_key):
    """First rollout must remain installable by the currently shipped v1 updater."""
    existing = asset_map(api, release)
    require('suite-update.json' in existing and 'suite-update.json.sig' in existing,
            'The first file-update release requires a signed full bridge installer for older launchers')
    full_bytes = api.download_small(existing['suite-update.json'])
    signature = api.download_small(existing['suite-update.json.sig'])
    with tempfile.TemporaryDirectory(prefix='generalsx-bridge-check-') as work:
        root = Path(work); (root / 'manifest').write_bytes(full_bytes); (root / 'signature').write_bytes(signature)
        (root / 'key').write_text(public_key + '\n')
        subprocess.run([str(signing_tool()), 'verify', str(root / 'manifest'), str(root / 'key'), str(root / 'signature')], check=True)
    full = json.loads(full_bytes)
    require(full.get('schema') == 1 and all(full.get(k) == value[k] for k in
            ('sequence', 'version', 'bundleVersion', 'bundleIdentifier', 'minimumSystemVersion', 'architecture', 'appName', 'appCDHash', 'expandedSize')),
            'The full bridge installer does not match the file-update release')
    parts = full.get('parts', [])
    require(0 < len(parts) <= 64 and sum(p['size'] for p in parts) == full['imageSize'] and
            re.fullmatch('[0-9a-f]{64}', full['imageSHA256']), 'Invalid full bridge download metadata')
    for number, part in enumerate(parts, 1):
        require(part['name'] == f'GeneralsX-{value["version"]}-macos-arm64.dmg.part{number:02d}' and
                0 < part['size'] <= 1024**3 and re.fullmatch('[0-9a-f]{64}', part['sha256']), 'Invalid bridge part')
        check_remote(existing.get(part['name']), part)
    manual = existing.get(f'GeneralsX-{value["version"]}-macos-arm64.tar.xz')
    require(manual and manual.get('state') == 'uploaded' and 0 < manual.get('size', 0) < 2 * 1024**3 and
            re.fullmatch('sha256:[0-9a-f]{64}', manual.get('digest', '')), 'The bridge requires a completed manual installer')


def run(api, value, required, objects, metadata, object_release_id, app_release_id, *, upload=False, publish=False,
        public_key=None, bootstrap=False):
    require(not publish or upload, 'Publishing requires explicit upload mode')
    version = value['version']; tag = 'files-v' + version
    object_release = api.json('GET', f'{API}/releases/{object_release_id}')
    app_release = api.json('GET', f'{API}/releases/{app_release_id}')
    require(object_release_id != app_release_id and object_release.get('tag_name') == tag and
            app_release.get('tag_name') == 'v' + version, 'Wrong app/object release IDs')
    require(app_release.get('draft') is True, 'The app release must remain an unpublished draft')
    require(object_release.get('draft') is True or object_release.get('prerelease') is True, 'Object release must be draft or a completed content prerelease')
    current = asset_map(api, object_release)
    expected_names = {name: expected for (source, name), expected in required.items() if source == tag}
    require(all(name in expected_names or incomplete_asset(item, expected_names) for name, item in current.items()),
            'Unexpected object-release assets; manual review needed')
    # Validate all old dependencies BEFORE uploading or publishing anything.
    previous = {}
    for (source, name), expected in required.items():
        if source == tag: continue
        if source not in previous:
            release = api.json('GET', API + '/releases/tags/' + source)
            require(release.get('tag_name') == source and release.get('draft') is False, 'A referenced object release is not public')
            previous[source] = asset_map(api, release)
        check_remote(previous[source].get(name), expected)
    def ensure(release, assets):
        existing = asset_map(api, release)
        for asset in assets:
            if asset['name'] in existing and existing[asset['name']].get('state') == 'uploaded':
                check_remote(existing[asset['name']], asset)
            elif upload:
                print('Uploading verified asset ' + asset['name'], flush=True)
                remote = upload_verified(api, release, asset, known_asset=existing.get(asset['name'])); check_remote(remote, asset)
                # Keep first-time bootstrap uploads below mutation rate limits.
                time.sleep(1.1)
            else:
                raise ValueError('Required asset is not uploaded: ' + asset['name'])
    ensure(object_release, objects)
    current = asset_map(api, object_release)
    for (source, name), expected in required.items():
        if source == tag: check_remote(current.get(name), expected)
    ensure(app_release, metadata)
    if publish:
        if bootstrap:
            require(public_key is not None, 'Bridge verification needs the pinned public key')
            verify_bridge(api, app_release, value, public_key)
        if object_release.get('draft'):
            object_release = api.json('PATCH', f'{API}/releases/{object_release_id}',
                {'draft': False, 'prerelease': True, 'make_latest': 'false'})
        require(object_release.get('draft') is False and object_release.get('prerelease') is True, 'Object publication was not confirmed')
        # Re-read every dependency and metadata object immediately before making
        # the app discoverable as Latest. There is no "latest patch only" shortcut.
        by_tag = {}
        for (source, name), expected in required.items():
            if source not in by_tag:
                release = api.json('GET', API + '/releases/tags/' + source)
                require(release.get('draft') is False, 'An update dependency is no longer public')
                by_tag[source] = asset_map(api, release)
            check_remote(by_tag[source].get(name), expected)
        app_release = api.json('GET', f'{API}/releases/{app_release_id}')
        require(app_release.get('draft') is True, 'The app release changed during verification')
        published = asset_map(api, app_release)
        for asset in metadata: check_remote(published.get(asset['name']), asset)
        if bootstrap: verify_bridge(api, app_release, value, public_key)
        app_release = api.json('PATCH', f'{API}/releases/{app_release_id}',
            {'draft': False, 'prerelease': False, 'make_latest': 'true'})
        latest = api.json('GET', API + '/releases/latest')
        require(app_release.get('draft') is False and latest.get('id') == app_release_id, 'Latest release publication was not confirmed')
    print('PASS: all referenced objects and signed metadata verified; ' + ('release published' if publish else 'app remains draft'), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--app', type=Path, required=True)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--source-archive', type=Path, required=True)
    parser.add_argument('--object-release-id', type=int, required=True)
    parser.add_argument('--app-release-id', type=int, required=True)
    parser.add_argument('--upload', action='store_true')
    parser.add_argument('--publish', action='store_true')
    args = parser.parse_args()
    value, required, objects, metadata, public_key, bootstrap = local_plan(args.app, args.directory, args.source_archive)
    api = GitHub(os.environ.get('GITHUB_TOKEN') or credential())
    run(api, value, required, objects, metadata, args.object_release_id, args.app_release_id,
        upload=args.upload, publish=args.publish, public_key=public_key, bootstrap=bootstrap)
