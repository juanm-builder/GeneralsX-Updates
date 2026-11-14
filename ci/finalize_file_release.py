"""CI-only final publication after release manifests have been signed locally.

No private key or local git credential is used. The explicitly dispatched workflow
provides a contents-scoped GitHub token, a reviewed config and expected build run.
"""
from pathlib import Path
import argparse
import base64
import hashlib
import json
import os
import subprocess
import tempfile

from github_release_store import API, REPO, GitHub, require
from prepare_file_update import signing_tool, validate_files
from publish_file_update import asset_map, check_remote, run


def finalize(api, config, expected_commit, expected_run):
    version = config['version']
    matches = [r for r in api.pages(API + '/releases') if r.get('tag_name') == 'v' + version]
    require(len(matches) == 1 and matches[0].get('draft') is True, 'Exact application draft required')
    release = matches[0]; assets = asset_map(api, release)
    blobs = {}
    def read(name):
        remote = assets.get(name)
        require(remote and remote.get('state') == 'uploaded' and 0 < remote.get('size', 0) <= 4 * 1024 * 1024, 'Required metadata missing or too large')
        data = api.download_small(remote)
        check_remote(remote, {'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
        blobs[name] = data
        return data
    full = json.loads(read('suite-update.json'))
    files = json.loads(read('suite-files.json'))
    report_name = f'GeneralsX-{version}-ci-validation.json'
    report_bytes = read(report_name); report = json.loads(report_bytes)
    read('suite-update.json.sig'); read('suite-files.json.sig')
    checksums = read('SHA256SUMS.txt').decode()
    require(report.get('workflowCommit') == expected_commit and report.get('workflowRunId') == str(expected_run) and
            report.get('inputArchiveSHA256') == config['inputSHA256'] and
            report.get('appCDHash') == config['expectedAppCDHash'] and
            report.get('treeEntriesVerified') == config['expectedTreeEntries'] and
            report.get('mountedTreeEntriesVerified') == config['expectedTreeEntries'] and
            report.get('strictDeepCodeSignatureVerified') is True and report.get('exactContentTypesModesSymlinks') is True and
            report.get('manifestSHA256') == hashlib.sha256(blobs['suite-update.json']).hexdigest() and
            report.get('published') is False and report.get('privateSigningKeyUsed') is False,
            'Build provenance/installer validation mismatch')
    key = base64.b64decode(config['publicKey'], validate=True)
    require(len(key) == 32 and hashlib.sha256(key).hexdigest() == config['publicKeySHA256'], 'Pinned public key continuity mismatch')
    with tempfile.TemporaryDirectory(prefix='generalsx-finalize-public-key-') as work:
        work = Path(work); (work / 'public').write_text(config['publicKey'] + '\n')
        for name in ('suite-update.json', 'suite-files.json'):
            (work / name).write_bytes(blobs[name]); (work / (name + '.sig')).write_bytes(blobs[name + '.sig'])
            subprocess.run([str(signing_tool()), 'verify', str(work / name), str(work / 'public'), str(work / (name + '.sig'))], check=True)
    require(files.get('schema') == 2 and full.get('schema') == 1 and files.get('sequence') == config['sequence'] and
            files.get('version') == version and files.get('bundleVersion') == config['bundleVersion'] and
            files.get('appCDHash') == config['expectedAppCDHash'], 'Release snapshot identity mismatch')
    for field in ('sequence', 'version', 'bundleVersion', 'bundleIdentifier', 'minimumSystemVersion', 'architecture', 'appName', 'appCDHash', 'expandedSize'):
        require(files.get(field) == full.get(field), 'Full and file-update identity mismatch')
    validate_files(files['files'], files['expandedSize'])
    require(len(files['files']) == config['expectedTreeEntries'] and report.get('fileSnapshotSHA256') == hashlib.sha256(blobs['suite-files.json']).hexdigest()
            and report.get('objectAssetsVerified') is True, 'File snapshot validation mismatch')
    required = {(item['tag'], item['asset']): {'name': item['asset'], 'size': item['downloadSize'], 'sha256': item['downloadSHA256']}
                for item in files['files'] if item['kind'] == 'file'}
    require({tag for tag, name in required} == {'files-v' + version}, 'First bridge must seed its complete object store')
    objects = api.json('GET', f'{API}/releases/{report["objectReleaseId"]}')
    require(objects.get('tag_name') == 'files-v' + version, 'Object release mismatch')
    metadata = [{'name': name, 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()} for name, data in blobs.items()]
    source = config['source']
    check_remote(assets.get(source['name']), source); metadata.append(source)
    manual = report['manualInstaller']
    require(report.get('manualInstallerAvailable') is True and manual.get('appCDHash') == config['expectedAppCDHash'] and
            manual.get('strictDeepCodeSignatureVerified') is True and manual.get('treeEntriesVerified') == config['expectedTreeEntries'], 'Manual installer verification mismatch')
    check_remote(assets.get(manual['name']), manual); metadata.append(manual)
    checksum_text = ''
    for part in full['parts']:
        check_remote(assets.get(part['name']), part); metadata.append(part)
        checksum_text += f'{part["sha256"]}  {part["name"]}\n'
    checksum_text += f'{full["imageSHA256"]}  GeneralsX-{version}-macos-arm64.dmg\n'
    checksum_text += f'{source["sha256"]}  {source["name"]}\n{manual["sha256"]}  {manual["name"]}\n'
    require(checksums == checksum_text and sum(p['size'] for p in full['parts']) == full['imageSize'] and
            full['imageSHA256'] == report['imageSHA256'] and full['imageSize'] == report['imageSize'], 'Installer checksums mismatch')
    run(api, files, required, [], metadata, objects['id'], release['id'], upload=True, publish=True,
        public_key=config['publicKey'], bootstrap=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--build-commit', required=True)
    parser.add_argument('--build-run', required=True)
    args = parser.parse_args()
    require(os.environ.get('GITHUB_REPOSITORY') == REPO and os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch',
            'Only this repository explicit release workflow may finalize publication')
    require(bool(os.environ.get('GITHUB_TOKEN')), 'Missing scoped workflow token')
    finalize(GitHub(os.environ['GITHUB_TOKEN']), json.loads(args.config.read_text()), args.build_commit, args.build_run)
