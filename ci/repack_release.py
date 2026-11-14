#!/usr/bin/env python3
"""Repack the exact already-signed .12 app from verified .11 plus a pinned patch.

Never signs, creates/deletes releases, replaces assets, or publishes. The only
remote writes are explicit uploads of verified output files to the target draft.
Uses release_uploader.py's streaming client, not its CLI or credential helper.
"""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import re
import shutil
import stat
import subprocess
import tarfile
from urllib.parse import urlsplit

from release_uploader import CHUNK, GitHub, ReleaseError, require
from release_config import (CONFIG, API, REPO, VERSION, TAG, SOURCE, IMAGE, MANUAL,
                            PATCH, INPUT, REPORT, EXPECTED_CDHASH, EXPECTED_ENTRIES,
                            PATCH_COUNT, BASE, BASE_CDHASH, BASE_IMAGE_HASH,
                            BASE_PARTS, BASE_TAG, PART_SIZE, ASSET_LIMIT, part_name)

APP = "Generals X Launcher.app"
OUTER_NAMES = {PATCH, "baseline-update.json", "expected-tree.json", "patch-files.json", "source-info.json", "update-template.json", "volume-files.json", "volume-files/.DS_Store", "volume-files/Read Me.txt", "volume-files/Nemesis testing.txt"}
VOLUME_NAMES = {".DS_Store", "Read Me.txt", "Nemesis testing.txt"}


def sha(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(CHUNK):
            result.update(block)
    return result.hexdigest()


def read_json(path):
    return json.loads(path.read_text())


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def safe_relative(value):
    path = PurePosixPath(value)
    require(bool(value) and value != "." and not path.is_absolute() and all(p not in {"", ".", ".."} for p in value.split("/")) and "\\" not in value, "Unsafe archive/manifest path")
    return path


def tree(app):
    entries = []
    def visit(path, relative):
        mode = path.lstat().st_mode
        entry = {"path": relative, "mode": stat.S_IMODE(mode)}
        if stat.S_ISLNK(mode):
            entry.update(type="symlink", target=os.readlink(path))
        elif stat.S_ISREG(mode):
            entry.update(type="file", size=path.stat().st_size, sha256=sha(path))
        elif stat.S_ISDIR(mode):
            entry["type"] = "directory"
        else:
            raise ReleaseError("Unsupported app filesystem node: " + relative)
        entries.append(entry)
        if entry["type"] == "directory":
            for child in sorted(path.iterdir(), key=lambda p: p.name):
                visit(child, child.name if relative == "." else relative + "/" + child.name)
    visit(app, ".")
    return sorted(entries, key=lambda x: x["path"])


def hardlink_groups(app):
    groups = {}
    for directory, _, files in os.walk(app, followlinks=False):
        for name in files:
            path = Path(directory) / name
            details = path.lstat()
            if stat.S_ISREG(details.st_mode) and details.st_nlink > 1:
                groups.setdefault((details.st_dev, details.st_ino), []).append(path.relative_to(app).as_posix())
    return sorted(sorted(paths) for paths in groups.values() if len(paths) > 1)


def compare_tree(app, expected):
    actual = tree(app)
    wanted = sorted(expected["entries"], key=lambda x: x["path"])
    require(len({e["path"] for e in wanted}) == len(wanted), "Duplicate expected tree path")
    if actual != wanted:
        left, right = {e["path"]: e for e in actual}, {e["path"]: e for e in wanted}
        differences = [name for name in sorted(set(left) | set(right)) if left.get(name) != right.get(name)]
        raise ReleaseError("App tree differs (content/type/mode/symlink): " + ", ".join(differences[:12]))
    require(hardlink_groups(app) == expected["hardlinks"], "App hardlink topology differs from the signed stage")
    return len(actual)


def verify_codesign(app, expected):
    subprocess.run(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(app)], check=True)
    result = subprocess.run(["/usr/bin/codesign", "-d", "--verbose=4", str(app)], capture_output=True, text=True, check=True)
    match = re.search(r"^CDHash=([0-9a-f]{40})$", result.stderr, re.MULTILINE)
    require(match is not None and match[1] == expected, "App CodeDirectory hash mismatch")


def extract_input(archive, destination, expected_sha):
    require(sha(archive) == expected_sha, "CI input archive SHA256 mismatch")
    destination.mkdir()
    with tarfile.open(archive, "r:gz") as source:
        members = source.getmembers()
        require(len(members) == len(OUTER_NAMES) and {m.name for m in members} == OUTER_NAMES, "Unexpected CI input members")
        for member in members:
            require(member.isfile() and member.size <= 256 * 1024 * 1024, "CI input must contain bounded regular files only")
            path = destination / safe_relative(member.name)
            path.parent.mkdir(parents=True, exist_ok=True)
            with source.extractfile(member) as inp, path.open("xb") as out:
                shutil.copyfileobj(inp, out, CHUNK)


def apply_patch(app, inputs):
    expected = read_json(inputs / "expected-tree.json")
    require(expected.get("appCDHash") == EXPECTED_CDHASH and len(expected["entries"]) == EXPECTED_ENTRIES, "Expected app identity/tree count mismatch")
    entries = {e["path"]: e for e in expected["entries"]}
    paths = read_json(inputs / "patch-files.json")
    require(len(paths) == PATCH_COUNT and len(set(paths)) == PATCH_COUNT, "Pinned number of unique replacements is required")
    with tarfile.open(inputs / PATCH, "r:gz") as archive:
        members = archive.getmembers()
        require(len(members) == PATCH_COUNT and {m.name for m in members} == set(paths), "Patch archive members do not match declared replacements")
        for member in members:
            relative = safe_relative(member.name)
            wanted = entries.get(member.name, {})
            require(member.isfile() and wanted.get("type") == "file" and member.size == wanted.get("size"), "Patch member type/size mismatch")
            target = app / relative
            require(target.is_file() and not target.is_symlink(), "Patch replacement must already be a regular file")
            require(target.stat().st_nlink == 1, "Patch replacement cannot write through a hardlinked file")
            parent = target.parent
            while parent != app:
                require(not parent.is_symlink(), "Patch parent cannot be a symlink")
                parent = parent.parent
            with archive.extractfile(member) as inp, target.open("wb") as out:
                shutil.copyfileobj(inp, out, CHUNK)
            target.chmod(wanted["mode"])
            require(sha(target) == wanted["sha256"], "Patched file hash mismatch")
    count = compare_tree(app, expected)
    verify_codesign(app, EXPECTED_CDHASH)
    return expected, count


def make_volume(baseline_app, inputs, volume):
    verify_codesign(baseline_app, BASE_CDHASH)
    volume.mkdir()
    app = volume / APP
    subprocess.run(["/usr/bin/ditto", str(baseline_app), str(app)], check=True)
    expected, count = apply_patch(app, inputs)
    entries = read_json(inputs / "volume-files.json")["entries"]
    require(len(entries) == 3 and {e["path"] for e in entries} == VOLUME_NAMES, "Unexpected installer outer files")
    for entry in entries:
        source = inputs / "volume-files" / entry["path"]
        require(entry["type"] == "file" and source.stat().st_size == entry["size"] and sha(source) == entry["sha256"], "Installer outer file differs")
        shutil.copyfile(source, volume / entry["path"])
        (volume / entry["path"]).chmod(entry["mode"])
    (volume / "Applications").symlink_to("/Applications")
    return expected, count


def verify_volume(volume, inputs, expected):
    # HFS creates filesystem bookkeeping directories outside the shipped files.
    require(os.readlink(volume / "Applications") == "/Applications", "Installer Applications link mismatch")
    for entry in read_json(inputs / "volume-files.json")["entries"]:
        path = volume / entry["path"]
        require(path.is_file() and not path.is_symlink() and stat.S_IMODE(path.stat().st_mode) == entry["mode"] and path.stat().st_size == entry["size"] and sha(path) == entry["sha256"], "Mounted installer outer file mismatch")
    count = compare_tree(volume / APP, expected)
    verify_codesign(volume / APP, EXPECTED_CDHASH)
    return count


def attach(image, mount):
    mount.mkdir()
    subprocess.run(["/usr/bin/hdiutil", "attach", "-readonly", "-nobrowse", "-noautoopen", "-owners", "on", "-mountpoint", str(mount), str(image)], check=True)


def detach(mount):
    subprocess.run(["/usr/bin/hdiutil", "detach", str(mount)], check=True)


def download(api, asset, stream, expected_size, expected_sha):
    """Download bounded data, never carrying API Authorization over redirects."""
    url = f"{API}/releases/assets/{asset['id']}"
    authenticated = True
    for _ in range(5):
        endpoint = urlsplit(url)
        require(endpoint.scheme == "https" and not endpoint.username and not endpoint.password and endpoint.port in (None, 443), "Unsafe download URL")
        allowed = {"api.github.com"} if authenticated else {"api.github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com", "github.com"}
        require(endpoint.hostname in allowed, "Unexpected download host")
        headers = {"Accept": "application/octet-stream", "User-Agent": "GeneralsX-Verified-Repacker", "X-GitHub-Api-Version": "2022-11-28"}
        if authenticated:
            headers["Authorization"] = "Bearer " + api._token
        connection = http.client.HTTPSConnection(endpoint.hostname, timeout=180)
        try:
            connection.request("GET", endpoint.path + (("?" + endpoint.query) if endpoint.query else ""), headers=headers)
            response = connection.getresponse()
            if response.status in {301, 302, 303, 307, 308}:
                url = response.getheader("Location")
                require(bool(url), "Missing download redirect")
                authenticated = False
                continue
            require(response.status == 200, f"Asset download HTTP {response.status}")
            total, digest = 0, hashlib.sha256()
            while block := response.read(CHUNK):
                total += len(block)
                require(total <= expected_size, "Asset download exceeds declared size")
                stream.write(block)
                digest.update(block)
            require(total == expected_size and digest.hexdigest() == expected_sha, "Downloaded asset size/SHA256 mismatch")
            return
        finally:
            connection.close()
    raise ReleaseError("Too many asset redirects")


def draft(api, release_id):
    release = api.json("GET", f"{API}/releases/{release_id}")
    require(release.get("tag_name") == TAG and release.get("draft") is True and not release.get("prerelease"), "Target must remain the existing release draft")
    return release


def asset_map(api, release):
    values = api.assets(release)
    result = {a["name"]: a for a in values}
    require(len(result) == len(values), "Duplicate remote asset names")
    return result


def check_asset(asset, size, digest):
    require(asset.get("state") == "uploaded" and asset.get("size") == size and asset.get("digest") == "sha256:" + digest, "Remote asset size/state/SHA256 mismatch")


def create_manual(volume, image, work):
    if CONFIG["manualInstaller"] == "none":
        return None
    if CONFIG["manualFormat"] == "dmg":
        archive = image
    else:
        archive = work / MANUAL
        environment = os.environ.copy()
        environment.pop("COPYFILE_DISABLE", None)
        compressor = shutil.which("xz")
        require(compressor is not None, "The build runner needs xz for manual archive compression")
        # xz is a build-only tool. Recipients extract with macOS's native tar/liblzma.
        producer = subprocess.Popen(["/usr/bin/tar", "-cf", "-", "--", APP, "Read Me.txt"], cwd=volume, env=environment, stdout=subprocess.PIPE)
        consumer = None
        try:
            with archive.open("xb") as output:
                consumer = subprocess.Popen([compressor, "-T3", "-9", "--stdout"], stdin=producer.stdout, stdout=output, env=environment)
                producer.stdout.close()
                compression_status = consumer.wait()
                tar_status = producer.wait()
            require(compression_status == 0 and tar_status == 0, "Manual archive producer failed")
        finally:
            for process in (consumer, producer):
                if process is not None and process.poll() is None:
                    process.terminate()
                    process.wait()
    if archive.stat().st_size >= ASSET_LIMIT:
        require(CONFIG["manualInstaller"] != "required", "Manual installer exceeds GitHub asset limit; no outputs uploaded")
        if archive != image:
            archive.unlink()
        return None
    return archive


def verify_manual(archive, work, inputs, expected):
    if archive is None:
        return None
    if CONFIG["manualFormat"] == "tar.xz":
        extraction = work / "manual-extracted"
        extraction.mkdir()
        environment = os.environ.copy()
        environment.pop("COPYFILE_DISABLE", None)
        subprocess.run(["/usr/bin/tar", "-xJpf", str(archive), "-C", str(extraction)], env=environment, check=True)
        require({p.name for p in extraction.iterdir()} == {APP, "Read Me.txt"}, "Manual archive has unexpected top-level contents")
        count = compare_tree(extraction / APP, expected)
        verify_codesign(extraction / APP, EXPECTED_CDHASH)
        readme = next(e for e in read_json(inputs / "volume-files.json")["entries"] if e["path"] == "Read Me.txt")
        path = extraction / "Read Me.txt"
        require(path.is_file() and not path.is_symlink() and path.stat().st_size == readme["size"] and stat.S_IMODE(path.stat().st_mode) == readme["mode"] and sha(path) == readme["sha256"], "Manual Read Me differs")
        shutil.rmtree(extraction)
    else:
        # The very same DMG already passed read-only mounted tree/signature checks.
        count = EXPECTED_ENTRIES
    return {"name": MANUAL, "format": CONFIG["manualFormat"], "size": archive.stat().st_size, "sha256": sha(archive), "treeEntriesVerified": count, "hardlinkGroupsVerified": len(expected["hardlinks"]), "strictDeepCodeSignatureVerified": True, "appCDHash": EXPECTED_CDHASH}


def split_and_manifest(image, inputs, output, manual_path=None, manual=None):
    output.mkdir()
    parts, image_hash = [], hashlib.sha256()
    part_count = (image.stat().st_size + PART_SIZE - 1) // PART_SIZE
    require(1 <= part_count <= 8, "Unexpected image size/part count")
    with image.open("rb") as source:
        for index in range(1, part_count + 1):
            name = part_name(index)
            size, digest = 0, hashlib.sha256()
            with (output / name).open("xb") as target:
                while size < PART_SIZE:
                    block = source.read(min(CHUNK, PART_SIZE - size))
                    if not block:
                        break
                    target.write(block)
                    size += len(block)
                    digest.update(block)
                    image_hash.update(block)
            require(size > 0, "Expected nonempty image part")
            parts.append({"name": name, "size": size, "sha256": digest.hexdigest()})
        require(source.read(1) == b"", "Image changed while splitting")
    template = read_json(inputs / "update-template.json")
    require(template.get("version") == VERSION and template.get("appCDHash") == EXPECTED_CDHASH and template.get("sequence") == CONFIG["sequence"] and template.get("bundleVersion") == CONFIG["bundleVersion"], "Update metadata identity mismatch")
    template.update(parts=parts, imageSize=image.stat().st_size, imageSHA256=image_hash.hexdigest())
    write_json(output / "suite-update.json", template)
    source_info = read_json(inputs / "source-info.json")
    require(source_info["name"] == SOURCE, "Source archive identity mismatch")
    (output / "SHA256SUMS.txt").write_text("".join(f"{p['sha256']}  {p['name']}\n" for p in parts) + f"{template['imageSHA256']}  {IMAGE}\n{source_info['sha256']}  {SOURCE}\n")
    if manual is not None:
        require(manual_path is not None and manual["size"] < ASSET_LIMIT, "Invalid verified manual archive")
        os.link(manual_path, output / MANUAL)
        if MANUAL != IMAGE:
            with (output / "SHA256SUMS.txt").open("a") as checksums:
                checksums.write(f"{manual['sha256']}  {MANUAL}\n")
    return template


def upload_outputs(api, release_id, output, manifest):
    part_names = [p["name"] for p in manifest["parts"]]
    names = part_names + ([MANUAL] if (output / MANUAL).exists() else []) + ["suite-update.json", "SHA256SUMS.txt", REPORT]
    allowed = set(names)
    require({p.name for p in output.iterdir()} == allowed, "Unexpected generated upload files")
    for name in names:
        release = draft(api, release_id)
        existing = asset_map(api, release)
        path = output / name
        stat_value = path.stat()
        asset = {"name": name, "path": path, "size": stat_value.st_size, "sha256": sha(path), "stamp": (stat_value.st_dev, stat_value.st_ino, stat_value.st_size, stat_value.st_mtime_ns)}
        if name in existing:
            check_asset(existing[name], asset["size"], asset["sha256"])
        else:
            print(f"Uploading verified draft asset {name}", flush=True)
            uploaded = api.upload(release, asset)
            check_asset(uploaded, asset["size"], asset["sha256"])
    final = asset_map(api, draft(api, release_id))
    for name in allowed:
        check_asset(final[name], (output / name).stat().st_size, sha(output / name))
    print(f"PASS: {len(names)} verified output assets uploaded; release remains DRAFT; manifest remains UNSIGNED", flush=True)


def remote_run(args):
    require(os.environ.get("GITHUB_REPOSITORY") == REPO and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch", "Remote mode requires this repository's manually dispatched workflow")
    require(re.fullmatch(r"[0-9a-f]{64}", args.input_sha256 or "") is not None, "Input SHA256 is required")
    token = os.environ.get("GITHUB_TOKEN", "")
    require(bool(token), "Missing workflow token")
    api = GitHub(token)
    release = draft(api, args.release_id)
    assets = asset_map(api, release)
    input_asset = assets.get(INPUT)
    require(input_asset and input_asset["id"] == args.input_asset_id, "CI input asset does not belong to target draft")
    check_asset(input_asset, input_asset["size"], args.input_sha256)
    require(0 < input_asset["size"] < 256 * 1024 * 1024, "Unexpected CI input size")
    # A rerun must never replace a previous run's nondeterministic DMG bytes.
    superseded = {
        'GeneralsX-1.0.6.2-ci-input-superseded.tar.gz': (61813787, 'c4a1c637000160a00ee660c7347c6e8afc1f5b02803f35bddc40cfcd5efa7b0f'),
        'GeneralsX-1.0.6.2-source-superseded.tar.gz': (15151046, '496a2cae3d1078cb961506e9b89d4dcc52959d422f6dba5c0a80f6daa567709a'),
    }
    require(set(assets) in ({INPUT, SOURCE}, {INPUT, SOURCE} | set(superseded)), "Draft may contain only reviewed preparation archives; existing outputs require manual review")
    for name in set(assets) & set(superseded):
        check_asset(assets[name], *superseded[name])
    args.work.mkdir()
    archive = args.work / INPUT
    with archive.open("xb") as stream:
        download(api, input_asset, stream, input_asset["size"], args.input_sha256)
    inputs = args.work / "input"
    extract_input(archive, inputs, args.input_sha256)
    source_info = read_json(inputs / "source-info.json")
    require(source_info["name"] == SOURCE and SOURCE in assets, "Expected source archive must already be uploaded")
    check_asset(assets[SOURCE], source_info["size"], source_info["sha256"])
    baseline = api.json("GET", API + "/releases/tags/" + BASE_TAG)
    require(baseline.get("draft") is False and baseline.get("tag_name") == BASE_TAG, "Expected pinned public baseline")
    base_assets = asset_map(api, baseline)
    image = args.work / "baseline.dmg"
    with image.open("xb") as stream:
        for name, size, digest in BASE_PARTS:
            check_asset(base_assets[name], size, digest)
            print("Downloading verified baseline " + name, flush=True)
            download(api, base_assets[name], stream, size, digest)
    require(sha(image) == BASE_IMAGE_HASH, "Baseline full image hash mismatch")
    mount, volume = args.work / "baseline-mount", args.work / "volume"
    attach(image, mount)
    try:
        expected, count = make_volume(mount / APP, inputs, volume)
    finally:
        detach(mount)
    image.unlink()
    archive.unlink()
    (inputs / PATCH).unlink()
    expanded = sum(e.get("size", 0) for e in expected["entries"] if e["type"] == "file")
    needed = expanded + BASE["imageSize"] + 512 * 1024 * 1024
    require(shutil.disk_usage(args.work).free >= needed, "Insufficient free disk for safe image creation")
    image = args.work / IMAGE
    create = ["/usr/bin/hdiutil", "create", "-fs", "HFS+", "-volname", "Generals X Installer", "-srcfolder", str(volume), "-format", CONFIG["dmgFormat"]]
    if CONFIG["dmgFormat"] == "UDZO":
        create += ["-imagekey", "zlib-level=6"]
    subprocess.run(create + [str(image)], check=True)
    subprocess.run(["/usr/bin/hdiutil", "verify", str(image)], check=True)
    new_mount = args.work / "new-image-mount"
    attach(image, new_mount)
    try:
        mounted_count = verify_volume(new_mount, inputs, expected)
    finally:
        detach(new_mount)
    manual_path = create_manual(volume, image, args.work)
    shutil.rmtree(volume)
    manual = verify_manual(manual_path, args.work, inputs, expected)
    output = args.work / "output"
    manifest = split_and_manifest(image, inputs, output, manual_path, manual)
    report = {"schema": 1, "repository": REPO, "tag": TAG, "releaseId": args.release_id, "inputArchiveSHA256": args.input_sha256, "baselineImageSHA256": BASE_IMAGE_HASH, "appCDHash": EXPECTED_CDHASH, "expectedTreeSHA256": sha(inputs / "expected-tree.json"), "treeEntriesVerified": count, "mountedTreeEntriesVerified": mounted_count, "hardlinkGroupsVerified": len(expected["hardlinks"]), "exactContentTypesModesSymlinks": True, "strictDeepCodeSignatureVerified": True, "imageSHA256": manifest["imageSHA256"], "imageSize": manifest["imageSize"], "manifestSHA256": sha(output / "suite-update.json"), "workflowCommit": os.environ.get("GITHUB_SHA"), "workflowRunId": os.environ.get("GITHUB_RUN_ID"), "privateSigningKeyUsed": False, "manifestSigned": False, "published": False, "dmgFormat": CONFIG["dmgFormat"], "manualInstallerAvailable": manual is not None, "manualInstaller": manual, "releaseConfigSHA256": sha(Path(__file__).with_name("release-config.json"))}
    write_json(output / REPORT, report)
    upload_outputs(api, args.release_id, output, manifest)
    print(json.dumps(report, indent=2), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--input-directory", type=Path, help="Local-only reconstruction test")
    parser.add_argument("--baseline-app", type=Path, help="Local-only baseline for reconstruction test")
    parser.add_argument("--input-asset-id", type=int)
    parser.add_argument("--input-sha256")
    parser.add_argument("--release-id", type=int)
    args = parser.parse_args()
    args.work = args.work.resolve()
    require(not args.work.exists(), "Work directory must be new")
    if args.input_directory or args.baseline_app:
        require(args.input_directory and args.baseline_app, "Local reconstruction needs both paths")
        args.work.mkdir()
        expected, count = make_volume(args.baseline_app.resolve(), args.input_directory.resolve(), args.work / "volume")
        result = {"passed": True, "remoteRequests": 0, "treeEntries": count, "hardlinkGroups": len(expected["hardlinks"]), "replacedFiles": PATCH_COUNT, "appCDHash": expected["appCDHash"], "contentTypesModesSymlinksVerified": True, "strictDeepCodeSignatureVerified": True}
        write_json(args.work / "local-validation.json", result)
        print(json.dumps(result, indent=2))
    else:
        require(args.input_asset_id and args.release_id, "Remote mode requires asset and release IDs")
        remote_run(args)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        # Avoid printing signed redirect URLs, response bodies, or token-bearing headers.
        print("ERROR: " + (str(exc) if isinstance(exc, ReleaseError) else "Repack operation failed; inspect the last completed named step."), flush=True)
        raise SystemExit(1)
