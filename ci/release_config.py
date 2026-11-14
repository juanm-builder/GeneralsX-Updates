"""Reviewed release pins; deployment records must include this module and JSON."""
import json
from pathlib import Path
import re

CONFIG = json.loads(Path(__file__).with_name("release-config.json").read_text())
REPO = CONFIG["repository"]
VERSION = CONFIG["version"]
if REPO != "juanm-builder/GeneralsX-Updates" or VERSION != "1.0.6.2":
    raise ValueError("Release configuration is outside this reviewed release scope")
if re.fullmatch(r"[0-9a-f]{40}", CONFIG["expectedAppCDHash"]) is None:
    raise ValueError("Pin the staged app CDHash before using release helpers")
if type(CONFIG["patchFiles"]) is not int or not 0 < CONFIG["patchFiles"] < 100:
    raise ValueError("Pin the exact replacement file count")
if CONFIG["dmgFormat"] not in {"UDZO", "ULMO"} or CONFIG["manualInstaller"] not in {"required", "if_below_limit", "none"}:
    raise ValueError("Unreviewed installer format/policy")
if CONFIG["manualFormat"] not in {"dmg", "tar.xz"}:
    raise ValueError("Unreviewed manual archive format")
if CONFIG["manualCompression"] != "xz-threaded-9":
    raise ValueError("Unreviewed manual archive producer")
if CONFIG["baseline"]["version"] != "1.0.5.11":
    raise ValueError("Unexpected public baseline version")
TAG = "v" + VERSION
API = "https://api.github.com/repos/" + REPO
SOURCE = f"GeneralsX-{VERSION}-source.tar.gz"
IMAGE = f"GeneralsX-{VERSION}-macos-arm64.dmg"
MANUAL = IMAGE if CONFIG["manualFormat"] == "dmg" else f"GeneralsX-{VERSION}-macos-arm64.tar.xz"
INPUT = f"GeneralsX-{VERSION}-ci-input.tar.gz"
REPORT = f"GeneralsX-{VERSION}-ci-validation.json"
PATCH = f"GeneralsX-{VERSION}-app-patch.tar.gz"
PART_SIZE = 1024 ** 3
ASSET_LIMIT = 2 * 1024 ** 3
EXPECTED_CDHASH = CONFIG["expectedAppCDHash"]
EXPECTED_ENTRIES = CONFIG["expectedTreeEntries"]
PATCH_COUNT = CONFIG["patchFiles"]
BASE = CONFIG["baseline"]
BASE_CDHASH = BASE["appCDHash"]
BASE_IMAGE_HASH = BASE["imageSHA256"]
BASE_PARTS = [(p["name"], p["size"], p["sha256"]) for p in BASE["parts"]]
BASE_TAG = "v" + BASE["version"]


def part_name(index):
    return f"GeneralsX-{VERSION}-macos-arm64.dmg.part{index:02d}"
