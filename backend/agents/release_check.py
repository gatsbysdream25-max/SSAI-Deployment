"""Is there a newer SwarmSentinel release than the one installed?

Used in two places: the Settings page (to show "update available") and deploy/update-package.sh (to find what to download).
It asks GitHub's public releases API for the newest release of the distribution repository. The only thing that leaves this
machine is that one ordinary web request, the same one any browser makes; nothing about this install is sent.

Turn the check off with SSAI_UPDATE_CHECK=off. Point it at another repository with SSAI_UPDATE_REPO=OWNER/REPO.

From a shell:   python release_check.py INSTALL_FOLDER     prints "name value" lines the updater reads.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.request

DEFAULT_REPO = "gatsbysdream25-max/SSAI-Deployment"
CACHE_SECONDS = 30 * 60          # GitHub allows only 60 anonymous requests an hour per address, so do not ask on every page view
_VALID_TAG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

_cache = {"at": 0.0, "answer": None}


class ReleaseError(Exception):
    """The release information could not be read or did not look right."""


def enabled() -> bool:
    """False when the operator has switched the update check off."""
    return os.environ.get("SSAI_UPDATE_CHECK", "on").strip().lower() not in ("off", "0", "no", "false")


def api_url() -> str:
    """Where to ask for the newest release. SSAI_UPDATE_API replaces the whole address (the tests use a local file)."""
    override = os.environ.get("SSAI_UPDATE_API", "").strip()
    if override:
        return override
    repo = os.environ.get("SSAI_UPDATE_REPO", DEFAULT_REPO).strip()
    return f"https://api.github.com/repos/{repo}/releases/latest"


def installed_version(root: str) -> str:
    """The version this install says it is: the first word of its VERSION file ('v0.4.0 (abc123def456)' gives 'v0.4.0')."""
    try:
        with open(os.path.join(root, "VERSION"), encoding="utf-8") as handle:
            words = handle.read().split()
    except OSError:
        return "unknown"
    return words[0] if words else "unknown"


def _download_urls(release: dict) -> tuple:
    """Find the package and its checksum file among a release's attached files."""
    package = next((a for a in release.get("assets", [])
                    if a.get("name", "").startswith("swarmsentinel-") and a.get("name", "").endswith(".tar.gz")), None)
    if not package:
        raise ReleaseError("the newest release has no swarmsentinel-*.tar.gz file attached")
    wanted = package["name"] + ".sha256"
    checksum = next((a for a in release.get("assets", []) if a.get("name") == wanted), None)
    if not checksum:
        raise ReleaseError(f"the newest release has no {wanted} file, so the download could not be checked")
    return package["browser_download_url"], checksum["browser_download_url"]


def _check_url_is_safe(url: str) -> None:
    """Downloads must come over https. A local file: address is allowed only when the tests point the check at one."""
    if url.startswith("https://"):
        return
    if url.startswith("file://") and os.environ.get("SSAI_UPDATE_API"):
        return
    raise ReleaseError("refusing a download address that is not https")


def fetch_latest(timeout: int = 10) -> dict:
    """Ask for the newest release. Returns {'tag', 'notes', 'package_url', 'checksum_url'} or raises ReleaseError."""
    try:
        request = urllib.request.Request(api_url(), headers={"Accept": "application/vnd.github+json",
                                                              "User-Agent": "SwarmSentinel-update-check"})
        with urllib.request.urlopen(request, timeout=timeout) as response:   # nosec: https, or a test file
            release = json.loads(response.read().decode("utf-8"))
    except Exception as error:
        raise ReleaseError(f"could not read the newest release ({error.__class__.__name__}: {error})")
    tag = str(release.get("tag_name", ""))
    if not _VALID_TAG.match(tag):
        raise ReleaseError("the newest release has no usable version tag")
    package_url, checksum_url = _download_urls(release)
    _check_url_is_safe(package_url)
    _check_url_is_safe(checksum_url)
    return {"tag": tag, "notes": str(release.get("body") or "")[:2000],
            "package_url": package_url, "checksum_url": checksum_url}


def check(root: str, use_cache: bool = False) -> dict:
    """What the Settings page shows: {'enabled', 'installed', 'latest', 'update_available', 'notes', 'error'}."""
    answer = {"enabled": enabled(), "installed": installed_version(root), "latest": None,
              "update_available": False, "notes": "", "error": None}
    if not answer["enabled"]:
        return answer
    now = time.time()
    if use_cache and _cache["answer"] and now - _cache["at"] < CACHE_SECONDS:
        return dict(_cache["answer"], installed=answer["installed"])
    try:
        latest = fetch_latest()
    except ReleaseError as error:
        answer["error"] = str(error)
        return answer
    answer["latest"] = latest["tag"]
    answer["notes"] = latest["notes"]
    # A different tag means a newer release: the owner only ever publishes forward, and an install that does not know its own
    # version ('unknown') is offered the newest release too.
    answer["update_available"] = latest["tag"] != answer["installed"]
    _cache.update(at=now, answer=dict(answer))
    return answer


def main(argv: list) -> int:
    """Print what the updater needs, one 'name value' per line. Exit 0 if the check worked, 1 if not."""
    root = argv[1] if len(argv) > 1 else "."
    if not enabled():
        print("error the update check is switched off (SSAI_UPDATE_CHECK=off)")
        return 1
    try:
        latest = fetch_latest()
    except ReleaseError as error:
        print(f"error {error}")
        return 1
    installed = installed_version(root)
    print(f"installed {installed}")
    print(f"latest {latest['tag']}")
    print(f"available {'yes' if latest['tag'] != installed else 'no'}")
    print(f"package_url {latest['package_url']}")
    print(f"checksum_url {latest['checksum_url']}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
