#!/usr/bin/env python3
"""Build the SwarmSentinel Shield browser extension for each browser from one shared source (client/browser-extension/src).

    python client/browser-extension/build.py            # writes dist/<browser>/ and dist/swarmsentinel-shield-<browser>.zip

Four packages, one per browser, so people install the one for the browser they use:
    chrome, brave, edge  Chromium (Manifest V3, service worker). Same code; separate packages and names.
    firefox              Firefox (Manifest V3, background script, needs an add-on id).

Safe by construction: the build refuses to produce a package if any source file contains an API key, an admin-key placeholder or a
hard-coded address; the extension holds no credential of its own until a person enrols it with a single-use code.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "src")
DIST = os.path.join(HERE, "dist")
VERSION = "1.0.0"
BROWSERS = {"chrome": "Chrome", "brave": "Brave", "edge": "Edge", "firefox": "Firefox"}
FILES = ("background.js", "content-gmail.js", "popup.html", "popup.js")
FORBIDDEN = (re.compile(r"__SSAI_API_KEY__"), re.compile(r"X-API-Key['\"]?\s*:\s*API_KEY"), re.compile(r"\bsk-[A-Za-z0-9_-]{20,}"),
             re.compile(r"(?<![\w.])(?:192\.168|10\.\d+|172\.(?:1[6-9]|2\d|3[01]))\.\d+\.\d+"))


def manifest(browser: str) -> dict:
    """Build the manifest.json contents (the file that tells the browser what the extension is and what it may do) for one browser.
    Firefox needs a slightly different background-script setup from Chrome, Brave and Edge.
    """
    m = {
        "manifest_version": 3,
        "name": f"SwarmSentinel Shield for {BROWSERS[browser]}",
        "version": VERSION,
        "description": "Optional. Off until you turn it on: checks the Gmail message you have open for phishing signs and tells your own "
                       "SwarmSentinel hub only the warning signs.",
        "permissions": ["storage", "alarms"],
        "host_permissions": [],                                   # none: access to your hub is requested from the popup, one address
        "optional_host_permissions": ["https://*/*", "http://*/*"],   # only ever granted for the one hub address you type
        "content_scripts": [{"matches": ["https://mail.google.com/*"], "js": ["content-gmail.js"], "run_at": "document_idle"}],
        "action": {"default_title": "SwarmSentinel Shield", "default_popup": "popup.html",
                   "default_icon": {"16": "icons/icon16.png", "48": "icons/icon48.png", "128": "icons/icon128.png"}},
        "icons": {"16": "icons/icon16.png", "48": "icons/icon48.png", "128": "icons/icon128.png"},
    }
    if browser == "firefox":
        m["background"] = {"scripts": ["background.js"]}
        m["browser_specific_settings"] = {"gecko": {"id": "shield@swarmsentinel.example", "strict_min_version": "115.0"}}
    else:
        m["background"] = {"service_worker": "background.js"}
    return m


def check_source() -> None:
    for name in FILES:
        with open(os.path.join(SRC, name), encoding="utf-8") as f:
            text = f.read()
        for rx in FORBIDDEN:
            if rx.search(text):
                raise SystemExit(f"refusing to build: {name} contains something that must not ship ({rx.pattern})")


def build(browser: str) -> str:
    """Make the ready-to-install folder and zip file for one browser: copy the source files, stamp in the browser name, and add the manifest and icons.
    Returns the path of the zip.
    """
    out = os.path.join(DIST, browser)
    if os.path.isdir(out):
        shutil.rmtree(out)
    os.makedirs(out)
    for name in FILES:
        with open(os.path.join(SRC, name), encoding="utf-8") as f:
            text = f.read().replace("__BROWSER__", browser)
        with open(os.path.join(out, name), "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
    shutil.copytree(os.path.join(SRC, "icons"), os.path.join(out, "icons"))
    with open(os.path.join(out, "manifest.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(manifest(browser), f, indent=2)
    zip_path = os.path.join(DIST, f"swarmsentinel-shield-{browser}.zip")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        for root, _, files in os.walk(out):
            for fn in sorted(files):
                full = os.path.join(root, fn)
                z.write(full, os.path.relpath(full, out))
    return zip_path


def main() -> int:
    check_source()
    for browser in BROWSERS:
        print("built", os.path.relpath(build(browser), HERE))
    return 0


if __name__ == "__main__":
    sys.exit(main())
