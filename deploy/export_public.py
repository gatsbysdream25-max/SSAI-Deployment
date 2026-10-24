#!/usr/bin/env python3
"""Make a clean, one-way copy of SSAI for sharing: fresh history, nothing private (audit F-09 follow-up, owner decision 2026-10-21).

    python deploy/export_public.py --out ../ssai-public            # scan and report only (nothing is written)
    python deploy/export_public.py --out ../ssai-public --write    # build the copy if the scan is clean (or accepted, see below)

What it does:
  1. takes the files git tracks at HEAD (never your working-tree extras), minus the folders and file types listed in EXCLUDE;
  2. scans every file for things that must not be published: private and Tailscale addresses, MAC addresses, e-mail addresses,
     API-key formats, your own machine/user names (SSAI_PRIVATE_NAMES in the environment, plus --name NAME for each), and secrets
     in key=value form. Values are NEVER printed: a finding shows the file, the line number and the kind;
  3. with --write and a clean scan, copies the files into --out, runs `git init` there and makes ONE commit. The new repository has no
     link to this one's history, so nothing ever deleted here can be recovered from it.
It never pushes. Publishing is a separate step you do by hand (the last lines it prints tell you how).

If the scan finds things that are acceptable on purpose (a documentation address such as 203.0.113.9, a placeholder e-mail), review
the report and re-run with --accept-report-hash HASH (printed with the report). The hash covers the exact findings, so a NEW leak
after your review changes the hash and the export refuses again.

One-way by design: this script reads the source repo and writes only to --out. It has no option to touch the source or any remote.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import os
import re
import shutil
import subprocess
import sys
from collections import Counter
from typing import List, Tuple

EXCLUDE_DIRS = ("backend/instance/", "instance/", "logs/", "archive/", "_archive/", "docs/audit/", "docs/plans/", "threats/", ".github/ISSUE_TEMPLATE/", "node_modules/", "__pycache__/",
                "windows_client_incomplete/", "monetization_dashboard.html")   # unfinished client with a hub address; a stale lab status page
EXCLUDE_SUFFIXES = (".bak", ".log", ".db", ".sqlite", ".pem", ".key", ".pyc", ".swp")
EXCLUDE_NAMES = (".env", "cloud_audit.jsonl", "remediation_audit.jsonl", "ai_weights.json", "ssai-consensus-plan.md")
MAX_FILE_BYTES = 5 * 1024 * 1024
HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)

_IPV4 = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?![\w.]*\w)")
_MAC = re.compile(r"(?<![0-9a-fA-F:-])(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}(?![0-9a-fA-F:-])")
_EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)*\.[A-Za-z]{2,}")
_KEYS = re.compile(r"\b(?:sk-(?:ant-|or-v1-|proj-)?[A-Za-z0-9_-]{20,}|gsk_[A-Za-z0-9]{20,}|hf_[A-Za-z0-9]{30,}|AIza[0-9A-Za-z_-]{35}"
                   r"|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|AKIA[0-9A-Z]{16}|xox[abprs]-[A-Za-z0-9-]{10,})")
_SECRET_ASSIGN = re.compile(r"(?i)\b[\w.-]*(?:password|passwd|secret|api[_-]?key|token)[\w.-]*\s*[=:]\s*[\"']?([A-Za-z0-9/+_=.-]{16,})")
_PLACEHOLDER = re.compile(r"(?i)(example|placeholder|changeme|your[-_ ]|xxx|\.\.\.|<|test|fake|dummy|sample|redacted|secret_\d)")
ALLOWED_EMAIL_DOMAINS = ("example.com", "example.org", "example.net", "bank.example", "corp.example", "users.noreply.github.com", "noreply.anthropic.com")
DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def tracked_files() -> List[str]:
    """Files git tracks, minus the ones .gitattributes marks export-ignore: the same rule that builds the release package,
    so the public copy never carries the lab's network map, legacy code or internal plans."""
    out = subprocess.run(["git", "ls-files", "-z"], cwd=REPO, capture_output=True, check=True).stdout
    paths = [p for p in out.decode("utf-8").split("\0") if p]
    answer = subprocess.run(["git", "check-attr", "-z", "export-ignore", "--stdin"], cwd=REPO, input=("\0".join(paths) + "\0").encode("utf-8"),
                            capture_output=True, check=True).stdout.decode("utf-8").split("\0")
    ignored = {answer[i] for i in range(0, len(answer) - 2, 3) if answer[i + 2] == "set"}      # (path, attribute, value) triples
    return [p for p in paths if p not in ignored]


def excluded(path: str) -> bool:
    base = os.path.basename(path)
    return (path.startswith(EXCLUDE_DIRS) or any(("/" + d) in ("/" + path) for d in EXCLUDE_DIRS)
            or path.endswith(EXCLUDE_SUFFIXES) or base in EXCLUDE_NAMES or base.startswith(".env"))


def _private_ip(text: str) -> bool:
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return False                                   # 192.168.xxx.xxx and version-like strings are not addresses
    return not any(ip in n for n in DOC_NETS) and (ip.is_private or ip.is_link_local or ip in ipaddress.ip_network("100.64.0.0/10")) and not ip.is_loopback and not ip.is_unspecified


def scan_text(text: str, names: List[str]) -> List[Tuple[int, str]]:
    """(line number, kind) for each thing that must not be published. Values are never returned."""
    found: List[Tuple[int, str]] = []
    name_rx = re.compile(r"(?<![\w-])(?:%s)(?![\w-])" % "|".join(re.escape(n) for n in names), re.I) if names else None
    for number, line in enumerate(text.splitlines(), 1):
        if any(_private_ip(m.group(1)) for m in _IPV4.finditer(line)):
            found.append((number, "private-address"))
        if _MAC.search(line):
            found.append((number, "mac-address"))
        for m in _EMAIL.finditer(line):
            if not m.group(0).lower().endswith(ALLOWED_EMAIL_DOMAINS):
                found.append((number, "email"))
        if _KEYS.search(line):
            found.append((number, "api-key-format"))
        for m in _SECRET_ASSIGN.finditer(line):
            if not _PLACEHOLDER.search(m.group(1)) and not _PLACEHOLDER.search(line):
                found.append((number, "secret-assignment"))
        if name_rx and name_rx.search(line):
            found.append((number, "your-own-name"))
    return found


def scan(files: List[str], names: List[str]) -> List[Tuple[str, int, str]]:
    """Look through each file for things that must not be published (key formats, secrets, your own names); returns (file, line number, kind) for each.
    Files that are too large are reported rather than skipped, and binary files are not scanned.
    """
    findings = []
    for rel in files:
        full = os.path.join(REPO, rel)
        try:
            if os.path.getsize(full) > MAX_FILE_BYTES:
                findings.append((rel, 0, "file-too-large-to-scan"))
                continue
            with open(full, "rb") as f:
                raw = f.read()
        except OSError:
            continue
        if b"\0" in raw[:4096]:
            continue                                   # a binary file: not scanned, and not text we would have written
        findings += [(rel, n, kind) for n, kind in scan_text(raw.decode("utf-8", "replace"), names)]
    return findings


def report_hash(findings: List[Tuple[str, int, str]]) -> str:
    return hashlib.sha256("\n".join(f"{p}:{n}:{k}" for p, n, k in sorted(findings)).encode()).hexdigest()[:16]


def keep_executable_bits(files: List[str], out: str, env: dict) -> None:
    """Copying files on Windows loses the 'executable' mark, and a script that is not marked fails with 'Permission denied'
    on Linux (found when the first release was installed, 2026-10-24). Read the marks from the source repository and
    apply them to the new one."""
    listing = subprocess.run(["git", "ls-files", "-s", "-z"], cwd=REPO, capture_output=True, check=True).stdout.decode("utf-8")
    wanted = set(files)
    for entry in listing.split("\0"):
        mode, _, rest = entry.partition(" ")
        path = rest.split("\t", 1)[-1]
        if mode == "100755" and path in wanted:
            subprocess.run(["git", "update-index", "--chmod=+x", "--", path], cwd=out, env=env, check=True)


PUBLIC_GITATTRIBUTES = """# Shell scripts and Python must keep Unix line endings or they fail on Linux, whatever machine checked them out or packaged them.
*.sh text eol=lf
*.py text eol=lf
*.service text eol=lf
*.in text eol=lf
# The Windows installer is run by PowerShell, which is happy with either.
*.ps1 text eol=crlf
"""


def write_public_gitattributes(out: str) -> None:
    """The private repository's .gitattributes lists files that are not in the public copy, so the public one gets its own."""
    with open(os.path.join(out, ".gitattributes"), "w", encoding="utf-8", newline="\n") as handle:
        handle.write(PUBLIC_GITATTRIBUTES)


def prepare_existing_clone(out: str, env: dict) -> str:
    """For --onto: make sure OUT is a clean git clone, then empty its working files (keeping .git) so the export replaces them.
    Returns a reason to refuse, or an empty string."""
    if not os.path.isdir(os.path.join(out, ".git")):
        return f"{out} is not a git clone of the public repository"
    dirty = subprocess.run(["git", "status", "--porcelain"], cwd=out, capture_output=True, text=True, check=True).stdout.strip()
    if dirty:
        return f"{out} has uncommitted changes; commit or discard them first"
    subprocess.run(["git", "rm", "-rq", "--ignore-unmatch", "."], cwd=out, env=env, check=True)
    for name in os.listdir(out):
        if name != ".git":
            shutil.rmtree(os.path.join(out, name), ignore_errors=True)
    return ""


def main(argv=None) -> int:
    """Build a clean, one-commit copy of the repository for publishing, after scanning it for private data.
    Without --write it only reports; with findings it refuses unless you pass the hash of the report you reviewed. Returns 0 ok, 1 findings/refused, 2 bad --out folder.
    """
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", required=True, help="folder for the clean copy (must not exist yet, or be empty)")
    ap.add_argument("--write", action="store_true", help="build the copy (without it, only scan and report)")
    ap.add_argument("--name", action="append", default=[], help="a machine, user or domain name that must not appear (repeatable)")
    ap.add_argument("--accept-report-hash", help="the hash of a findings report you reviewed and accept")
    ap.add_argument("--message", default="SwarmSentinel public release", help="the single commit message")
    ap.add_argument("--onto", action="store_true",
                    help="--out is an existing, clean clone of the public repository: replace its files with this export and add ONE "
                         "new commit on top (every export after the first)")
    args = ap.parse_args(argv)

    out = os.path.abspath(args.out)
    if out == REPO or out.startswith(REPO + os.sep) or REPO.startswith(out + os.sep):
        print("refusing: --out must be a separate folder, not inside (or containing) this repository")
        return 2
    names = sorted({n.strip() for n in args.name + os.environ.get("SSAI_PRIVATE_NAMES", "").split(",") if len(n.strip()) >= 3})
    files = [p for p in tracked_files() if not excluded(p)]
    findings = scan(files, names)
    digest = report_hash(findings)
    kinds = Counter(k for _, _, k in findings)
    print(f"{len(files)} files would be copied; {len(findings)} thing(s) found that should not be published {dict(kinds) if kinds else ''}")
    for path, line, kind in sorted(findings)[:200]:
        print(f"   {path}:{line}  {kind}")
    if len(findings) > 200:
        print(f"   ... and {len(findings) - 200} more")
    if findings:
        print(f"report hash: {digest}")
    if not args.write:
        print("nothing was written (add --write to build the copy)")
        return 1 if findings else 0
    if findings and args.accept_report_hash != digest:
        print("refusing to write: fix the findings, or review the list and re-run with --accept-report-hash " + digest)
        return 1
    env = dict(os.environ, GIT_AUTHOR_NAME="SwarmSentinel", GIT_AUTHOR_EMAIL="noreply@users.noreply.github.com",
               GIT_COMMITTER_NAME="SwarmSentinel", GIT_COMMITTER_EMAIL="noreply@users.noreply.github.com")
    if args.onto:
        problem = prepare_existing_clone(out, env)
        if problem:
            print("refusing: " + problem)
            return 2
    elif os.path.exists(out) and os.listdir(out):
        print(f"refusing: {out} already has files in it")
        return 2
    os.makedirs(out, exist_ok=True)
    for rel in files:
        dest = os.path.join(out, rel)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.copy2(os.path.join(REPO, rel), dest)
    write_public_gitattributes(out)
    for cmd in ([] if args.onto else [["git", "init", "-q", "-b", "main"]]) + [["git", "add", "-A"]]:
        subprocess.run(cmd, cwd=out, env=env, check=True)
    keep_executable_bits(files, out, env)
    subprocess.run(["git", "commit", "-q", "-m", args.message], cwd=out, env=env, check=True)
    if args.onto:
        print(f"added ONE new commit on top of {out}. Review it, then publish by hand:  cd " + out + "  &&  git push")
        return 0
    print(f"built {out} with ONE commit and no history from the source repository. Review it, then publish by hand:")
    print("   cd " + out + "  &&  git remote add origin <the new empty repository's URL>  &&  git push -u origin main")
    return 0


if __name__ == "__main__":
    sys.exit(main())
