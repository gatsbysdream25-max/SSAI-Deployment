#!/usr/bin/env python3
"""Run every backend/tools/test_*.py, each in its own process, with no way to reach the internet.

    swarmsentinel-env/bin/python3 backend/tools/run_all_tests.py            all tests
    swarmsentinel-env/bin/python3 backend/tools/run_all_tests.py recall     only files whose name contains "recall"

Why this exists (consensus plan, Phase 0): a test that forgets to mock a provider call must not send anything to a
cloud AI. Each test runs with
  1. the no-internet guard in tools/nocloud/ (public connections and DNS lookups are refused and logged);
  2. every API key, token and password removed from its environment (a test that needs one sets a fake itself).
The summary at the end lists any refused internet attempt, so a leak shows up as a number instead of staying quiet.
"""
import os
import re
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
GUARD_DIR = os.path.join(HERE, "nocloud")
SECRET_NAME = re.compile(r"(API_KEY|_TOKEN|TOKEN$|PASSWORD|SECRET|_KEY$)", re.I)
TIMEOUT_SECONDS = 600


def clean_environment(log_path, test_file):
    """Build the environment for one test run: secrets removed, the no-internet guard switched on, and a private provider
    state file."""
    env = {k: v for k, v in os.environ.items() if not SECRET_NAME.search(k)}
    # Putting the guard folder first means Python loads its start-up hook before any test code can open a connection.
    env["PYTHONPATH"] = GUARD_DIR + os.pathsep + env.get("PYTHONPATH", "")
    env["NOCLOUD_GUARD"] = "1"
    env["NOCLOUD_LOG"] = log_path
    env["NOCLOUD_TEST"] = test_file
    # A test that makes a provider "run out of credits" must not leave it resting for the next test file.
    env["SSAI_PROVIDER_REST_FILE"] = os.path.join(tempfile.gettempdir(), "ssai-rest-%d-%s.json" % (os.getpid(), os.path.basename(test_file)))
    return env


def run_one(path, log_path):
    """Run one test file in its own process with a time limit; returns (passed, seconds, last lines of output)."""
    started = time.time()
    try:
        done = subprocess.run([sys.executable, path], env=clean_environment(log_path, path), capture_output=True,
                              text=True, timeout=TIMEOUT_SECONDS)
        ok, tail = done.returncode == 0, (done.stdout + done.stderr).strip().splitlines()[-3:]
    except subprocess.TimeoutExpired:
        ok, tail = False, [f"timed out after {TIMEOUT_SECONDS}s"]
    return ok, round(time.time() - started, 1), tail


def main(argv):
    """Run every matching test file, print PASS or FAIL for each, then the totals and any internet attempts that were
    refused."""
    wanted = argv[1] if len(argv) > 1 else ""
    files = sorted(f for f in os.listdir(HERE) if f.startswith("test_") and f.endswith(".py") and wanted in f)
    log_fd, log_path = tempfile.mkstemp(prefix="nocloud-", suffix=".log")
    os.close(log_fd)
    failed = []
    for name in files:
        ok, seconds, tail = run_one(os.path.join(HERE, name), log_path)
        print(f"{'PASS' if ok else 'FAIL'}  {name}  ({seconds}s)")
        if not ok:
            failed.append(name)
            for line in tail:
                print(f"        {line}")
    with open(log_path, encoding="utf-8") as f:
        blocked = [line.strip() for line in f if line.strip()]
    os.unlink(log_path)
    print(f"\n{len(files) - len(failed)} of {len(files)} test files passed")
    print(f"internet attempts refused by the guard: {len(blocked)}")
    for line in sorted(set(blocked)):
        print(f"   {line}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
