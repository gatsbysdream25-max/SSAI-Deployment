#!/usr/bin/env python3
"""Live red-team drills for a SANDBOX install: stage real attacks on this machine and check SwarmSentinel catches them.

The always-on RedTeamAgent (agents/redteam.py) only feeds crafted data to the code. These drills do the real thing:
write attack lines into the system logs, start a process that looks like a miner, open a backdoor-style port, touch a
watched system file, block and unblock an address in the real firewall, and try to stay under the detection
thresholds. Each one then waits for the matching finding to appear on the hub. They change this machine, so they
refuse to run unless the install is marked as a sandbox (SSAI_SANDBOX=1 in .env) and they run as root.

    sudo swarmsentinel-env/bin/python3 backend/tools/sandbox_drills.py            all drills
    sudo ... sandbox_drills.py --only brute-force,miner                           some of them
    sudo ... sandbox_drills.py --timeout 600                                      wait longer for slow agents

Results: printed, and written to backend/instance/sandbox_drills/<time>.json and .md. Exit code 1 if a drill that
must be caught was missed. An "evasion" drill that is NOT caught is reported as a known gap (a finding to improve
on), not a failure. Addresses are from the documentation ranges (203.0.113.0/24, 198.51.100.0/24): nobody's real host.
Speed it up with SSAI_INTERVAL_SCALE=0.2 in .env (agents check five times as often).
"""
import argparse
import json
import os
import random
import shutil
import signal
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
sys.path[:0] = [os.path.join(BACKEND, 'agents'), BACKEND]

import requests  # noqa: E402

import ssai_config  # noqa: E402

CAUGHT, MISSED, GAP, CLOSED, SKIPPED, ERROR = 'caught', 'MISSED', 'gap', 'closed', 'skipped', 'ERROR'


def env_file():
    """Read the KEY=value lines of the install's .env file into a dict (empty if it cannot be read), without touching
    os.environ."""
    vals = {}
    try:
        with open(ssai_config.ENV_PATH) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    k, v = line.split('=', 1)
                    vals[k.strip()] = v.strip().strip('"').strip("'")
    except OSError:
        pass
    return vals


class Hub:
    def __init__(self, base, key):
        self.base, self.key = base.rstrip('/'), key

    def threats(self):
        r = requests.get(f'{self.base}/api/threats/', params={'limit': 500}, headers={'X-API-Key': self.key}, timeout=10)
        r.raise_for_status()
        return r.json()

    def post(self, path):
        return requests.post(f'{self.base}{path}', headers={'X-API-Key': self.key}, timeout=30)


def logger(tag, msg, facility='auth.info'):
    subprocess.run(['logger', '-p', facility, '-t', tag, msg], check=True)


def ufw_rules():
    r = subprocess.run(['ufw', 'status'], capture_output=True, text=True, timeout=15)
    return r.stdout


class Drill:
    """One staged attack. stage() does it; match(threat) recognises its finding; cleanup() undoes it."""
    name, category, expect = '', '', True          # expect=False: an evasion attempt, missed = a known gap

    def stage(self):
        pass

    def match(self, t):
        return False

    def cleanup(self):
        pass


class BruteForce(Drill):
    name, category = 'brute-force', 'detection'
    description = 'six failed SSH logins from one address (threshold: 5)'

    def __init__(self):
        self.ip = f'203.0.113.{random.randint(10, 250)}'

    def stage(self):
        for i in range(6):
            logger('sshd', f'Failed password for invalid user drill{i} from {self.ip} port {40000 + i} ssh2')

    def match(self, t):
        return t.get('type') == 'brute-force' and (t.get('url') or '').startswith(self.ip)


class SlowBruteForce(Drill):
    name, category, expect = 'low-and-slow-brute-force', 'evasion', False
    description = 'four failed logins from each of six addresses: under the per-address threshold'

    def __init__(self):
        base = random.randint(10, 200)
        self.ips = [f'198.51.100.{base + i}' for i in range(6)]

    def stage(self):
        for ip in self.ips:
            for i in range(4):
                logger('sshd', f'Failed password for root from {ip} port {41000 + i} ssh2')

    def match(self, t):
        if t.get('type') == 'distributed-brute-force':            # the detector added after this drill found the gap
            return True                                            # one row for the host; a re-run is a new sighting
        return t.get('type') == 'brute-force' and any((t.get('url') or '').startswith(ip) for ip in self.ips)


class BreakIn(Drill):
    name, category = 'break-in-attempt', 'detection'
    description = 'a "POSSIBLE BREAK-IN ATTEMPT" line in syslog'

    def __init__(self):
        self.ip = f'203.0.113.{random.randint(10, 250)}'

    def stage(self):
        logger('sshd', f'reverse mapping checking getaddrinfo for drill.example [{self.ip}] failed - '
                       'POSSIBLE BREAK-IN ATTEMPT!', facility='daemon.warning')

    def match(self, t):
        return t.get('type') == 'intrusion-attempt' and self.ip in (t.get('url') or '')


class Miner(Drill):
    name, category = 'miner-process', 'detection'
    description = 'a process named like a crypto miner (xmrig)'

    def __init__(self):
        self.proc = None

    def stage(self):
        self.proc = subprocess.Popen(['bash', '-c', 'exec -a xmrig-ssai-drill sleep 900'], start_new_session=True)

    def match(self, t):
        return (t.get('type') == 'suspicious-process' and self.proc is not None
                and (t.get('url') or '') == f'process://{self.proc.pid}')

    def cleanup(self):
        if self.proc and self.proc.poll() is None:
            os.killpg(self.proc.pid, signal.SIGTERM)


class Backdoor(Drill):
    name, category = 'backdoor-port', 'detection'
    description = 'a new listener on port 4444 (a classic reverse-shell port)'

    def __init__(self):
        self.sock = None

    def stage(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('0.0.0.0', 4444))
        self.sock.listen(1)

    def match(self, t):
        return t.get('type') == 'unexpected-listener' and (t.get('url') or '').endswith(':4444')

    def cleanup(self):
        if self.sock:
            self.sock.close()


class FileTamper(Drill):
    name, category = 'file-tamper', 'detection'
    description = 'the SSH server config is changed (timestamp only, contents untouched)'
    path = '/etc/ssh/sshd_config'

    def __init__(self):
        self.st = None

    def stage(self):
        self.st = os.stat(self.path)
        os.utime(self.path, ns=(self.st.st_atime_ns, self.st.st_mtime_ns + 1_000_000_000))

    def match(self, t):
        return t.get('type') == 'file-modification' and t.get('url') == self.path


class FirewallRoundTrip(Drill):
    """Not an attack: proves a block really lands in the firewall and is really removed (on this VM only)."""
    name, category = 'firewall-round-trip', 'response'
    description = 'block the brute-force address through the API, check ufw, unblock, check again'


def wait_for_agents(settle=20):
    """Agents take their baselines when they start (file signatures, log offsets, listening ports). A change staged
    before that is part of the baseline and, correctly, not reported, so give a freshly (re)started runner time."""
    try:
        out = subprocess.run(['systemctl', 'show', '-p', 'ActiveEnterTimestampMonotonic', 'ssai-agents'],
                             capture_output=True, text=True, timeout=5).stdout
        started_us = int(out.strip().split('=', 1)[1] or 0)
        with open('/proc/uptime') as f:
            up = float(f.read().split()[0])
        age = up - started_us / 1e6
        if 0 <= age < settle:
            print(f'agents started {age:.0f}s ago; waiting {settle - age:.0f}s for their baselines')
            time.sleep(settle - age)
    except (OSError, ValueError, IndexError, subprocess.SubprocessError):
        time.sleep(settle)


def wait_for_findings(drills, hub, timeout, started, known, results):
    """Poll the hub until every staged drill has a matching finding or time runs out; record what was caught or missed."""
    pending = [d for d in drills if d.name not in results]
    deadline = time.monotonic() + timeout
    while pending and time.monotonic() < deadline:
        time.sleep(5)                               # poll the hub every 5 seconds; the agents work on a timer, so faster would gain nothing
        fresh = [t for t in hub.threats() if t['id'] not in known or t.get('last_seen') != known[t['id']]]
        for d in list(pending):
            hit = next((t for t in fresh if d.match(t)), None)
            if hit:
                secs = int((datetime.now(timezone.utc) - started).total_seconds())
                results[d.name] = (CAUGHT if d.expect else CLOSED, f'finding #{hit["id"]} ({hit["severity"]}) after ~{secs}s', hit)
                pending.remove(d)
        if pending and all(not d.expect for d in pending):
            # only evasion attempts left: give them a fair window (one full log-agent cycle), not the whole timeout
            deadline = min(deadline, time.monotonic() + 90)
    for d in pending:
        results[d.name] = (MISSED if d.expect else GAP, f'no finding within {timeout}s', None)


def firewall_round_trip(hub, results):
    """Response test: a real block and unblock in this machine's firewall, on the brute-force finding."""
    bf = results.get('brute-force')
    if not shutil.which('ufw'):
        results['firewall-round-trip'] = (SKIPPED, 'ufw is not installed', None)
    elif not bf or bf[2] is None:
        results['firewall-round-trip'] = (SKIPPED, 'needs the brute-force finding', None)
    else:
        tid, ip = bf[2]['id'], bf[2]['url']
        r = hub.post(f'/api/threats/{tid}/block')
        added = ip in ufw_rules()
        u = hub.post(f'/api/threats/{tid}/unblock')
        removed = ip not in ufw_rules()
        ok = r.status_code == 200 and added and u.status_code == 200 and removed
        results['firewall-round-trip'] = (
            CAUGHT if ok else MISSED,
            f'block HTTP {r.status_code}, rule present: {added}; unblock HTTP {u.status_code}, rule gone: {removed}'
            + ('' if r.status_code == 200 else f' ({(r.json() or {}).get("error", "")[:120]})'), None)


def run_red_team(results):
    """Run the always-on offline red-team probes and add their outcome to the same report."""
    try:
        import logging
        import redteam
        logging.disable(logging.WARNING)                # the probes trip the fail-closed paths on purpose; not news
        try:
            rt = redteam.run_all()
        finally:
            logging.disable(logging.NOTSET)
        bad = [r['probe'] for r in rt if r['status'] == redteam.FAIL]
        results['redteam-probes'] = (MISSED if bad else CAUGHT,
                                     f"{sum(r['status'] == redteam.PASS for r in rt)} passed" + (f', failed: {bad}' if bad else ''), None)
    except Exception as e:                          # noqa: BLE001
        results['redteam-probes'] = (ERROR, f'{type(e).__name__}: {e}', None)


def run(only, timeout, hub, report_dir):
    """Stage the drills, wait for the hub to report matching findings, test the firewall block and unblock, run the
    red-team probes, and write the report."""
    wait_for_agents()
    started = datetime.now(timezone.utc)
    drills = [BruteForce(), SlowBruteForce(), BreakIn(), Miner(), Backdoor(), FileTamper()]
    if only:
        drills = [d for d in drills if d.name in only]
    results = {}
    # A finding counts when it is new OR an existing one was sighted again: SSAI folds a repeat into the same row
    # (times_seen, last_seen), so on a second run the backdoor port is a new sighting, not a new row.
    known = {t['id']: t.get('last_seen') for t in hub.threats()}
    for d in drills:
        try:
            d.stage()
        except Exception as e:                      # noqa: BLE001 -- a drill that cannot be staged is reported
            results[d.name] = (ERROR, f'could not stage: {type(e).__name__}: {e}', None)
    wait_for_findings(drills, hub, timeout, started, known, results)
    for d in drills:
        try:
            d.cleanup()
        except Exception:                           # noqa: BLE001
            # cleaning up one drill must not stop the others being cleaned up
            pass

    if not only or 'firewall-round-trip' in only:
        firewall_round_trip(hub, results)

    run_red_team(results)

    descriptions = {d.name: d.description for d in drills}
    descriptions['firewall-round-trip'] = FirewallRoundTrip.description
    descriptions['redteam-probes'] = 'the 13 offline probes of RedTeamAgent'
    rows = [{'drill': k, 'status': v[0], 'detail': v[1], 'what': descriptions.get(k, '')} for k, v in results.items()]
    os.makedirs(report_dir, exist_ok=True)
    stamp = started.strftime('%Y%m%dT%H%M%SZ')
    with open(os.path.join(report_dir, f'{stamp}.json'), 'w') as f:
        json.dump({'started': started.isoformat(), 'results': rows}, f, indent=2)
    with open(os.path.join(report_dir, f'{stamp}.md'), 'w') as f:
        f.write(f'# Sandbox drills {started:%Y-%m-%d %H:%M} UTC\n\n| Drill | Result | Detail | What was staged |\n|---|---|---|---|\n')
        for r in rows:
            f.write(f"| {r['drill']} | {r['status']} | {r['detail']} | {r['what']} |\n")
    return rows


def main(argv=None):
    """Command-line entry point: refuse unless this is a sandbox and we are root, run the drills, and print a line per
    result."""
    p = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    p.add_argument('--only', default='', help='comma-separated drill names')
    p.add_argument('--timeout', type=int, default=420, help='seconds to wait for findings (default 420)')
    p.add_argument('--hub', default='', help='hub URL (default: this machine, PORT from .env)')
    a = p.parse_args(argv)
    env = env_file()
    if env.get('SSAI_SANDBOX', os.environ.get('SSAI_SANDBOX', '')).strip().lower() not in ('1', 'true', 'yes', 'on'):
        print('refusing: these drills change this machine (logs, a process, a port, the firewall). Run them only on a '
              'sandbox install with SSAI_SANDBOX=1 in .env.', file=sys.stderr)
        return 2
    if os.geteuid() != 0:
        print('run as root (sudo): the drills write system logs and change the firewall', file=sys.stderr)
        return 2
    hub = Hub(a.hub or f"http://127.0.0.1:{env.get('PORT', '5000')}", env.get('SSAI_API_KEY', ''))
    only = {x.strip() for x in a.only.split(',') if x.strip()}
    rows = run(only, a.timeout, hub, os.path.join(ssai_config.INSTANCE_DIR, 'sandbox_drills'))
    width = max(len(r['drill']) for r in rows)
    for r in rows:
        print(f"{r['status']:8} {r['drill']:{width}}  {r['detail']}")
    return 1 if any(r['status'] in (MISSED, ERROR) for r in rows) else 0


if __name__ == '__main__':
    sys.exit(main())
