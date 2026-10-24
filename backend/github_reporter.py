#!/usr/bin/env python3
"""
Task 6: GitHub auto-push pipeline for SwarmSentinel threat intelligence.

Maintains a single deduplicated ledger (threats/known_threats.json) of
distinct threats, each with a times_seen counter, instead of appending a
new record every time the same threat re-fires. Runs every 5 minutes,
updates the ledger, commits + pushes to GitHub.
"""
import os
import sys
import re
import json
import time
import hashlib
import sqlite3
import logging
import logsafe
import subprocess
import socket
from datetime import datetime, timezone

import getpass

import ssai_config
from agents import redact

try:                                       # this service has no EnvironmentFile: read the settings (SSAI_PRIVATE_NAMES...) itself
    from dotenv import load_dotenv
    load_dotenv(ssai_config.ENV_PATH)
except ImportError:
    pass

redact.install_log_redaction()

REPO        = ssai_config.THREAT_INTEL_REPO
DB_PATH     = ssai_config.DB_PATH
EXPORT_DIR  = os.path.join(REPO, 'threats')
LEDGER_PATH = os.path.join(EXPORT_DIR, 'known_threats.json')
STATE_FILE  = ssai_config.GITHUB_STATE_PATH
INTERVAL    = int(os.environ.get('SSAI_GH_INTERVAL', 300))   # 5 min default
GIT_NAME    = 'SwarmSentinel Bot'
GIT_EMAIL   = 'swarmsentinel@local.host'

SEVERITY_RANK = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [github-reporter] %(levelname)s %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logsafe.SecureRotatingFileHandler(os.path.join(REPO, 'logs', 'github_reporter.log'), maxBytes=10 * 1024 * 1024, backupCount=3),
    ]
)
log = logging.getLogger('github-reporter')


def load_state():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as f:
            return json.load(f)
    return {'last_id': 0, 'last_push': None}


def save_state(state):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    with open(STATE_FILE, 'w') as f:
        json.dump(state, f)


def resync_cursor(last_id, last_push):
    """The retention job deletes old rows, and SQLite hands the freed ids out again. A cursor that is AHEAD of the newest id in the
    table then waits for ids that never come, and the ledger silently stops updating (it did, for three weeks). When that happens,
    fall back to the newest row that existed at the last push, so nothing newer is skipped and nothing older is sent twice."""
    conn = sqlite3.connect(DB_PATH, timeout=5)
    try:
        newest = conn.execute('SELECT MAX(id) FROM threat').fetchone()[0] or 0
        if last_id <= newest:
            return last_id
        cutoff = (last_push or '')[:19].replace('T', ' ')
        at_push = conn.execute('SELECT MAX(id) FROM threat WHERE timestamp <= ?', (cutoff,)).fetchone()[0] if cutoff else None
    finally:
        conn.close()
    fixed = at_push or 0
    log.warning(f'Cursor {last_id} is ahead of the newest threat id {newest} (old rows were cleaned up); resuming from {fixed}.')
    return fixed


def fetch_new_threats(last_id):
    """Read from the database every threat newer than `last_id` (the last one already published), oldest first."""
    conn = sqlite3.connect(DB_PATH, timeout=5)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute('''
        SELECT id, url, type, severity, description, detected_by, node_id, status, timestamp
        FROM threat WHERE id > ? ORDER BY id ASC
    ''', (last_id,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def fetch_all_threats():
    """Read every threat in the database, oldest first; used for the one-time --backfill rebuild."""
    conn = sqlite3.connect(DB_PATH, timeout=5)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute('''
        SELECT id, url, type, severity, description, detected_by, node_id, status, timestamp
        FROM threat ORDER BY id ASC
    ''')
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


_HOSTNAME = socket.gethostname()

# ── privacy: what may leave this machine ─────────────────────────────────────────────────────────────────────────────
# The ledger is meant to describe THREATS (attacker addresses, malware URLs), never the people or machines that saw them.
# So before anything is written to it we remove: this network's addresses, the names of the machines and accounts on it
# (from the database, this host, and SSAI_PRIVATE_NAMES), the recipient and subject of quarantined mail, and the local
# part of any email address (the sender's domain stays: it is the useful signal).
_EMAIL = re.compile(r'[A-Za-z0-9._%+\-]+@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})')
_SYSLOG_PREFIX = re.compile(r'^\d{4}-\d{2}-\d{2}T[\d:.+]+\s+\S+\s+')          # "<timestamp> <any hostname> " on a syslog line
_MAIL_RECIPIENT = re.compile(r',\s*to:\s*[^,]+')
_MAIL_SUBJECT = re.compile(r',\s*subject:\s*".*?"(?=,|$)')
_private_re = {'re': None}


def _name_list(extra=()):
    """Collect the names of this machine, its user, SSAI_PRIVATE_NAMES and `extra`, longest first, ready to be masked.
    Longer names come first so a long name is replaced before a shorter one inside it. Very short names, numbers, 'root' and 'localhost' are skipped because masking them would damage ordinary text.
    """
    names = {_HOSTNAME, os.environ.get('USER', ''), os.environ.get('USERNAME', '')}
    try:
        names.add(getpass.getuser())
    except Exception:
        # some systems have no user name to look up; the other names are still masked
        pass
    names.update(n.strip() for n in os.environ.get('SSAI_PRIVATE_NAMES', '').split(','))
    names.update(extra)
    return sorted({n.lower() for n in names if n and len(n) >= 3 and not n.isdigit() and n.lower() not in ('root', 'localhost')},
                  key=len, reverse=True)


def load_private_names(db_path=None):
    """Compile the set of names to mask: this host, its user, SSAI_PRIVATE_NAMES, and every machine the hub has seen."""
    extra = []
    try:
        conn = sqlite3.connect(db_path or DB_PATH, timeout=5)
        for sql in ('SELECT hostname FROM agent', 'SELECT hostname FROM node', 'SELECT node_id FROM node'):
            try:
                extra += [r[0] for r in conn.execute(sql) if r[0]]
            except sqlite3.Error:
                pass
        conn.close()
    except sqlite3.Error:
        pass
    names = _name_list(extra)
    _known_names[:] = names
    _private_re['re'] = re.compile(r'(?<![A-Za-z0-9])(?:' + '|'.join(re.escape(n) for n in names) + r')(?![A-Za-z0-9])', re.I) if names else None
    return names


_PROCESS_PUBLIC = 'Suspicious process detected on a monitored host (command line withheld from the public ledger)'
_HOME = re.compile(r'(/home/|/Users/|[A-Za-z]:[\\/]Users[\\/])[^/\\\s"\']+')


_WITHHELD = '[withheld: could not be made safe to publish]'
_known_names = []                                           # every machine name the hub has seen (set by load_private_names)


def _mask(s):
    """Make one piece of text safe for the public ledger: hide credentials, home folders, this network's names, e-mail senders and private addresses.
    Returns a 'withheld' notice instead if anything private could still remain.
    """
    if not s:
        return s
    s = redact.redact(s)                                    # credentials: key formats, key=value, sshpass, URL passwords
    s = _HOME.sub(r'\1[user]', s)
    if _private_re['re'] is None:
        load_private_names()
    if _private_re['re'] is not None:
        s = _private_re['re'].sub('[node]', s)
    s = _EMAIL.sub(lambda m: '[sender]@' + m.group(1), s)
    # Hide the host part of private-network addresses (192.168.x.x, 10.x.x.x, 172.16-31.x.x) but keep the first
    # numbers, so the kind of network is still visible.
    s = re.sub(r'\b(192\.168)\.\d+\.\d+\b', r'\1.xxx.xxx', s)
    s = re.sub(r'\b(10)\.\d+\.\d+\.\d+\b', r'\1.xxx.xxx.xxx', s)
    s = re.sub(r'\b(172\.(?:1[6-9]|2\d|3[01]))\.\d+\.\d+\b', r'\1.xxx.xxx', s)
    return _shared_rules(s)


def _shared_rules(s):
    """The same redaction rules the cloud gate uses (sanitizer.Redactor), so the public ledger can never be weaker than the
    AI path (audit F-09): MAC addresses, IPv6, Tailscale/link-local addresses, user names in log lines, internal host names.
    Attacker addresses on the public internet stay, as before. If anything private still shows after that, or the rules
    cannot run, the text is withheld: a public repository gets nothing rather than a leak."""
    try:
        import sanitizer
        red = sanitizer.Redactor(extra_names=list(_known_names), keep_public_ips=True)
        s = red.redact(s)
        if sanitizer.Redactor.private_leftovers(s):
            return _WITHHELD
        return s
    except Exception as exc:                                # noqa: BLE001 -- fail closed
        log.warning(f'ledger masking failed, text withheld: {type(exc).__name__}: {exc}')
        return _WITHHELD


def _sanitize(record):
    """Remove everything about this network and its people from a threat before it is published.
    External/attacker IPs are intentionally left intact: they identify the threat, not this network."""
    desc = record.get('description') or ''
    desc = _SYSLOG_PREFIX.sub('', desc)                     # the log line's own hostname, whatever it is
    if record.get('type') == 'email-quarantine':            # who received it and what it said are private
        desc = _MAIL_SUBJECT.sub('', _MAIL_RECIPIENT.sub('', desc))
    if record.get('type') == 'suspicious-process':
        # A process finding's description is a whole `ps aux` line: user, paths, arguments, sometimes a password
        # typed on the command line. None of it identifies the threat for anyone else, so none of it is published.
        desc = _PROCESS_PUBLIC
    desc = _mask(desc)
    record = dict(record)
    record['description']  = desc
    record['url']          = _mask(record.get('url'))
    record['detected_by']  = _mask(record.get('detected_by'))
    record['node_id']      = _mask(record.get('node_id'))
    return record


def threat_identity(record):
    """Stable string identifying 'the same' threat across repeat occurrences."""
    ttype = record.get('type') or 'unknown'
    url = (record.get('url') or '').strip()

    if ttype == 'firewall-block':
        # Identity = the external source IP. Destination port is ephemeral
        # per-connection noise and shouldn't split one attacker into many entries.
        m = re.match(r'^(\d{1,3}(?:\.\d{1,3}){3}):\d+$', url) or re.match(r'^([0-9a-fA-F:.]+)', url)
        src = m.group(1) if m else url
        return f'firewall-block:{src}'

    if url:
        # e.g. suspicious-port url already carries the masked host:port,
        # which is exactly the right identity for that finding.
        return f'{ttype}:{url}'

    # Fallback: normalize the description by stripping timestamps/digits
    # so near-identical repeat log lines collapse to one identity.
    desc = record.get('description') or ''
    desc = re.sub(r'\d{4}-\d{2}-\d{2}T[\d:.+]+', '', desc)
    desc = re.sub(r'\d+', '#', desc)
    return f'{ttype}:{desc.strip()[:200]}'


def threat_id(record):
    return hashlib.sha256(threat_identity(record).encode()).hexdigest()[:10]


def load_ledger():
    if os.path.exists(LEDGER_PATH):
        with open(LEDGER_PATH) as f:
            data = json.load(f)
        return {e['id']: e for e in data}
    return {}


def save_ledger(ledger):
    ordered = sorted(ledger.values(), key=lambda r: (-r['times_seen'], r['id']))
    os.makedirs(EXPORT_DIR, exist_ok=True)
    with open(LEDGER_PATH, 'w') as f:
        json.dump(ordered, f, indent=2, default=str)


def update_ledger(ledger, raw_threats):
    """Fold raw threat rows into the ledger. Returns (new_count, repeat_count)."""
    new_count = 0
    repeat_count = 0
    for raw in raw_threats:
        rec = _sanitize(raw)
        tid = threat_id(rec)
        ts = rec.get('timestamp') or datetime.now(timezone.utc).isoformat()

        entry = ledger.get(tid)
        if entry is None:
            ledger[tid] = {
                'id': tid,
                'type': rec.get('type'),
                'severity': rec.get('severity'),
                'description': rec.get('description'),
                'url': rec.get('url'),
                'detected_by': rec.get('detected_by'),
                'first_seen': ts,
                'last_seen': ts,
                'times_seen': 1,
            }
            new_count += 1
        else:
            entry['times_seen'] += 1
            entry['last_seen'] = ts
            entry['description'] = rec.get('description') or entry['description']
            if SEVERITY_RANK.get(rec.get('severity'), 0) > SEVERITY_RANK.get(entry.get('severity'), 0):
                entry['severity'] = rec.get('severity')
            repeat_count += 1
    return new_count, repeat_count


def scrub_ledger(ledger):
    """Re-sanitize an existing ledger (entries written before a rule existed). Ids are derived from the sanitized text, so
    they are recomputed, and entries that become the same threat are merged. Returns (new_ledger, changed, merged)."""
    load_private_names()
    out, changed, merged = {}, 0, 0
    for entry in ledger.values():
        clean = _sanitize(entry)
        if any(clean.get(k) != entry.get(k) for k in ('description', 'url', 'detected_by')):
            changed += 1
        rec = dict(entry, description=clean['description'], url=clean['url'], detected_by=clean['detected_by'])
        tid = threat_id(rec)
        rec['id'] = tid
        if tid in out:
            keep = out[tid]
            keep['times_seen'] = keep.get('times_seen', 1) + rec.get('times_seen', 1)
            keep['first_seen'] = min(str(keep.get('first_seen')), str(rec.get('first_seen')))
            keep['last_seen'] = max(str(keep.get('last_seen')), str(rec.get('last_seen')))
            if SEVERITY_RANK.get(rec.get('severity'), 0) > SEVERITY_RANK.get(keep.get('severity'), 0):
                keep['severity'] = rec.get('severity')
            merged += 1
        else:
            out[tid] = rec
    return out, changed, merged


def git_commit_push(message):
    """Stage, commit, and push the ledger. Returns True if pushed."""
    env = os.environ.copy()
    env['GIT_AUTHOR_NAME']     = GIT_NAME
    env['GIT_AUTHOR_EMAIL']    = GIT_EMAIL
    env['GIT_COMMITTER_NAME']  = GIT_NAME
    env['GIT_COMMITTER_EMAIL'] = GIT_EMAIL

    def run(cmd):
        r = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True, env=env, timeout=30)
        if r.returncode != 0:
            log.warning(f'git cmd failed: {" ".join(cmd)}\n{r.stderr.strip()}')
        return r

    run(['git', 'add', 'threats/'])
    # only the ledger counts: the checkout has other uncommitted work, which is not a reason to commit or push
    status = subprocess.run(['git', 'status', '--porcelain', '--', 'threats/'], cwd=REPO,
                            capture_output=True, text=True).stdout.strip()
    if not status:
        log.info('No ledger changes to commit.')
        return False

    run(['git', 'commit', '-m', message, '--', 'threats/'])         # never sweep in files someone else has staged

    remote_url = subprocess.run(
        ['git', 'remote', 'get-url', 'origin'],
        cwd=REPO, capture_output=True, text=True
    ).stdout.strip()

    if remote_url and 'github.com' in remote_url:
        result = run(['git', 'push', 'origin', 'main'])
        if result.returncode == 0:
            log.info('Pushed ledger update to GitHub.')
            return True
        else:
            log.warning('Push failed — commit saved locally.')
            return False
    else:
        log.info(f'No GitHub remote — committed locally: {message}')
        return False


def push_waiting_commits(repo=None, require_github=True):
    """Try again to push ledger commits that are already made but not yet on GitHub. Returns True if something was pushed.

    A push is refused when someone else pushed first. The commit then waits here, and without this it would wait until the next NEW
    finding made another commit and pushed both, which on a quiet network can be a long time. A push of commits that are already
    ahead of GitHub is harmless: if GitHub has moved on, the push is refused again and the updater reconciles it (deploy/update.sh).
    """
    repo = repo or REPO
    def git(*args):
        return subprocess.run(['git', *args], cwd=repo, capture_output=True, text=True, timeout=30)
    try:
        remote = git('remote', 'get-url', 'origin').stdout.strip()
        if require_github and 'github.com' not in remote:
            return False
        ahead = git('rev-list', '--count', 'origin/main..main')
        if ahead.returncode != 0 or int(ahead.stdout.strip() or 0) == 0:
            return False
        result = git('push', 'origin', 'main')
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        log.warning(f'Could not retry the waiting push: {exc}')
        return False
    if result.returncode == 0:
        log.info('Pushed ledger commits that were waiting.')
        return True
    log.info('A ledger commit is still waiting: GitHub has newer work. The next deploy (deploy/update.sh) will reconcile it.')
    return False


def run_cycle():
    """One pass of the reporter: take the threats added since last time, merge them into the ledger, commit and push it, and remember how far we got.
    Does nothing (apart from retrying a waiting push) when there are no new threats.
    """
    load_private_names()                      # machines can appear at any time: refresh the names to mask every cycle
    state = load_state()
    state['last_id'] = resync_cursor(state['last_id'], state.get('last_push'))
    threats = fetch_new_threats(state['last_id'])
    if not threats:
        log.debug('No new threats since last run.')
        push_waiting_commits()
        return

    ledger = load_ledger()
    new_count, repeat_count = update_ledger(ledger, threats)
    save_ledger(ledger)

    msg = (f'threat-intel: {new_count} new, {repeat_count} repeat sightings '
           f'({len(ledger)} known threats total) — '
           f'{datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}')
    pushed = git_commit_push(msg)

    state['last_id']   = max(t['id'] for t in threats)
    state['last_push'] = datetime.now(timezone.utc).isoformat()
    save_state(state)
    log.info(f'Cycle complete. last_id={state["last_id"]}, new={new_count}, '
             f'repeat={repeat_count}, pushed={pushed}')


def backfill():
    """One-time consolidation: rebuild the ledger from the *entire* history
    in the DB, replacing any legacy per-day export files."""
    log.info('Starting full-history backfill...')
    all_threats = fetch_all_threats()
    log.info(f'Loaded {len(all_threats)} historical threat rows.')

    ledger = {}
    new_count, repeat_count = update_ledger(ledger, all_threats)
    save_ledger(ledger)
    log.info(f'Backfill built {len(ledger)} distinct known threats '
             f'from {len(all_threats)} historical rows '
             f'(new={new_count}, repeat={repeat_count}).')

    # Remove legacy per-day dump files -- superseded by the ledger.
    for fname in os.listdir(EXPORT_DIR):
        if re.match(r'^\d{4}-\d{2}-\d{2}\.json$', fname) or fname == 'latest.json':
            os.remove(os.path.join(EXPORT_DIR, fname))
            log.info(f'Removed legacy export file: {fname}')

    state = {
        'last_id': max((t['id'] for t in all_threats), default=0),
        'last_push': None,
    }
    save_state(state)

    msg = (f'threat-intel: consolidate into deduplicated known-threats ledger '
           f'({len(ledger)} distinct threats from {len(all_threats)} historical detections)')
    pushed = git_commit_push(msg)
    log.info(f'Backfill commit complete. pushed={pushed}')


def main():
    """Entry point: run --backfill or --scrub once if asked, otherwise loop forever running run_cycle() every INTERVAL seconds.
    A failed cycle is logged and the loop carries on.
    """
    if len(sys.argv) > 1 and sys.argv[1] == '--backfill':
        backfill()
        return
    if len(sys.argv) > 1 and sys.argv[1] == '--scrub':
        ledger, changed, merged = scrub_ledger(load_ledger())
        save_ledger(ledger)
        log.info(f'Scrub: {changed} entries rewritten, {merged} merged, {len(ledger)} remain.')
        if changed or merged:
            git_commit_push('threat-intel: remove private names and addresses from existing entries')
        return

    log.info(f'GitHub reporter started. Interval: {INTERVAL}s')
    load_private_names()
    os.makedirs(EXPORT_DIR, exist_ok=True)
    os.makedirs(os.path.join(REPO, 'logs'), exist_ok=True)
    while True:
        try:
            run_cycle()
        except Exception as e:
            log.error(f'Cycle error: {e}', exc_info=True)
        time.sleep(INTERVAL)


if __name__ == '__main__':
    main()
