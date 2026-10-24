#!/usr/bin/env python3
"""
SwarmSentinel — rebuild swarmsentinel.db from the GitHub threat ledger.

The Azure VM (and its live SQLite DB) is gone; the surviving copy of the
collective threat intelligence is threats/known_threats.json in the repo.
This script rebuilds backend/instance/swarmsentinel.db from that ledger.

Run from the backend/ directory with the venv python:
    PYTHONPATH=. ../swarmsentinel-env/bin/python3 import_ledger.py
"""
import json
import os
import sys
from datetime import datetime, timezone

from flask import Flask

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
LEDGER = os.path.join(REPO, 'threats', 'known_threats.json')

sys.path.insert(0, HERE)
from models import db, Threat, normalize_severity  # noqa: E402

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///swarmsentinel.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)


def parse_ts(value):
    """Turn a timestamp string from the ledger into a datetime, trying several formats; falls back to 'now' if it is
    missing or unreadable."""
    if not value:
        return datetime.now(timezone.utc)
    for parse in (datetime.fromisoformat,
                  lambda v: datetime.strptime(v, '%Y-%m-%d %H:%M:%S.%f'),
                  lambda v: datetime.strptime(v, '%Y-%m-%d %H:%M:%S')):
        try:
            return parse(value)
        except (ValueError, TypeError):
            continue
    return datetime.now(timezone.utc)


def main():
    """One-off import of the threat ledger file (known_threats.json) into the database.
    It refuses to run on a database that already has threats unless --force is given, to avoid duplicating a live database.
    """
    if not os.path.exists(LEDGER):
        print(f'✗ Ledger not found: {LEDGER}')
        sys.exit(1)

    with open(LEDGER, 'r') as f:
        entries = json.load(f)
    print(f'Ledger entries: {len(entries)}')

    with app.app_context():
        db.create_all()
        existing = Threat.query.count()
        if existing > 0 and '--force' not in sys.argv:
            print(f'✗ DB already has {existing} threats — refusing to import.')
            print('  This may be a live database. Re-run with --force to append anyway.')
            sys.exit(1)

        imported = 0
        for e in entries:
            if not isinstance(e, dict):
                continue
            desc = e.get('description', '')
            times = e.get('times_seen', 1)
            if times and times > 1:
                desc = f'{desc} [ledger: seen {times}x, ' \
                       f'{e.get("first_seen", "?")} → {e.get("last_seen", "?")}]'
            db.session.add(Threat(
                url=(e.get('url') or '')[:500],
                type=(e.get('type') or 'unknown')[:100],
                severity=normalize_severity(e.get('severity')),
                description=desc,
                detected_by=(e.get('detected_by') or 'ledger-import')[:100],
                node_id='ledger-import',
                status='active',
                timestamp=parse_ts(e.get('last_seen') or e.get('first_seen')),
                ai_analyzed=False,
            ))
            imported += 1
            if imported % 1000 == 0:
                db.session.commit()
                print(f'  ...{imported}')
        db.session.commit()
        print(f'✓ Imported {imported} threats into swarmsentinel.db '
              f'(total now: {Threat.query.count()})')


if __name__ == '__main__':
    main()
