#!/usr/bin/env python3
"""AI panel lineage: what changed, and roll back to an earlier configuration (2026-10-09).

    python3 backend/tools/lineage_cli.py events [N]          recent manifest changes, newest first
    python3 backend/tools/lineage_cli.py show <id>           one manifest (panel members, models, config hashes)
    python3 backend/tools/lineage_cli.py verdict <threat-id> the lineage stamped on one threat's AI verdict (needs the hub DB)
    python3 backend/tools/lineage_cli.py restore <id>        show what a rollback would write
    python3 backend/tools/lineage_cli.py restore <id> --apply   write it (current files kept as .bak-<timestamp>)

Restoring puts back this installation's override files as they were under that manifest: instance/ai_models.json,
ai_weights.json and ai_providers.json. A file that did not exist then is moved aside. The agents notice within a
cycle and log the change as a new lineage event. API keys live in .env and are never part of a manifest.
"""
import json
import os
import sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
sys.path[:0] = [os.path.join(BACKEND, 'agents'), BACKEND]
import lineage  # noqa: E402
import state_store  # noqa: E402


def _print(obj):
    print(json.dumps(obj, indent=2, sort_keys=True, default=str))


def cmd_events(store, n=20):
    """Print the most recent panel configuration changes, newest first."""
    ev = store.lineage_events(n)
    if not ev:
        print('No lineage recorded yet (SwarmConsensusAgent writes it on start and every cycle).')
    for e in ev:
        print(f"{e['ts']}  {e['old_id'] or '-':>12} -> {e['new_id']}")
        for c in e['changes']:
            print(f'    {c}')
    return 0


def cmd_show(store, mid):
    m = store.get_manifest(mid)
    if not m:
        print(f'No manifest {mid}', file=sys.stderr)
        return 1
    m = dict(m, snapshot=sorted(m.get('snapshot', {})))   # names only; contents via restore
    _print(m)
    return 0


def plan_restore(store, mid, instance_dir):
    """[(path, new_text_or_None)] -- None means the file did not exist under that manifest (move it aside)."""
    m = store.get_manifest(mid)
    if not m:
        raise LookupError(f'No manifest {mid}')
    snap = m.get('snapshot') or {}
    plan = []
    for name in lineage.SNAPSHOT_FILES:
        path = os.path.join(instance_dir, name)
        want = snap.get(name)
        try:
            with open(path, encoding='utf-8') as f:
                have = f.read()
        except OSError:
            have = None
        if want != have:
            plan.append((path, want))
    return plan


def apply_restore(plan):
    """Carry out a restore plan: keep each current file as a .bak copy, then write the old contents (or leave it moved
    aside if it did not exist)."""
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    for path, text in plan:
        if os.path.exists(path):
            os.replace(path, f'{path}.bak-{stamp}')
        if text is not None:
            tmp = path + '.tmp'
            with open(tmp, 'w', encoding='utf-8') as f:
                f.write(text)
            os.replace(tmp, path)


def cmd_restore(store, mid, apply, instance_dir):
    """Show what restoring an earlier configuration would change, and write it only when --apply was given."""
    try:
        plan = plan_restore(store, mid, instance_dir)
    except LookupError as e:
        print(e, file=sys.stderr)
        return 1
    if not plan:
        print(f'Nothing to do: the override files already match manifest {mid}.')
        return 0
    for path, text in plan:
        print(f"{'write ' if text is not None else 'remove'} {path}" + (f' ({len(text)} bytes)' if text else ''))
    if not apply:
        print('Dry run. Add --apply to write these files.')
        return 0
    apply_restore(plan)
    print(f'Restored manifest {mid}. The agents pick it up within a cycle.')
    return 0


def cmd_verdict(threat_id):
    """Print the lineage (which panel and settings made it) stored on one threat's AI verdict."""
    os.environ.setdefault('SSAI_PROVIDER_CHECK', '0')
    from app import app
    from models import Threat
    with app.app_context():
        t = Threat.query.get(int(threat_id))
        if t is None:
            print(f'No threat {threat_id}', file=sys.stderr)
            return 1
        try:
            v = json.loads(t.ai_verdict or '{}')
        except ValueError:
            v = {}
    lin = (v.get('consensus') or {}).get('lineage')
    if not lin:
        print('This verdict has no lineage (made before 2026-10-09, recalled, or not judged by the panel).')
        return 0
    _print(lin)
    return 0


def main(argv):
    """Command-line entry point: pick the sub-command (events, show, verdict, restore) from the arguments and run it."""
    if not argv or argv[0] in ('-h', '--help'):
        print(__doc__)
        return 0
    store = state_store.store()
    cmd, rest = argv[0], argv[1:]
    if cmd == 'events':
        return cmd_events(store, int(rest[0]) if rest else 20)
    if cmd == 'show' and rest:
        return cmd_show(store, rest[0])
    if cmd == 'verdict' and rest:
        return cmd_verdict(rest[0])
    if cmd == 'restore' and rest:
        return cmd_restore(store, rest[0], '--apply' in rest, lineage._instance_dir())
    print(__doc__)
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
