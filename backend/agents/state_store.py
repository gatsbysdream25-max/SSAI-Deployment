"""Local shared state for the agents on one machine (2026-10-09, "Local Shared State Plan").

Findings are already shared and deduplicated by the hub's database (Threat.fingerprint / first_seen / last_seen /
times_seen), and every agent reaches it through the hub API. What was missing is the agents' OWN state, which lived
only in memory and was lost on every restart:

  agent_state  per-agent resume point (a log offset, the last cycle time, ...): a restarted agent carries on where it
               stopped instead of skipping what happened while it was down or starting over
  sync_log     every pull from an outside source (abuse.ch feeds, ...): when, what came back, how many records, so a
               restart does not re-download a feed that was refreshed minutes ago and an outage is visible
  lineage_*    which AI models / config produced each verdict (see lineage.py)

One SQLite file per machine under ssai_config.INSTANCE_DIR (the /data volume in Docker): no server, no setup, works
with no network. It is NOT the hub database: a node keeps its own, and nothing here is needed for the hub's findings.

Failure policy: state is an optimisation, never a reason for an agent to stop. Every public function catches its own
errors, logs once, and returns the "nothing remembered" answer (None / {} / False).
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

log = logging.getLogger("state_store")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS agent_state (
    agent_id   TEXT NOT NULL,
    key        TEXT NOT NULL,
    value      TEXT NOT NULL,              -- JSON
    updated_at TEXT NOT NULL,
    PRIMARY KEY (agent_id, key)
);
CREATE TABLE IF NOT EXISTS sync_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    source      TEXT NOT NULL,             -- e.g. threatfox, feodo, urlhaus
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    ok          INTEGER NOT NULL DEFAULT 0,
    http_status INTEGER,
    records     INTEGER,
    note        TEXT
);
CREATE INDEX IF NOT EXISTS ix_sync_source ON sync_log (source, id);
CREATE TABLE IF NOT EXISTS lineage_manifest (
    manifest_id TEXT PRIMARY KEY,          -- sha256 of the canonical manifest, first 12 hex
    created_at  TEXT NOT NULL,
    body        TEXT NOT NULL              -- JSON: panel members + models + config/data hashes + config snapshot
);
CREATE TABLE IF NOT EXISTS lineage_event (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    old_id      TEXT,
    new_id      TEXT NOT NULL,
    changes     TEXT NOT NULL              -- JSON list of human-readable changes
);
"""

SYNC_LOG_KEEP = 5000          # rows kept per source; older ones are pruned on write


def default_path() -> str:
    if os.environ.get("SSAI_STATE_DB"):                 # tests, or an operator who wants it elsewhere
        return os.environ["SSAI_STATE_DB"]
    try:
        import ssai_config
        return os.path.join(ssai_config.INSTANCE_DIR, "agent_state.db")
    except ImportError:
        return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "instance", "agent_state.db")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class StateStore:
    """Thread-safe (one connection per thread).

    Written by the agent runner (root on a bare-metal hub), read by the web app (the install's own user) for
    GET /api/status/governance. So: a rollback journal, not WAL (a WAL reader needs WRITE access to the -shm file,
    which another user does not have), the file 0644 (it holds log offsets, feed pull times and AI-panel config
    snapshots; no secrets: keys live in .env), and the web app opens it with readonly=True."""

    def __init__(self, path: Optional[str] = None, readonly: bool = False):
        self.path = path or default_path()
        self.readonly = readonly
        self._local = threading.local()
        self._init_lock = threading.Lock()
        self._ready = False
        self._warned: Dict[str, float] = {}

    # ── plumbing ────────────────────────────────────────────────────────────
    def _warn(self, what: str, exc: BaseException) -> None:
        now = time.time()
        if now - self._warned.get(what, 0) >= 300:
            self._warned[what] = now
            log.warning(f"agent state store: {what} failed ({type(exc).__name__}: {exc}); carrying on without it")

    def _conn(self) -> sqlite3.Connection:
        """This thread's SQLite connection, opened on first use (each thread keeps its own, since a connection should not
        be shared between threads). Read-only mode never creates the file; otherwise the folder and tables are created
        once, and the lock makes sure only one thread does that set-up."""
        c = getattr(self._local, "conn", None)
        if c is None:
            if self.readonly:
                if not os.path.exists(self.path):
                    raise FileNotFoundError(self.path)          # nothing recorded yet; callers fail soft
                c = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True, timeout=10)
                self._local.conn = c
                return c
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            # timeout=10: wait up to 10 seconds for a lock held by another process before giving up.
            c = sqlite3.connect(self.path, timeout=10)
            c.execute("PRAGMA journal_mode=DELETE")                # also converts a store created in WAL mode
            self._local.conn = c
        if not self._ready:
            with self._init_lock:
                if not self._ready:
                    c.executescript(_SCHEMA)
                    c.commit()
                    try:
                        os.chmod(self.path, 0o644)
                    except OSError:
                        pass
                    self._ready = True
        return c

    def close(self) -> None:
        c = getattr(self._local, "conn", None)
        if c is not None:
            c.close()
            self._local.conn = None

    # ── agent_state ─────────────────────────────────────────────────────────
    def get(self, agent_id: str, key: str, default: Any = None) -> Any:
        try:
            row = self._conn().execute("SELECT value FROM agent_state WHERE agent_id=? AND key=?",
                                       (agent_id, key)).fetchone()
            return json.loads(row[0]) if row else default
        except Exception as e:                       # noqa: BLE001 -- state is optional
            self._warn("read", e)
            return default

    def put(self, agent_id: str, key: str, value: Any) -> bool:
        """Save `value` (stored as JSON) under (agent_id, key), replacing any earlier value. Returns False instead of
        raising when the store is unusable, because this state is optional."""
        try:
            c = self._conn()
            c.execute("INSERT INTO agent_state (agent_id, key, value, updated_at) VALUES (?,?,?,?) "
                      "ON CONFLICT(agent_id, key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
                      (agent_id, key, json.dumps(value), _now()))
            c.commit()
            return True
        except Exception as e:                       # noqa: BLE001
            self._warn("write", e)
            return False

    def agent_states(self) -> Dict[str, Dict[str, Any]]:
        """{agent_id: {key: {"value":..., "updated_at":...}}} for the status page / support bundle."""
        out: Dict[str, Dict[str, Any]] = {}
        try:
            for aid, key, val, ts in self._conn().execute(
                    "SELECT agent_id, key, value, updated_at FROM agent_state ORDER BY agent_id, key"):
                out.setdefault(aid, {})[key] = {"value": json.loads(val), "updated_at": ts}
        except Exception as e:                       # noqa: BLE001
            self._warn("read", e)
        return out

    # ── sync_log ────────────────────────────────────────────────────────────
    def sync_start(self, source: str) -> Optional[int]:
        """Record that a pull from `source` (an outside data feed) has started. Returns the log row id to hand to
        sync_finish, or None if logging failed."""
        try:
            c = self._conn()
            cur = c.execute("INSERT INTO sync_log (source, started_at) VALUES (?, ?)", (source, _now()))
            c.commit()
            return cur.lastrowid
        except Exception as e:                       # noqa: BLE001
            self._warn("sync log", e)
            return None

    def sync_finish(self, sync_id: Optional[int], ok: bool, http_status: Optional[int] = None,
                    records: Optional[int] = None, note: Optional[str] = None) -> None:
        """Record how that pull ended (success, HTTP status, record count, short note), then trim the log to the newest
        SYNC_LOG_KEEP rows for that source so it cannot grow without end."""
        if sync_id is None:
            return
        try:
            c = self._conn()
            c.execute("UPDATE sync_log SET finished_at=?, ok=?, http_status=?, records=?, note=? WHERE id=?",
                      (_now(), 1 if ok else 0, http_status, records, (note or "")[:300] or None, sync_id))
            src = c.execute("SELECT source FROM sync_log WHERE id=?", (sync_id,)).fetchone()
            if src:
                c.execute("DELETE FROM sync_log WHERE source=? AND id <= "
                          "(SELECT id FROM sync_log WHERE source=? ORDER BY id DESC LIMIT 1 OFFSET ?)",
                          (src[0], src[0], SYNC_LOG_KEEP))
            c.commit()
        except Exception as e:                       # noqa: BLE001
            self._warn("sync log", e)

    def last_good_sync(self, source: str) -> Optional[datetime]:
        """When `source` last returned usable data, or None."""
        try:
            row = self._conn().execute("SELECT finished_at FROM sync_log WHERE source=? AND ok=1 "
                                       "ORDER BY id DESC LIMIT 1", (source,)).fetchone()
            return datetime.fromisoformat(row[0]) if row and row[0] else None
        except Exception as e:                       # noqa: BLE001
            self._warn("sync log", e)
            return None

    def due(self, source: str, refresh_seconds: float, now: Optional[datetime] = None) -> bool:
        """Pull `source` now? True unless it was refreshed successfully within `refresh_seconds`."""
        last = self.last_good_sync(source)
        if last is None:
            return True
        now = now or datetime.now(timezone.utc)
        return (now - last).total_seconds() >= refresh_seconds

    def recent_syncs(self, limit: int = 50, source: Optional[str] = None) -> List[dict]:
        """The newest sync log entries first (optionally for one source) as dicts for the status page. Returns an empty
        list if the log cannot be read."""
        try:
            q = "SELECT id, source, started_at, finished_at, ok, http_status, records, note FROM sync_log"
            args: tuple = ()
            if source:
                q += " WHERE source=?"
                args = (source,)
            q += " ORDER BY id DESC LIMIT ?"
            rows = self._conn().execute(q, args + (int(limit),)).fetchall()
            keys = ("id", "source", "started_at", "finished_at", "ok", "http_status", "records", "note")
            return [dict(zip(keys, r), ok=bool(r[4])) for r in rows]
        except Exception as e:                       # noqa: BLE001
            self._warn("sync log", e)
            return []

    # ── lineage (bodies built by lineage.py) ────────────────────────────────
    def save_manifest(self, manifest_id: str, body: dict) -> bool:
        """Store a lineage manifest (a record of the AI panel's set-up: which models and config) under its id. INSERT OR
        IGNORE means saving the same id again keeps the first copy. Returns True on success."""
        try:
            c = self._conn()
            c.execute("INSERT OR IGNORE INTO lineage_manifest (manifest_id, created_at, body) VALUES (?,?,?)",
                      (manifest_id, _now(), json.dumps(body, sort_keys=True)))
            c.commit()
            return True
        except Exception as e:                       # noqa: BLE001
            self._warn("lineage", e)
            return False

    def get_manifest(self, manifest_id: str) -> Optional[dict]:
        try:
            row = self._conn().execute("SELECT created_at, body FROM lineage_manifest WHERE manifest_id=?",
                                       (manifest_id,)).fetchone()
            return {"manifest_id": manifest_id, "created_at": row[0], **json.loads(row[1])} if row else None
        except Exception as e:                       # noqa: BLE001
            self._warn("lineage", e)
            return None

    def log_lineage_change(self, old_id: Optional[str], new_id: str, changes: List[str]) -> bool:
        """Record that the panel's set-up changed from manifest `old_id` to `new_id`, with a list of what changed (old_id
        is None for the first one)."""
        try:
            c = self._conn()
            c.execute("INSERT INTO lineage_event (ts, old_id, new_id, changes) VALUES (?,?,?,?)",
                      (_now(), old_id, new_id, json.dumps(changes)))
            c.commit()
            return True
        except Exception as e:                       # noqa: BLE001
            self._warn("lineage", e)
            return False

    def lineage_events(self, limit: int = 50) -> List[dict]:
        try:
            rows = self._conn().execute("SELECT id, ts, old_id, new_id, changes FROM lineage_event "
                                        "ORDER BY id DESC LIMIT ?", (int(limit),)).fetchall()
            return [{"id": r[0], "ts": r[1], "old_id": r[2], "new_id": r[3], "changes": json.loads(r[4])} for r in rows]
        except Exception as e:                       # noqa: BLE001
            self._warn("lineage", e)
            return []

    def current_manifest_id(self) -> Optional[str]:
        ev = self.lineage_events(1)
        return ev[0]["new_id"] if ev else None


_STORE: Optional[StateStore] = None
_STORE_LOCK = threading.Lock()


def store() -> StateStore:
    """The process-wide store at the default path."""
    global _STORE
    if _STORE is None:
        with _STORE_LOCK:
            if _STORE is None:
                _STORE = StateStore()
    return _STORE
