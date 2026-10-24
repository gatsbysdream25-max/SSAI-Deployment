"""Third-party AI provider approvals (2026-10-09). See docs/third-party-ai/README.md for the framework.

    load()                      -> {provider_id: entry}   shipped config/provider_approvals.json + instance overrides
    base_id("groq-llama-3")     -> "groq"                  extra models of a provider share its approval
    status("groq")              -> "approved" | "pending" | "rejected" | "unlisted"
    enforced()                  -> SSAI_REQUIRE_PROVIDER_APPROVAL is on
    cloud_allowed("groq")       -> may a CLOUD provider sit on the panel right now?
    problems(entry)             -> why an entry marked approved is not really complete ([] if fine)

Local models need no approval and never reach this check (ai_swarm_agent decides what is local).
"""
from __future__ import annotations

import json
import os
from typing import Dict, List, Optional

_HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_PATH = os.path.join(os.path.dirname(_HERE), "config", "provider_approvals.json")
STATUSES = ("approved", "pending", "rejected")
_cache: Dict[str, object] = {"key": None, "data": {}}


def instance_path() -> str:
    try:
        import ssai_config
        return os.path.join(ssai_config.INSTANCE_DIR, "provider_approvals.json")
    except ImportError:
        return os.path.join(os.path.dirname(_HERE), "instance", "provider_approvals.json")


def _read(path: str) -> dict:
    try:
        with open(path) as f:
            doc = json.load(f)
        return doc if isinstance(doc, dict) else {}
    except (OSError, ValueError):
        return {}


def _mtime(path: str) -> Optional[float]:
    try:
        return os.path.getmtime(path)
    except OSError:
        return None


def checklist_items(default_path: Optional[str] = None) -> Dict[str, str]:
    return dict(_read(default_path or DEFAULT_PATH).get("checklist_items") or {})


def load(default_path: Optional[str] = None, override_path: Optional[str] = None) -> Dict[str, dict]:
    """Shipped entries, with this installation's overrides merged in field by field (checklist item by item)."""
    dp, op = default_path or DEFAULT_PATH, override_path or instance_path()
    key = (dp, op, _mtime(dp), _mtime(op))
    if _cache["key"] == key:
        return _cache["data"]  # type: ignore[return-value]
    out: Dict[str, dict] = {}
    for pid, e in (_read(dp).get("providers") or {}).items():
        if isinstance(e, dict):
            out[pid] = dict(e, checklist=dict(e.get("checklist") or {}))
    for pid, e in (_read(op).get("providers") or {}).items():
        if not isinstance(e, dict):
            continue
        cur = out.setdefault(pid, {"checklist": {}})
        for k, v in e.items():
            if k == "checklist" and isinstance(v, dict):
                cur["checklist"].update(v)
            else:
                cur[k] = v
    _cache.update(key=key, data=out)
    return out


def base_id(pid: str, entries: Optional[Dict[str, dict]] = None) -> str:
    """Approval id for a panel member: exact match, else the part before the first '-' (groq-<model> -> groq)."""
    entries = load() if entries is None else entries
    if pid in entries:
        return pid
    head = (pid or "").split("-", 1)[0]
    return head if head in entries else pid


def status(pid: str, entries: Optional[Dict[str, dict]] = None) -> str:
    """Say where an AI provider stands: 'unlisted' if unknown, otherwise its status (pending, approved ...). An approval
    with missing items counts as pending."""
    entries = load() if entries is None else entries
    e = entries.get(base_id(pid, entries))
    if not e:
        return "unlisted"
    s = str(e.get("status", "pending")).strip().lower()
    if s == "approved" and problems(e):
        return "pending"                     # an incomplete 'approved' never counts as approved
    return s if s in STATUSES else "pending"


def problems(entry: dict, items: Optional[Dict[str, str]] = None) -> List[str]:
    """For an entry marked approved: what is missing. [] when complete (or when not marked approved)."""
    if str(entry.get("status", "")).strip().lower() != "approved":
        return []
    items = items if items is not None else checklist_items()
    out = []
    cl = entry.get("checklist") or {}
    for k in items:
        if cl.get(k) is not True:
            out.append(f"checklist item not confirmed: {k}")
    if not entry.get("reviewed"):
        out.append("no review date")
    if not entry.get("reviewer"):
        out.append("no reviewer named")
    return out


def enforced() -> bool:
    return os.environ.get("SSAI_REQUIRE_PROVIDER_APPROVAL", "0").strip().lower() in ("1", "true", "yes", "on")


def cloud_allowed(pid: str, entries: Optional[Dict[str, dict]] = None) -> bool:
    """A cloud provider may vote unless enforcement is on and it is not approved. Rejected is always out."""
    st = status(pid, entries)
    if st == "rejected":
        return False
    return st == "approved" or not enforced()


def summary(entries: Optional[Dict[str, dict]] = None) -> List[dict]:
    """For the status API / dashboard: one row per provider."""
    entries = load() if entries is None else entries
    items = checklist_items()
    rows = []
    for pid, e in sorted(entries.items()):
        cl = e.get("checklist") or {}
        rows.append({"id": pid, "name": e.get("name", pid), "kind": e.get("kind"), "status": status(pid, entries),
                     "reviewed": e.get("reviewed"), "record": e.get("record"),
                     "checklist_done": sum(1 for k in items if cl.get(k) is True), "checklist_total": len(items)})
    return rows
