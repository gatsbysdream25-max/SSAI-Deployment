"""Model and data lineage for AI verdicts (2026-10-09, "Third-Party AI Shared Responsibility Plan").

Question this answers: a verdict was wrong -- which model, from which provider, under which configuration made it, and
did anything change just before? If a provider swapped the model behind a name, or someone edited the weights, the
record has to show it, so blame can be traced to SSAI's code or to the provider's update with evidence.

  manifest   one snapshot of the AI panel: every member's provider id, model, kind, local/cloud, endpoint host and vote
             weight, the hashes of the config files that shape it, the code version, and a COPY of this installation's
             own override files (for rollback). Its id is a hash of that content: same panel, same id.
  event      written whenever the manifest id changes: old id, new id, and a readable list of what changed.
  stamp      added to every consensus verdict: the manifest id, the exact model each answering provider used, and the
             state of the local threat-intel data at that moment.

Stored in the per-machine state store (state_store.py), written automatically by SwarmConsensusAgent every cycle; no
manual logging. Roll back with backend/tools/lineage_cli.py.
"""
from __future__ import annotations

import hashlib
import json
import os
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

try:
    import model_config
except ImportError:                       # imported as agents.lineage by the web app
    from agents import model_config

# Installation override files whose contents are snapshotted for rollback (no secrets live in these: keys are in .env).
SNAPSHOT_FILES = ("ai_models.json", "ai_weights.json", "ai_providers.json")


def _instance_dir() -> str:
    try:
        import ssai_config
        return ssai_config.INSTANCE_DIR
    except ImportError:
        return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "instance")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def _file_hash(path: str) -> Optional[str]:
    try:
        with open(path, "rb") as f:
            return _sha(f.read())
    except OSError:
        return None


def _read_text(path: str) -> Optional[str]:
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except OSError:
        return None


def code_version() -> str:
    """SSAI_VERSION if set (Docker builds), else the git commit of the checkout, else the VERSION file of a release
    package, else 'unknown'."""
    v = os.environ.get("SSAI_VERSION", "").strip()
    if v:
        return v[:40]
    here = os.path.dirname(os.path.abspath(__file__))
    for root in (os.path.dirname(os.path.dirname(here)), os.environ.get("DATA_DIR", "")):
        head = os.path.join(root, ".git", "HEAD") if root else ""
        txt = _read_text(head) if head else None
        if not txt:
            continue
        txt = txt.strip()
        if txt.startswith("ref:"):
            ref = txt.split(None, 1)[1]
            sha = _read_text(os.path.join(root, ".git", ref))
            if sha:
                return sha.strip()[:12]
            packed = _read_text(os.path.join(root, ".git", "packed-refs")) or ""
            for line in packed.splitlines():
                if line.endswith(" " + ref):
                    return line.split()[0][:12]
        else:
            return txt[:12]
    for root in (os.path.dirname(os.path.dirname(here)), os.environ.get("DATA_DIR", "")):
        txt = _read_text(os.path.join(root, "VERSION")) if root else None   # a release package (deploy/make-release.sh)
        if txt and txt.strip():
            return txt.strip().splitlines()[0][:40]
    return "unknown"


def _member(p, weights: dict) -> dict:
    """Describe one panel member (name, model, kind, local or cloud, host, vote weight) for the manifest, without ever
    recording its API key."""
    caps = {}
    try:
        caps = p.capabilities() or {}
    except Exception:                                    # noqa: BLE001 -- a provider must not break the manifest
        pass
    url = getattr(p, "base_url", "") or getattr(p, "endpoint", "") or ""
    host = urlparse(url).hostname if "://" in str(url) else None
    return {
        "provider": p.name,
        "model": caps.get("model") or getattr(p, "model", None),
        "kind": type(p).__name__.lstrip("_").replace("Provider", "").lower(),
        "local": bool(caps.get("local")),
        "endpoint_host": host,
        "weight": weights.get(p.name, 1.0),
    }


def build_manifest(analyzer, *, instance_dir: Optional[str] = None) -> dict:
    """The manifest for the analyzer's current panel (members that are configured, switched on and approved)."""
    try:
        import ai_swarm_agent as asa
    except ImportError:
        from agents import ai_swarm_agent as asa
    idir = instance_dir or _instance_dir()
    weights = asa.load_weights()
    panel = [p for p in getattr(analyzer, "_providers", []) if asa.panel_allowed(p)]
    members = sorted((_member(p, weights) for p in panel), key=lambda m: m["provider"])
    config = {"default_models": _file_hash(model_config.DEFAULT_PATH)}
    snapshot = {}
    for name in SNAPSHOT_FILES:
        path = os.path.join(idir, name)
        config["instance/" + name] = _file_hash(path)
        txt = _read_text(path)
        if txt is not None:
            snapshot[name] = txt
    return {"members": members, "config": config, "code_version": code_version(), "snapshot": snapshot}


def manifest_id(manifest: dict) -> str:
    """Content hash. The snapshot is covered through the config hashes, so it is left out of the id itself."""
    core = {k: v for k, v in manifest.items() if k != "snapshot"}
    return _sha(json.dumps(core, sort_keys=True, default=str).encode())[:12]


def diff(old: Optional[dict], new: dict) -> List[str]:
    """Readable changes between two manifests."""
    if not old:
        return ["first manifest recorded"]
    out: List[str] = []
    om = {m["provider"]: m for m in old.get("members", [])}
    nm = {m["provider"]: m for m in new.get("members", [])}
    for pid in sorted(set(om) - set(nm)):
        out.append(f"provider removed from panel: {pid} ({om[pid].get('model')})")
    for pid in sorted(set(nm) - set(om)):
        out.append(f"provider added to panel: {pid} ({nm[pid].get('model')})")
    for pid in sorted(set(om) & set(nm)):
        for field in ("model", "endpoint_host", "weight", "local"):
            if om[pid].get(field) != nm[pid].get(field):
                out.append(f"{pid} {field}: {om[pid].get(field)} -> {nm[pid].get(field)}")
    for k in sorted(set(old.get("config", {})) | set(new.get("config", {}))):
        if old.get("config", {}).get(k) != new.get("config", {}).get(k):
            out.append(f"config file changed: {k}")
    if old.get("code_version") != new.get("code_version"):
        out.append(f"code version: {old.get('code_version')} -> {new.get('code_version')}")
    return out or ["no material change"]


class Tracker:
    """Keeps the current manifest id; records a manifest + change event whenever it moves."""

    def __init__(self, store):
        self.store = store
        self.current_id: Optional[str] = store.current_manifest_id()
        self.current: Optional[dict] = store.get_manifest(self.current_id) if self.current_id else None

    def refresh(self, analyzer) -> Tuple[str, List[str]]:
        """Recompute; returns (manifest_id, changes) where changes is [] if nothing moved."""
        m = build_manifest(analyzer)
        mid = manifest_id(m)
        if mid == self.current_id:
            return mid, []
        changes = diff(self.current, m)
        self.store.save_manifest(mid, m)
        self.store.log_lineage_change(self.current_id, mid, changes)
        self.current_id, self.current = mid, m
        return mid, changes

    def stamp(self, consensus: dict, intel_state: Optional[dict] = None) -> dict:
        """Add the lineage block to a consensus verdict (in place; also returned)."""
        if not isinstance(consensus, dict):
            return consensus
        members = {m["provider"]: m.get("model") for m in (self.current or {}).get("members", [])}
        models: Dict[str, Optional[str]] = dict(consensus.get("models") or {})
        for src in consensus.get("ai_sources") or []:
            models.setdefault(src, members.get(src))
        consensus["lineage"] = {"manifest": self.current_id, "models": models,
                                "code_version": (self.current or {}).get("code_version")}
        if intel_state:
            consensus["lineage"]["intel"] = intel_state
        return consensus
