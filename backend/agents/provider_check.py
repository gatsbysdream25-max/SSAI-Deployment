#!/usr/bin/env python3
"""Provider health check: ping every configured AI provider once and name what is wrong (2026-09-23).

A provider that quietly stops answering (no credits, expired key, retired model, rate limit) used to just shrink the
consensus panel with nothing on screen. This turns each of those into a named failure.

  * Runs in the background when the AI panel starts (see AiSwarmAnalyzer.reload) and logs the table.
  * Run it by hand:      swarmsentinel-env/bin/python3 backend/agents/provider_check.py [--json]
  * Last result:         backend/instance/provider_check.json  and  GET /api/ai/health

What is pinged is read from the same model config (backend/config/ai_models.json) the consensus uses. A cloud
provider gets one tiny real request (the whole path: key, credits, model name), costing a few tokens. A local Ollama
model is checked without loading it: the server must answer and the model must be pulled.
"""
from __future__ import annotations

import concurrent.futures
import json
import os
import sys
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional

import requests

_HERE = os.path.dirname(os.path.abspath(__file__))
if __name__ == "__main__":
    sys.path[:0] = [_HERE, os.path.dirname(_HERE)]

# Use the copy of the swarm module that is already loaded (the web app imports it as agents.ai_swarm_agent, the agent
# runner as ai_swarm_agent): a second copy would have its own registry and health state.
swarm = sys.modules.get("ai_swarm_agent") or sys.modules.get("agents.ai_swarm_agent")
if swarm is None:
    try:
        import ai_swarm_agent as swarm  # noqa: E402
    except ImportError:
        from agents import ai_swarm_agent as swarm  # noqa: E402
model_config = swarm.model_config
provider_errors = swarm.provider_errors

PROBE_PROMPT = "Reply with the single word OK."
OVERALL_TIMEOUT = 45

# status values, in the words an operator would use (defined once in provider_errors.py, shared with the live panel)
OK, NO_KEY = provider_errors.OK, provider_errors.NO_KEY
NO_CREDITS, BAD_KEY, BAD_MODEL, RATE_LIMITED = (provider_errors.NO_CREDITS, provider_errors.BAD_KEY,
                                                provider_errors.BAD_MODEL, provider_errors.RATE_LIMITED)
TIMEOUT, UNREACHABLE, PROVIDER_ERROR, ERROR = (provider_errors.TIMEOUT, provider_errors.UNREACHABLE,
                                               provider_errors.PROVIDER_ERROR, provider_errors.ERROR)
QUOTA_USED = provider_errors.QUOTA_USED
_REACHED = {OK, NO_CREDITS, BAD_KEY, BAD_MODEL, RATE_LIMITED, QUOTA_USED, PROVIDER_ERROR}    # the server answered something

_HINT = {
    NO_CREDITS: "out of credits: resting (not voting) until it answers again; top up the API account (a chat subscription does not fund the API)",
    QUOTA_USED: "free quota used up: resting (not voting) and checked again later; it returns by itself when the quota resets",
    BAD_KEY: "key rejected: it is wrong, expired or revoked: make a new key and save it in Setup",
    BAD_MODEL: "model name not accepted: it was probably retired: edit \"model\" for this provider in config/ai_models.json",
    RATE_LIMITED: "rate limit or free quota used up: wait, lower the request rate, or use another provider",
    TIMEOUT: "no answer in time",
    UNREACHABLE: "could not connect: server down, wrong endpoint, or no network",
}


classify = provider_errors.classify


def _row(pid: str, e: dict, **kw) -> dict:
    base = {"provider": pid, "model": model_config.model_of(e), "kind": e["kind"], "tier": e.get("tier"),
            "in_panel": swarm.provider_enabled(pid), "status": ERROR, "reachable": None, "detail": "",
            "latency_ms": None, "checked": datetime.now(timezone.utc).isoformat()}
    base.update(kw)
    base["reachable"] = None if base["status"] == NO_KEY else base["status"] in _REACHED
    base["working"] = base["status"] == OK
    return base


def check_provider(pid: str, e: dict) -> dict:
    """Ping one configured provider once and return its row."""
    try:
        p = swarm._build_provider(pid, e)
    except Exception as exc:                                       # a broken provider must not stop the others
        return _row(pid, e, status=ERROR, detail=f"could not start: {exc}")
    if p is None:
        return _row(pid, e, status=ERROR, detail=f"unknown kind {e['kind']!r}")
    if e["kind"] == "ollama":
        if getattr(p, "available", False):
            return _row(pid, e, status=OK, detail=f"server answers, model pulled ({getattr(p, 'base_url', '')}); not test-generated, to spare the CPU")
        problem = getattr(p, "problem", "") or "no Ollama server found"
        missing = "not installed" in problem
        return _row(pid, e, status=(BAD_MODEL if missing else UNREACHABLE), detail=problem,
                    hint=("pull the model on that machine, then it will show as working" if missing else _HINT[UNREACHABLE]))
    if not p.available:
        return _row(pid, e, status=NO_KEY, detail=f"not configured: set {e.get('key_env')}")
    t0 = time.time()
    try:
        text = p.analyze(PROBE_PROMPT)
    except Exception as exc:                                       # noqa: BLE001 -- classified below
        status, detail = classify(exc)
        return _row(pid, e, status=status, detail=detail, latency_ms=int((time.time() - t0) * 1000), hint=_HINT.get(status, ""))
    ms = int((time.time() - t0) * 1000)
    if not (text or "").strip():
        return _row(pid, e, status=PROVIDER_ERROR, detail="answered with an empty reply", latency_ms=ms)
    return _row(pid, e, status=OK, detail="answers", latency_ms=ms)


def check_all(only: Optional[List[str]] = None, timeout: float = OVERALL_TIMEOUT) -> List[dict]:
    """One row per provider in the model config (all in parallel; one that hangs cannot hold up the rest)."""
    cfg = model_config.load()
    ids = [i for i in cfg if not only or i in only]
    rows: Dict[str, dict] = {}
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(len(ids), 12)))
    futs = {ex.submit(check_provider, i, cfg[i]): i for i in ids}
    try:
        for f in concurrent.futures.as_completed(futs, timeout=timeout):
            rows[futs[f]] = f.result()
    except concurrent.futures.TimeoutError:
        pass
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    for i in ids:
        if i not in rows:
            rows[i] = _row(i, cfg[i], status=TIMEOUT, detail=f"no answer within {int(timeout)}s")
    for r in rows.values():
        r.setdefault("hint", _HINT.get(r["status"], ""))
    return [rows[i] for i in ids]


def format_table(rows: List[dict]) -> str:
    """Lay the provider check results out as a plain-text table with aligned columns, for printing in a terminal."""
    def yn(v):
        return "-" if v is None else ("yes" if v else "NO")
    head = ("PROVIDER", "MODEL", "IN PANEL", "REACHABLE", "WORKING", "DETAIL")
    body = [(r["provider"], r["model"], "yes" if r["in_panel"] else "off", yn(r["reachable"]), yn(r["working"]),
             r["detail"] + (f"  [{r['hint']}]" if r.get("hint") and not r["working"] and r["status"] != NO_KEY else ""))
            for r in rows]
    widths = [max(len(str(x[i])) for x in [head] + body) for i in range(5)]
    line = lambda x: "  ".join(str(x[i]).ljust(widths[i]) for i in range(5)) + "  " + str(x[5])
    return "\n".join([line(head), line(["-" * w for w in widths] + ["-" * 6])] + [line(b) for b in body])


def state_path() -> str:
    return os.path.join(os.path.dirname(model_config.instance_path()), "provider_check.json")


def save(rows: List[dict]) -> None:
    path = state_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"checked": datetime.now(timezone.utc).isoformat(), "providers": rows}, f, indent=1)
    os.replace(tmp, path)


def load_last() -> dict:
    try:
        with open(state_path(), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {"checked": None, "providers": []}


def summary(rows: List[dict]) -> dict:
    """Counts an operator (and the quorum report) can use: how many providers are configured, in the panel, working."""
    configured = [r for r in rows if r["status"] != NO_KEY]
    panel = [r for r in configured if r["in_panel"]]
    return {"configured": len(configured), "in_panel": len(panel), "in_panel_working": sum(1 for r in panel if r["working"]),
            "not_working": [r["provider"] for r in panel if not r["working"]]}


def run(analyzer=None, log=None) -> List[dict]:
    """Check everything, save the result, log the table, and feed the analyzer's live health record so the dashboard
    shows a named error at once instead of waiting for the first failed analysis."""
    rows = check_all()
    try:
        save(rows)
    except OSError as exc:
        (log or swarm.log).warning(f"provider check result not saved: {exc}")
    lg = log or swarm.log
    lg.info("AI provider health check:\n" + format_table(rows))
    s = summary(rows)
    if s["not_working"]:
        lg.warning(f"AI panel: {s['in_panel_working']} of {s['in_panel']} provider(s) in the panel are working; NOT working: {', '.join(s['not_working'])}")
    if analyzer is not None:
        for r in rows:
            if r["status"] in (NO_KEY,) or not r["in_panel"]:
                continue
            if r["working"]:
                analyzer._record_success(r["provider"])
            else:
                analyzer._record_error(r["provider"], f"{r['status']}: {r['detail']}", r["status"])
    return rows


if __name__ == "__main__":
    try:                                                            # load the same .env the service uses
        for ln in open(swarm._find_env_path(), encoding="utf-8"):
            ln = ln.strip()
            if ln and not ln.startswith("#") and "=" in ln:
                k, v = ln.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
    except OSError:
        pass
    rows = check_all()
    try:
        save(rows)
    except OSError:
        pass
    print(json.dumps({"checked": datetime.now(timezone.utc).isoformat(), "providers": rows}, indent=1) if "--json" in sys.argv
          else format_table(rows))
    bad = summary(rows)["not_working"]
    sys.exit(1 if bad else 0)
