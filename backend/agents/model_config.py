"""One file decides which model each AI provider uses (2026-09-23).

Every model choice (provider, model name, endpoint, which environment variable holds the key) lives in
`backend/config/ai_models.json`. Upgrading a model is a one-line edit there, and the provider health check and the
consensus panel both read the same entries.

Layers, later wins:
    1. backend/config/ai_models.json        defaults shipped with the product (in git)
    2. <INSTANCE_DIR>/ai_models.json         this installation's changes: a different model, an Ollama on another
                                             machine, an extra local voice. Never overwritten by an update.
    3. environment variables                 <model_env> / <endpoint_env> named in the entry (GROQ_MODEL, OLLAMA_URL...)
                                             kept so existing .env files keep working.

Keys never live in this file: `key_env` only names the environment variable that holds the key.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Dict, Optional

log = logging.getLogger("ai_swarm")

_HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_PATH = os.path.join(os.path.dirname(_HERE), "config", "ai_models.json")

KINDS = ("openai", "ollama", "anthropic", "gemini", "huggingface")
_STR_FIELDS = ("kind", "model", "endpoint", "key_env", "model_env", "endpoint_env", "tier", "notes",
               "name", "specialty", "focus", "icon", "description", "cost", "rate_limit", "signup_url",
               "reasoning_effort", "key_ref")
_cache: Dict[str, object] = {"stamp": None, "data": {}}


def instance_path() -> str:
    try:
        import ssai_config
        return os.path.join(ssai_config.INSTANCE_DIR, "ai_models.json")
    except ImportError:
        return os.path.join(os.path.dirname(_HERE), "instance", "ai_models.json")


def _read(path: str) -> Dict[str, dict]:
    """Load the 'providers' section of the model config file; a missing or broken file gives {} (and a warning if it is
    broken)."""
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as exc:
        log.warning(f"model config {path} unreadable, ignoring it: {exc}")
        return {}
    providers = doc.get("providers") if isinstance(doc, dict) else None
    if not isinstance(providers, dict):
        log.warning(f"model config {path} has no 'providers' object, ignoring it")
        return {}
    return {str(k): v for k, v in providers.items() if isinstance(v, dict)}


def _clean(pid: str, raw: dict) -> Optional[dict]:
    """Validate one entry; a bad entry is dropped with a warning naming the problem, never silently."""
    e = {k: raw[k] for k in _STR_FIELDS if isinstance(raw.get(k), str) and raw[k].strip()}
    e = {k: v.strip() for k, v in e.items()}
    if e.get("kind") not in KINDS:
        log.warning(f"model config: provider '{pid}' needs kind one of {', '.join(KINDS)} (got {raw.get('kind')!r}); skipped")
        return None
    if not e.get("model"):
        log.warning(f"model config: provider '{pid}' has no model; skipped")
        return None
    if e["kind"] != "ollama" and not e.get("key_env"):
        log.warning(f"model config: provider '{pid}' has no key_env; skipped")
        return None
    for flag in ("verified", "default_on"):
        e[flag] = raw.get(flag) is True          # only a real true: the string "false" is truthy and would put a paid provider in the default panel
    if isinstance(raw.get("max_tokens"), int) and 0 < raw["max_tokens"] <= 32000:
        e["max_tokens"] = raw["max_tokens"]
    if isinstance(raw.get("num_thread"), int) and 0 < raw["num_thread"] <= 64:
        e["num_thread"] = raw["num_thread"]                    # local models: CPU threads (a heat cap)
    for field in ("daily_request_cap",):                       # limits and prices for usage_caps.py; ignored when not a sensible number
        if isinstance(raw.get(field), int) and not isinstance(raw.get(field), bool) and 0 < raw[field] <= 10_000_000:
            e[field] = raw[field]
    for field in ("monthly_spend_cap_usd", "price_in_per_mtok", "price_out_per_mtok"):
        value = raw.get(field)
        if isinstance(value, (int, float)) and not isinstance(value, bool) and 0 <= value <= 1_000_000:
            e[field] = float(value)
    if isinstance(raw.get("allowed_deployments"), list):
        e["allowed_deployments"] = [str(x).strip().lower() for x in raw["allowed_deployments"] if str(x).strip()][:20]
    if raw.get("think") is False:
        e["think"] = False                                     # local reasoning models: skip the long hidden thinking pass
    e["id"] = pid
    e.setdefault("tier", "free")
    return e


def load(default_path: Optional[str] = None, override_path: Optional[str] = None) -> Dict[str, dict]:
    """provider id -> validated entry (defaults overlaid by this installation's overrides), in file order."""
    dp, op = default_path or DEFAULT_PATH, override_path or instance_path()
    stamp = tuple(os.path.getmtime(p) if os.path.exists(p) else None for p in (dp, op))
    using_defaults = default_path is None and override_path is None
    if using_defaults and _cache["stamp"] == stamp:
        return _cache["data"]  # type: ignore[return-value]
    merged: Dict[str, dict] = {k: dict(v) for k, v in _read(dp).items()}
    for pid, over in _read(op).items():
        if over.get("remove") is True:
            merged.pop(pid, None)
        else:
            merged[pid] = {**merged.get(pid, {}), **over}
    out: Dict[str, dict] = {}
    for pid, raw in merged.items():
        e = _clean(pid, raw)
        if e:
            out[pid] = e
    if using_defaults:
        _cache.update(stamp=stamp, data=out)
    return out


def get(pid: str) -> Optional[dict]:
    return load().get(pid)


def model_of(entry: dict) -> str:
    """The model to call: the entry's model_env variable if set, else the configured model."""
    env = entry.get("model_env")
    return (os.environ.get(env, "").strip() if env else "") or entry["model"]


def endpoint_of(entry: dict) -> str:
    env = entry.get("endpoint_env")
    return ((os.environ.get(env, "").strip() if env else "") or entry.get("endpoint") or "").rstrip("/")


def key_of(entry: dict) -> str:
    """The API key: the environment variable named by key_env (existing .env files keep working), else the OS key vault item named
    by key_ref (keyvault.py). Empty when neither has one."""
    env = entry.get("key_env")
    key = os.environ.get(env, "").strip() if env else ""
    if key or not entry.get("key_ref"):
        return key
    try:
        import keyvault
    except ImportError:                       # imported as agents.model_config by the web app
        from agents import keyvault
    return keyvault.get(entry["key_ref"])
