"""Reading a screenshot with a local vision model (screenshot_ai.py).

A screenshot is never sent to a cloud AI: an image cannot be redacted the way text can, so the only safe reader is a vision-capable
model on THIS network. vision_model() finds that reader; analyze_screenshot_image() asks it for a threat draft; the route turns an
answer of None into a clear "AI could not draft this" message.
"""
from __future__ import annotations

import base64
import json
import os

import requests

try:
    from utils.logger import get_logger
    log = get_logger("ai_swarm")
except ImportError:
    import logging as _logging
    log = _logging.getLogger("ai_swarm")

try:
    import model_config
    from ai_providers import _TIMEOUT_LOCAL, _private_endpoint
except ImportError:                       # imported as agents.screenshot_ai by the web app
    from agents import model_config
    from agents.ai_providers import _TIMEOUT_LOCAL, _private_endpoint

_VISION_PROMPT = """You are a security analyst reviewing a screenshot an admin \
captured because they believe it shows a security-relevant issue (malware alert, \
phishing email, suspicious process, unexpected error/popup, unauthorized access, etc).

Respond with ONLY a JSON object:
{
  "threat_type": "<short-kebab-case type, e.g. phishing-email, malware-alert, suspicious-process, unauthorized-access, other>",
  "severity": "low" | "medium" | "high" | "critical",
  "description": "<one or two sentences: what the screenshot shows and why it matters>",
  "confidence": <0-100 integer: how confident this is a genuine finding, not a false positive>
}
"""


def _extract_json_object(text: str):
    start, end = text.find("{"), text.rfind("}") + 1
    if start < 0 or end <= start:
        return None
    try:
        return json.loads(text[start:end])
    except Exception:
        return None


def vision_model():
    """Where screenshots are read: (provider id, endpoint, model, "") or (None, None, None, why not).

    A screenshot is never sent to a cloud AI (audit F-01, 2026-10-20). An image cannot be redacted the way text can, so the only
    safe reader is a vision-capable model on THIS network: an Ollama server at a private address. SSAI_VISION_PROVIDER names
    which configured Ollama model reads images (default ollama-gemma4); SSAI_VISION_MODEL overrides the model name."""
    pid = os.environ.get("SSAI_VISION_PROVIDER", "ollama-gemma4").strip() or "ollama-gemma4"
    entry = model_config.get(pid)
    if not entry or entry.get("kind") != "ollama":
        return None, None, None, f"{pid} is not a local Ollama model in the model config (set SSAI_VISION_PROVIDER)"
    endpoint = model_config.endpoint_of(entry)
    if not _private_endpoint(endpoint):
        return None, None, None, f"{pid} is not on this network, so screenshots are not sent to it"
    return pid, endpoint, os.environ.get("SSAI_VISION_MODEL", "").strip() or model_config.model_of(entry), ""


def screenshot_unavailable_reason() -> str:
    """Why screenshots cannot be read right now ('' when a local reader is configured). For the route's error message."""
    return vision_model()[3]


def analyze_screenshot_image(image_bytes: bytes, mime_type: str = "image/png"):
    """Read a screenshot with a local vision model and draft a threat from it. Returns a dict (threat_type, severity,
    description, confidence, source) or None when no local reader is configured, it is unreachable, or its answer is not a usable
    JSON object. The caller must treat None as "AI could not draft this" and say so, never drop the submission silently.

    The image goes to one place only: the Ollama server named by vision_model(), over the local network. Nothing is sent to
    any cloud provider, so there is no key, no approval gate and no sanitizer to get around."""
    pid, endpoint, model, why = vision_model()
    if pid is None:
        log.info(f"Screenshot analysis skipped: {why}")
        return None
    if os.environ.get("SSAI_CLOUD_VISION", "").strip().lower() in ("1", "true", "yes", "on"):
        log.warning("SSAI_CLOUD_VISION is no longer used: screenshots are read by a local model and never leave this network")
    try:
        import hashlib
        log.info("Screenshot read by %s (%d bytes, sha256 %s)", pid, len(image_bytes), hashlib.sha256(image_bytes).hexdigest()[:12])
        r = requests.post(
            f"{endpoint}/api/generate",
            json={"model": model, "prompt": _VISION_PROMPT, "images": [base64.b64encode(image_bytes).decode()],
                  "stream": False, "format": "json"},
            timeout=_TIMEOUT_LOCAL,
        )
        r.raise_for_status()
        verdict = _extract_json_object(r.json().get("response", ""))
        if verdict:
            verdict["source"] = pid
            return verdict
        log.warning(f"Screenshot analysis via {pid}: the answer was not a usable JSON object")
    except Exception as e:                                   # noqa: BLE001 -- the route turns None into a clear 503
        log.warning(f"Screenshot analysis via {pid} failed: {type(e).__name__}: {e}")
    return None
