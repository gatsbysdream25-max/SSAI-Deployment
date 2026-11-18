"""The AI providers: one small class per kind of model server (ai_providers.py).

Each class turns a prompt into the model's text answer and says whether it is usable (`available`). Nothing here decides what a
verdict means or who votes: that is ai_swarm_agent.py. Which model each provider uses lives only in config/ai_models.json
(see model_config.py), never in this file.

  _OllamaProvider        a local Ollama server found by looking in the usual places (the first model it has)
  _OllamaModelProvider   one named model on one Ollama server (the "ollama-hermes3" style voices)
  _OpenAICompatProvider  any OpenAI-style cloud API: Groq, OpenRouter, Cerebras, Mistral, Together ...
  _GeminiProvider, _HuggingFaceProvider, _AnthropicProvider   the services that need their own request shape
  _build_provider        picks the right class for one entry of the model config

The class names start with an underscore for historical reasons: other files reach them through ai_swarm_agent.
"""
from __future__ import annotations

import ipaddress
import os
from typing import Optional
from urllib.parse import urlparse

import requests

try:
    from utils.logger import get_logger
    log = get_logger("ai_swarm")
except ImportError:
    import logging as _logging
    log = _logging.getLogger("ai_swarm")

try:
    import model_config
except ImportError:                       # imported as agents.ai_providers by the web app
    from agents import model_config

# How long to wait for one answer. A CPU-only local model can need a minute or more; a cloud API answers in seconds.
_TIMEOUT_LOCAL = 150
_TIMEOUT_CLOUD = 30


def _required_entry(pid: str) -> dict:
    """This provider's entry from the model config. Model names live only in config/ai_models.json (Phase 1): if the
    entry was removed there is nothing to call, so say so instead of quietly inventing a model name in code."""
    entry = model_config.get(pid)
    if entry is None:
        raise RuntimeError(f"provider '{pid}' is not in config/ai_models.json (or instance/ai_models.json); add it or leave it unused")
    return entry


class _OllamaProvider:
    name = "ollama"

    def __init__(self):
        self.base_url = os.environ.get("OLLAMA_URL", "")
        self.model    = model_config.model_of(_required_entry("ollama"))
        self.available = False
        self._discover()

    @staticmethod
    def candidates(base_url, env=None, gateway=None):
        """The addresses to try, in order: OLLAMA_URL, this machine, OLLAMA_HOSTS. The router's address is tried only when
        SSAI_OLLAMA_DISCOVER=1 (audit O-1, 2026-11-18): whatever answers there would become a trusted voter and receive
        local evidence that is not scrubbed the way cloud requests are, so on a shared or guest network anyone who can
        answer at .1 could read it and steer verdicts. Name your model servers in OLLAMA_URL or OLLAMA_HOSTS instead.
        `gateway` is a function returning the guessed router address (tests pass a fake)."""
        env = os.environ if env is None else env
        out = [base_url] if base_url else []
        out.append("http://localhost:11434")
        for h in env.get("OLLAMA_HOSTS", "").split(","):
            h = h.strip()
            if h:
                out.append(h if "://" in h else f"http://{h}:11434")
        if str(env.get("SSAI_OLLAMA_DISCOVER", "")).strip().lower() in ("1", "true", "yes", "on"):
            guess = (gateway or _OllamaProvider._router_guess)()
            if guess:
                out.append(f"http://{guess}:11434")
        seen, ordered = set(), []
        for url in out:
            if url not in seen:
                seen.add(url)
                ordered.append(url)
        return ordered

    @staticmethod
    def _router_guess():
        """This machine's outward address ending in .1 (a convention, not a guarantee), or None."""
        import socket as _sock
        try:
            # Connecting a UDP socket sends no data; it only makes the OS pick the network address this machine would use
            # to reach the internet.
            s = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip.rsplit(".", 1)[0] + ".1"
        except Exception:                                  # noqa: BLE001 -- a guess; no guess is fine
            return None

    def _discover(self):
        """Find a working Ollama server (a program that runs AI models on your own hardware): the first of candidates()
        that answers wins and its first installed model is used; if none answers, available stays False."""
        tried = self.candidates(self.base_url)
        for url in tried:
            try:
                r = requests.get(f"{url}/api/tags", timeout=3)
                if r.ok:
                    models = r.json().get("models", [])
                    if models:
                        self.model = models[0].get("name", self.model).split(":")[0]
                    self.base_url = url
                    self.available = True
                    os.environ["OLLAMA_URL"] = url
                    log.info(f"Ollama discovered: {self.model} @ {url}")
                    return
            except Exception:
                continue
        log.warning(f"Ollama not found — tried: {', '.join(tried)}")

    def analyze(self, prompt: str) -> str:
        """Send the prompt to the local Ollama server and return its text reply. Optional settings (CPU thread cap, JSON
        mode, reasoning off) come from the model config or environment variables."""
        body = {"model": self.model, "prompt": prompt, "stream": False, "keep_alive": model_config.ollama_keep_alive()}
        # Heat cap: fewer CPU threads runs cooler and slower. Per model via "num_thread" in the model config, or for
        # every local call via the OLLAMA_NUM_THREAD environment variable.
        try:
            threads = int(getattr(self, "num_thread", 0) or os.environ.get("OLLAMA_NUM_THREAD", "0") or 0)
        except ValueError:
            threads = 0
        if threads > 0:
            body["options"] = {"num_thread": threads}
        if getattr(self, "json_mode", os.environ.get("OLLAMA_JSON_MODE", "0") == "1"):
            body["format"] = "json"
        # Reasoning models (Qwen3, DeepSeek-R1...) think at length before answering, far past the local timeout on CPU.
        # Per model via "think": false in the model config, or for every local call with OLLAMA_THINK=0.
        think = getattr(self, "think", None)
        if think is None and os.environ.get("OLLAMA_THINK", "") == "0":
            think = False
        if think is False:
            body["think"] = False
        r = requests.post(
            f"{self.base_url}/api/generate",
            json=body,
            timeout=_TIMEOUT_LOCAL,
        )
        r.raise_for_status()
        return r.json().get("response", "")

    def capabilities(self) -> dict:
        return {"provider": "ollama", "model": self.model, "local": True}


class _OllamaModelProvider(_OllamaProvider):
    """One named local model on one Ollama server, e.g. phi4:14b on the Watchtower box. Several of these make a
    majority-local panel. `available` is true only when the server answers AND has the model pulled; otherwise
    `problem` says exactly why (the provider health check prints it)."""

    def __init__(self, name: str, endpoint: str, model: str):
        self.name, self.base_url, self.model = name, endpoint.rstrip("/"), model
        self.available, self.problem = False, ""
        try:
            r = requests.get(f"{self.base_url}/api/tags", timeout=3)
            r.raise_for_status()
            names = [m.get("name", "") for m in r.json().get("models", [])]
            want = model if ":" in model else model + ":latest"
            if want in names or model in names:
                self.available = True
            else:
                self.problem = f"model '{model}' is not installed on {self.base_url} (run: ollama pull {model})"
        except Exception as exc:
            why = "connection refused" if "refused" in str(exc).lower() else ("timed out" if "timed out" in str(exc).lower() else type(exc).__name__)
            self.problem = f"Ollama at {self.base_url} not reachable ({why}): set this provider's \"endpoint\" in instance/ai_models.json"
        if self.available:
            log.info(f"{name} configured: {model} @ {self.base_url}")

    def capabilities(self) -> dict:
        return {"provider": self.name, "model": self.model, "local": True}


class _HuggingFaceProvider:
    name = "huggingface"

    def __init__(self):
        e = _required_entry("huggingface")
        self.token = model_config.key_of(e)
        self.model = model_config.model_of(e)
        self.endpoint = model_config.endpoint_of(e)
        self.available = bool(self.token)
        if self.available:
            log.info(f"HuggingFace configured: {self.model}")

    def analyze(self, prompt: str) -> str:
        """Send the prompt to HuggingFace's chat endpoint and return the reply text."""
        # BUG FIX (2026-09-19): api-inference.huggingface.co no longer resolves (retired), so this
        # provider failed on every call. The Inference Providers router speaks the OpenAI chat format.
        r = requests.post(
            f"{self.endpoint}/chat/completions",
            headers={"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"},
            json={"model": self.model, "messages": [{"role": "user", "content": prompt}],
                  "max_tokens": 600, "temperature": 0.1},
            timeout=_TIMEOUT_CLOUD,
        )
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]

    def capabilities(self) -> dict:
        return {"provider": "huggingface", "model": self.model, "local": False}


class _OpenAICompatProvider:
    """Generic OpenAI-compatible endpoint (Groq, OpenRouter, Cerebras, Mistral, Together, Kimi, Grok)."""

    def __init__(self, name: str, key_env: str, base_url: str, model: str, entry: Optional[dict] = None):
        self.name    = name
        self.api_key = model_config.key_of(entry) if entry else os.environ.get(key_env, "")
        self.base_url = base_url.rstrip("/")
        self.model   = model
        self.available = bool(self.api_key)
        # BUG FIX (2026-09-19): reasoning models (e.g. openai/gpt-oss-*) count their hidden thinking
        # against max_tokens; at 600 they finished with "length" and an empty answer ~60% of the time.
        self.reasoning = "gpt-oss" in model.lower()
        self.max_tokens = 1500 if self.reasoning else 600
        if self.available:
            log.info(f"{name} configured: {model}")

    def analyze(self, prompt: str) -> str:
        """Send the prompt to the OpenAI-style chat endpoint and return the reply text. Reasoning models get a bigger
        reply budget and low reasoning effort."""
        body = {
            "model":       self.model,
            "messages":    [{"role": "user", "content": prompt}],
            "max_tokens":  self.max_tokens,
            "temperature": 0.1,
        }
        if self.reasoning:
            body["reasoning_effort"] = "low"
        r = requests.post(
            f"{self.base_url}/chat/completions",
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
            json=body,
            timeout=_TIMEOUT_CLOUD,
        )
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]

    def capabilities(self) -> dict:
        return {"provider": self.name, "model": self.model, "local": False}


class _AnthropicProvider:
    name = "anthropic"

    def __init__(self):
        e = _required_entry("anthropic")
        self.api_key = model_config.key_of(e)
        self.model   = model_config.model_of(e)
        self.available = bool(self.api_key)
        if self.available:
            log.info(f"Anthropic configured: {self.model}")

    def analyze(self, prompt: str) -> str:
        """Send the prompt to Anthropic's messages API and return the reply text."""
        r = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key":         self.api_key,
                "anthropic-version": "2023-06-01",
                "content-type":      "application/json",
            },
            json={
                "model":     self.model,
                "max_tokens": 600,
                "messages":  [{"role": "user", "content": prompt}],
            },
            timeout=_TIMEOUT_CLOUD,
        )
        r.raise_for_status()
        return r.json()["content"][0]["text"]

    def capabilities(self) -> dict:
        return {"provider": "anthropic", "model": self.model, "local": False}


class _GeminiProvider:
    """Google Gemini via its OpenAI-compatible endpoint (free tier: 1,500 req/day)."""
    name = "gemini"

    def __init__(self):
        # FIX (2026-08-19): "gemini-1.5-flash" is fully shut down (404 on all
        # requests) — every call was silently failing.
        e = _required_entry("gemini")
        self.api_key = model_config.key_of(e)
        self.model   = model_config.model_of(e)
        self.endpoint = model_config.endpoint_of(e)
        self.available = bool(self.api_key)
        if self.available:
            log.info(f"Gemini configured: {self.model}")

    def analyze(self, prompt: str) -> str:
        """Send the prompt to Gemini's OpenAI-style chat endpoint and return the reply text. The large max_tokens leaves
        room for Gemini's hidden thinking."""
        # BUG FIX (2026-09-19): Gemini's hidden thinking counts against max_tokens; at 600 the reply
        # was cut off after ~25 visible tokens (finish_reason=length) and never contained valid JSON.
        body = {
            "model":       self.model,
            "messages":    [{"role": "user", "content": prompt}],
            "max_tokens":  2000,
            "temperature": 0.1,
        }
        if not self.model.startswith(("gemini-1", "gemini-2.0")):   # older models reject reasoning_effort
            body["reasoning_effort"] = "low"
        r = requests.post(
            f"{self.endpoint}/chat/completions",
            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
            json=body,
            timeout=_TIMEOUT_CLOUD,
        )
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]

    def capabilities(self) -> dict:
        return {"provider": "gemini", "model": self.model, "local": False}


def _build_provider(pid: str, e: dict):
    """The provider object for one config entry, or None for an unknown kind. It is returned even when unusable
    (no key, server down) so the health check can say why; callers keep only `.available` ones for the panel."""
    kind = e["kind"]
    if kind == "ollama":
        if pid == "ollama":
            return _OllamaProvider()
        p = _OllamaModelProvider(pid, model_config.endpoint_of(e) or "http://localhost:11434", model_config.model_of(e))
        if e.get("num_thread"):
            p.num_thread = e["num_thread"]
        if e.get("think") is False:
            p.think = False
        return p
    if kind == "huggingface":
        return _HuggingFaceProvider()
    if kind == "gemini":
        return _GeminiProvider()
    if kind == "anthropic":
        return _AnthropicProvider()
    if kind == "openai":
        p = _OpenAICompatProvider(pid, e["key_env"], model_config.endpoint_of(e), model_config.model_of(e), entry=e)
        if e.get("max_tokens"):
            p.max_tokens = e["max_tokens"]
        return p
    return None


# Where an endpoint lives. The cloud rule is that nothing leaves this network except through sanitizer.sanitize_for_cloud(), so
# every caller first asks: is this server on my own network?
_INTERNAL_TLDS = ("local", "lan", "internal", "home", "corp", "localdomain", "intranet", "private")
_LOCAL_NETS = tuple(ipaddress.ip_network(n) for n in (          # this network, and nothing else
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
    "::1/128", "fc00::/7", "fe80::/10"))


def _private_endpoint(url: str) -> bool:
    """True if `url` points at this machine or the local network: loopback / private / link-local IP, localhost,
    a bare name (watchtower) or an internal suffix (box.lan)."""
    host = (urlparse(url or "").hostname or "").lower()
    if not host:
        return False
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return any(ip.version == n.version and ip in n for n in _LOCAL_NETS)
    except ValueError:
        return "." not in host or host.rsplit(".", 1)[-1] in _INTERNAL_TLDS
