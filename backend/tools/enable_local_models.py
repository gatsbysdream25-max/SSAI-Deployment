#!/usr/bin/env python3
"""Put every AI model installed on THIS machine's Ollama onto the panel.

    python3 backend/tools/enable_local_models.py                 # asks http://127.0.0.1:11434
    python3 backend/tools/enable_local_models.py --dry-run
    python3 backend/tools/enable_local_models.py --local-only    # also switch every cloud voice OFF (a box with no internet)

A fresh install keeps every local model off the panel until someone has measured it (see docs/consensus-operating-guide.md), so a
stand-alone machine with models installed would still be judged by the stand-in panel. deploy/local-ai.sh runs this once after it
installs the models. It only switches ON models that are installed here and already described in config/ai_models.json; it never
adds a cloud provider, never switches anything off, and can be undone from the dashboard's panel switches.
"""
import argparse
import json
import os
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, os.path.join(HERE, "..", "agents"))


def installed_models(base):
    """Names Ollama reports, without the ':latest' suffix ('hermes3:latest' -> 'hermes3'). Empty if it cannot be reached."""
    try:
        with urllib.request.urlopen(base.rstrip("/") + "/api/tags", timeout=5) as r:
            names = [m["name"] for m in json.load(r).get("models", [])]
    except (OSError, ValueError, KeyError):
        return set()
    return {n[:-len(":latest")] if n.endswith(":latest") else n for n in names}


def main(argv=None):
    """Command-line entry point: find which models Ollama has installed here and switch on the matching panel members
    (optionally switch cloud ones off)."""
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--url", default="http://127.0.0.1:11434", help="the Ollama server on this machine")
    ap.add_argument("--local-only", action="store_true", help="also switch every non-local provider off, so no cloud call is even tried")
    ap.add_argument("--dry-run", action="store_true", help="say what would be switched on and change nothing")
    args = ap.parse_args(argv)

    have = installed_models(args.url)
    if not have:
        print(f"no models found at {args.url} (is the ssai-ollama service running?)")
        return 1
    import model_config
    from agents import ai_swarm_agent                # imported late: it reads the instance folder when loaded
    chosen, silenced = [], []
    for pid, entry in sorted(model_config.load().items()):
        if entry.get("kind") == "ollama" and model_config.model_of(entry) in have:
            chosen.append(pid)
            if not args.dry_run:
                ai_swarm_agent.set_provider_enabled(pid, True)
        elif args.local_only and entry.get("kind") != "ollama":
            silenced.append(pid)
            if not args.dry_run:
                ai_swarm_agent.set_provider_enabled(pid, False)
    verb = "would switch on" if args.dry_run else "switched on"
    print(f"models installed here: {', '.join(sorted(have))}")
    print(f"{verb}: {', '.join(chosen) if chosen else 'nothing (none of them is described in config/ai_models.json)'}")
    if silenced:
        print(f"{'would switch' if args.dry_run else 'switched'} off (cloud): {', '.join(silenced)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
