#!/usr/bin/env python3
"""Benchmark the local AI models THIS machine can run and switch on the best ones for its panel.

    python3 backend/tools/autotune_local_models.py                  # plan only: hardware, which models fit, what would run
    python3 backend/tools/autotune_local_models.py --run            # benchmark each fitting model, pick, show the choice
    python3 backend/tools/autotune_local_models.py --run --apply    # ...and switch the chosen models on (the rest of the local models off)

Every machine gets its own choice: a laptop with an 8 GB graphics card and a mini-PC with 16 GB of memory and no GPU will not
pick the same models. The measuring is done by tools/ai_benchmark.py (same prompt, same consensus code as production); this
script only decides what to measure, one model per process, and what to turn on afterwards.

  Crash safety   Each model is benchmarked in its own process and its report is kept in the work folder. If the machine
                 restarts, run the same command again: models that already have a report are not measured twice.
  Heat           Nothing starts while the GPU is above --max-temp, and models take turns (never two in memory at once).
  Choice         A model is chosen only if the measured run is large enough to trust (>= 40 indicators per class, see
                 ai_benchmark.MIN_PER_CLASS_FOR_ADOPTION), it beats chance, and its false-positive rate is under --max-fpr.
                 Best first, at most --max-models. --apply never adds a cloud provider and never changes cloud switches.
  Record         The result is written to instance/local_selection.json (with the hardware it was measured on).
"""
import argparse
import datetime
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
sys.path[:0] = [os.path.join(BACKEND, "agents"), BACKEND]

BENCH = os.path.join(HERE, "ai_benchmark.py")
MIN_PER_CLASS = 40
# Download size in GB of what Ollama pulls for each local model described in config/ai_models.json. A model not listed here
# is assumed to be 8 GB, so an unknown model is treated carefully rather than trusted to fit.
SIZE_GB = {"hermes3": 4.7, "mistral": 4.4, "phi4:14b": 9.0, "gemma4:12b": 7.6, "llama3": 4.7}
DEFAULT_SIZE_GB = 8.0


def ram_gb():
    """Total memory in GB (Windows, Linux, macOS), or 0 if it cannot be read."""
    try:
        with open("/proc/meminfo") as f:
            return int(re.search(r"MemTotal:\s+(\d+)", f.read()).group(1)) / 1024 / 1024
    except (OSError, AttributeError):
        pass
    try:
        import ctypes

        class Mem(ctypes.Structure):
            _fields_ = [("len", ctypes.c_ulong), ("load", ctypes.c_ulong), ("total", ctypes.c_ulonglong)] + \
                       [(n, ctypes.c_ulonglong) for n in ("avail", "ptotal", "pavail", "vtotal", "vavail", "ext")]
        m = Mem()
        m.len = ctypes.sizeof(Mem)
        ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m))
        return m.total / 1024 ** 3
    except (AttributeError, OSError):
        return 0.0


def gpu_info():
    """{'name', 'vram_gb', 'temp_c'} of the first NVIDIA GPU, or None when there is none (or no driver)."""
    try:
        out = subprocess.run(["nvidia-smi", "--query-gpu=name,memory.total,temperature.gpu", "--format=csv,noheader,nounits"],
                             capture_output=True, text=True, timeout=10, check=True).stdout.splitlines()[0]
        name, mem, temp = [x.strip() for x in out.split(",")]
        return {"name": name, "vram_gb": float(mem) / 1024, "temp_c": float(temp)}
    except (OSError, subprocess.SubprocessError, IndexError, ValueError):
        return None


def probe_hardware():
    """What this machine has: memory, CPU threads and GPU."""
    return {"host": os.environ.get("COMPUTERNAME") or (os.uname().nodename if hasattr(os, "uname") else "?"),
            "ram_gb": round(ram_gb(), 1), "cpus": os.cpu_count() or 1, "gpu": gpu_info()}


def fit(model, hw):
    """'gpu' if the model fits in graphics memory with room for its working space, 'cpu' if it fits in system memory
    (slow, and runs hot), else None."""
    size = SIZE_GB.get(model, DEFAULT_SIZE_GB)
    gpu = hw.get("gpu")
    if gpu and gpu["vram_gb"] >= size * 1.25:
        return "gpu"
    if hw.get("ram_gb", 0) >= size * 2 + 4:             # leave the operating system and SwarmSentinel their share
        return "cpu"
    return None


def candidates(entries, hw):
    """[(provider id, model, where it runs)] for each local model described in the config that fits, GPU-capable first."""
    import model_config
    out = []
    for pid, entry in sorted(entries.items()):
        if entry.get("kind") != "ollama" or pid == "ollama":      # plain "ollama" auto-discovers; the named ones are the voices
            continue
        model = model_config.model_of(entry)
        where = fit(model, hw)
        if where:
            out.append((pid, model, where))
    return sorted(out, key=lambda c: (c[2] != "gpu", SIZE_GB.get(c[1], DEFAULT_SIZE_GB)))


def choose(weights_doc, max_models, max_fpr):
    """Pick the models to switch on from a weights document. Returns (chosen provider ids, {provider id: why not})."""
    if weights_doc.get("provisional", True) or weights_doc.get("n_per_class", 0) < MIN_PER_CLASS:
        return [], {"*": f"the run is too small to trust (needs {MIN_PER_CLASS} indicators per class, had {weights_doc.get('n_per_class')})"}
    ranked, why = [], {}
    for pid, w in weights_doc.get("weights", {}).items():
        if w.get("youden_lb", 0) <= 0:
            why[pid] = "no better than chance"
        elif (w.get("fpr") or 0) > max_fpr:
            why[pid] = f"false-positive rate {w['fpr']:.0%} is over {max_fpr:.0%}"
        else:
            ranked.append((w["youden_lb"], pid))
    ranked.sort(reverse=True)
    for _, pid in ranked[max_models:]:
        why[pid] = f"not in the best {max_models}"
    return [pid for _, pid in ranked[:max_models]], why


def wait_until_cool(max_temp, poll=30, patience=20 * 60):
    """Block while the GPU is hotter than max_temp; give up (return False) after `patience` seconds."""
    deadline = time.time() + patience
    while True:
        gpu = gpu_info()
        if not gpu or gpu["temp_c"] <= max_temp:
            return True
        if time.time() > deadline:
            return False
        print(f"  GPU at {gpu['temp_c']:.0f} C (limit {max_temp}); waiting {poll}s")
        time.sleep(poll)


def bench_one(pid, model, args, workdir, items_from):
    """Run ai_benchmark.py for one model in its own process; return the path of its report .json (reused if it exists)."""
    out = os.path.join(workdir, pid)
    found = sorted(glob.glob(os.path.join(out, "*.json")))
    if found:
        print(f"  {pid}: already measured ({os.path.basename(found[-1])})")
        return found[-1]
    cmd = [sys.executable, BENCH, "--n", str(args.n), "--seed", str(args.seed), "--cloud", "none", "--yes", "--out", out,
           "--local", f"{pid}={args.url}|{model}", "--local-pause", str(args.pause)]
    if items_from:
        cmd += ["--items-from", items_from]
    print(f"  {pid}: benchmarking {model} ({args.n} per class)")
    if subprocess.run(cmd).returncode != 0:
        return None
    found = sorted(glob.glob(os.path.join(out, "*.json")))
    return found[-1] if found else None


def main(argv=None):
    """Command-line entry point: probe, plan, optionally benchmark and apply."""
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--run", action="store_true", help="actually benchmark (loads the CPU/GPU for a long time); without it, plan only")
    ap.add_argument("--apply", action="store_true", help="switch the chosen models on and the other local models off (needs --run)")
    ap.add_argument("--url", default="http://127.0.0.1:11434", help="Ollama on this machine")
    ap.add_argument("--n", type=int, default=MIN_PER_CLASS, help="indicators per class (default 40, the smallest run production trusts)")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--pause", type=float, default=5.0, help="seconds between calls to a local model")
    ap.add_argument("--max-models", type=int, default=3)
    ap.add_argument("--max-fpr", type=float, default=0.35, help="reject a model that calls this share of benign items bad")
    ap.add_argument("--max-temp", type=float, default=80.0, help="do not start a model while the GPU is hotter than this (C)")
    ap.add_argument("--workdir", default=os.path.join(BACKEND, "instance", "autotune"))
    args = ap.parse_args(argv)

    import model_config
    hw = probe_hardware()
    cands = candidates(model_config.load(), hw)
    gpu = hw["gpu"]
    print(f"machine: {hw['host']}, {hw['ram_gb']} GB memory, {hw['cpus']} CPU threads, "
          f"GPU: {gpu['name'] + ', %.0f GB' % gpu['vram_gb'] if gpu else 'none'}")
    if not cands:
        print("no described local model fits this machine; use cloud keys instead (Settings, AI models and API keys)")
        return 1
    for pid, model, where in cands:
        print(f"  can run {pid} ({model}, ~{SIZE_GB.get(model, DEFAULT_SIZE_GB)} GB) on the {where.upper()}")
    if not args.run:
        print(f"\nplan only. --run would benchmark {len(cands)} model(s) at {args.n} per class "
              f"(about {args.n * 2 * len(cands)} model calls); nothing was changed.")
        return 0

    import enable_local_models
    have = enable_local_models.installed_models(args.url)
    if not have:
        print(f"no Ollama at {args.url}. Install it and pull the models first (deploy/get-models.sh), then run again.")
        return 1
    os.makedirs(args.workdir, exist_ok=True)
    reports, items_from = [], None
    for pid, model, where in cands:
        if model not in have:
            print(f"  {pid}: {model} is not installed here (ollama pull {model}); skipped")
            continue
        if not wait_until_cool(args.max_temp):
            print("GPU stayed hot; stopping here. Run again later to carry on.")
            break
        rep = bench_one(pid, model, args, args.workdir, items_from)
        if rep:
            reports.append(rep)
            items_from = items_from or rep                  # every model sees the same indicators, so the results compare
    if not reports:
        print("nothing was measured")
        return 1

    weights_path = os.path.join(args.workdir, "weights.json")
    aliases = [a for pid, _, _ in cands for a in (f"ollama:{pid}={pid}",)]
    cmd = [sys.executable, BENCH, "--merge", *reports, "--out", os.path.join(args.workdir, "merged"), "--write-weights", weights_path]
    for a in aliases:
        cmd += ["--weights-alias", a]
    if subprocess.run(cmd, stdout=subprocess.DEVNULL).returncode != 0:
        print("could not combine the reports")
        return 1
    with open(weights_path, encoding="utf-8") as f:
        doc = json.load(f)
    chosen, why = choose(doc, args.max_models, args.max_fpr)
    print("\nresult:")
    for pid, w in sorted(doc["weights"].items(), key=lambda kv: -kv[1].get("youden_lb", 0)):
        print(f"  {pid:18} skill {w['youden_lb']:.2f}  recall {w['recall']:.0%}  false-positive {w['fpr']:.0%}  "
              f"{'CHOSEN' if pid in chosen else 'left off: ' + why.get(pid, '')}")
    if "*" in why:
        print(f"  no choice made: {why['*']}")

    record = {"measured": datetime.datetime.now(datetime.timezone.utc).isoformat(), "hardware": hw, "chosen": chosen,
              "left_off": why, "weights": doc.get("weights"), "n_per_class": doc.get("n_per_class")}
    sel_path = os.path.join(BACKEND, "instance", "local_selection.json")
    os.makedirs(os.path.dirname(sel_path), exist_ok=True)
    with open(sel_path, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=1)
    print(f"\nrecorded in {sel_path}")

    if args.apply and chosen:
        from agents import ai_swarm_agent
        for pid, _, _ in cands:
            ai_swarm_agent.set_provider_enabled(pid, pid in chosen)
        print(f"switched on: {', '.join(chosen)}; other local models off. Restart ssai-agents to use them.")
    elif args.apply:
        print("nothing chosen, so nothing was changed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
