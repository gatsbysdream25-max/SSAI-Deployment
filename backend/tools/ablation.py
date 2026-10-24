#!/usr/bin/env python3
"""Does a candidate AI voice earn a vote? The ablation test of the consensus plan (section 9.5).

A model earns influence only by adding MEASURED value. This scores the panel WITH and WITHOUT the candidate on the same held-out
cases, over many random splits, and keeps the candidate only if the gain repeats. It reads a saved benchmark run (the .json that
tools/ai_benchmark.py writes: every model's answer to every case) and so never calls a model.

    python backend/tools/ablation.py RUN.json --candidate kimi [--splits 30] [--out kimi-ablation.md]

It prints and (with --out) writes a report. It NEVER changes weights, the model config or the live panel: turning a voice on is
a separate, reviewed change that quotes this report's before-and-after numbers (plan 9.5 point 6). For the same reason it refuses
to write its report into the production instance or config folders.

Rules a candidate must meet (all of them):
  * answered at least 90% of the cases (timeouts and malformed answers count against it)
  * the panel's F1 on the held-out cases improves by at least MIN_GAIN on average
  * that improvement shows in at least 75% of the splits (it repeats; it is not luck)
  * it does not make the panel miss more real threats ("critical misses") on average
It also reports what the candidate catches that the panel misses, and how many mistakes it shares with the panel (independence).
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys
from typing import Dict, List, Optional

MIN_GAIN = 0.01
MIN_REPEAT = 0.75
MIN_ANSWER_RATE = 0.90
HELD_OUT_FRACTION = 1 / 3
HERE = os.path.dirname(os.path.abspath(__file__))
FORBIDDEN_OUTPUT_DIRS = (os.path.join(os.path.dirname(HERE), "instance"), os.path.join(os.path.dirname(HERE), "config"))


def _verdict(results: dict, name: str, item_id: str) -> Optional[str]:
    v = (results.get(name, {}).get(item_id) or {}).get("verdict")
    return v if v in ("malicious", "suspicious", "benign") else None


def panel_says_malicious(results: dict, names: List[str], item_id: str) -> Optional[bool]:
    """The panel's strict call on one case: malicious only if MORE than half of the models that answered said malicious."""
    votes = [_verdict(results, n, item_id) for n in names]
    votes = [v for v in votes if v is not None]
    if not votes:
        return None
    return votes.count("malicious") > len(votes) / 2


def _f1(items: List[dict], calls: Dict[str, Optional[bool]]) -> dict:
    tp = sum(1 for i in items if i["label"] == 1 and calls.get(i["id"]) is True)
    fn = sum(1 for i in items if i["label"] == 1 and calls.get(i["id"]) is not True)      # no answer counts as a miss
    fp = sum(1 for i in items if i["label"] == 0 and calls.get(i["id"]) is True)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"f1": f1, "misses": fn, "false_alarms": fp}


def _split(items: List[dict], rng: random.Random) -> List[dict]:
    """A held-out third, drawn separately from the malicious and the benign cases so both are always present."""
    held: List[dict] = []
    for label in (0, 1):
        group = [i for i in items if i["label"] == label]
        rng.shuffle(group)
        held += group[:max(1, round(len(group) * HELD_OUT_FRACTION))]
    return held


def ablate(items: List[dict], results: dict, candidate: str, splits: int = 30, seed: int = 0) -> dict:
    """Test whether one model improves the panel: score the other voters with and without it on many random held-out
    samples and compare."""
    others = [n for n in results if n != candidate]
    if len(others) < 2:
        raise ValueError("the panel needs at least 2 other voters to compare against")
    if candidate not in results:
        raise ValueError(f"{candidate} is not in this benchmark run")
    rng = random.Random(seed)
    rows = []
    for _ in range(splits):
        held = _split(items, rng)
        without = {i["id"]: panel_says_malicious(results, others, i["id"]) for i in held}
        with_c = {i["id"]: panel_says_malicious(results, others + [candidate], i["id"]) for i in held}
        a, b = _f1(held, without), _f1(held, with_c)
        rows.append({"gain": b["f1"] - a["f1"], "misses_delta": b["misses"] - a["misses"], "false_alarms_delta": b["false_alarms"] - a["false_alarms"],
                     "f1_without": a["f1"], "f1_with": b["f1"]})
    mean = lambda key: sum(r[key] for r in rows) / len(rows)       # noqa: E731
    answered = sum(1 for i in items if _verdict(results, candidate, i["id"]) is not None)
    unique, shared, cand_wrong, panel_wrong = [], [], 0, 0
    for i in items:
        truth = i["label"] == 1
        panel = panel_says_malicious(results, others, i["id"])
        cand = _verdict(results, candidate, i["id"])
        cand_call = None if cand is None else (cand == "malicious")
        cand_right, panel_right = cand_call is truth, panel is truth
        cand_wrong += not cand_right
        panel_wrong += not panel_right
        if cand_right and not panel_right:
            unique.append(i["id"])
        if not cand_right and not panel_right:
            shared.append(i["id"])
    repeat = sum(1 for r in rows if r["gain"] > 0) / len(rows)
    answer_rate = answered / len(items) if items else 0.0
    checks = {
        "answered_enough": answer_rate >= MIN_ANSWER_RATE,
        "gain_big_enough": mean("gain") >= MIN_GAIN,
        "gain_repeats": repeat >= MIN_REPEAT,
        "no_more_misses": mean("misses_delta") <= 0,
    }
    return {"candidate": candidate, "panel_without": others, "splits": splits, "cases": len(items),
            "answer_rate": round(answer_rate, 3), "mean_f1_without": round(mean("f1_without"), 4), "mean_f1_with": round(mean("f1_with"), 4),
            "mean_gain": round(mean("gain"), 4), "gain_repeats_in": round(repeat, 3), "mean_misses_delta": round(mean("misses_delta"), 3),
            "mean_false_alarms_delta": round(mean("false_alarms_delta"), 3),
            "catches_panel_misses": len(unique), "shared_mistakes": len(shared),
            "shared_share_of_candidate_mistakes": round(len(shared) / cand_wrong, 3) if cand_wrong else 0.0,
            "checks": checks, "earns_a_vote": all(checks.values())}


def to_markdown(r: dict) -> str:
    """Turn the ablation result dict into a Markdown report with a pass or FAIL line for each check."""
    ok = {True: "pass", False: "FAIL"}
    lines = [f"# Ablation test: {r['candidate']}", "",
             f"**Result: {'EARNS A VOTE' if r['earns_a_vote'] else 'DOES NOT EARN A VOTE (yet)'}**", "",
             f"Panel without it: {', '.join(r['panel_without'])}. {r['cases']} cases, {r['splits']} random held-out splits.", "",
             f"- Answered {r['answer_rate']:.0%} of the cases: {ok[r['checks']['answered_enough']]} (needs {MIN_ANSWER_RATE:.0%})",
             f"- Panel F1 {r['mean_f1_without']:.3f} without, {r['mean_f1_with']:.3f} with; mean gain {r['mean_gain']:+.4f}: "
             f"{ok[r['checks']['gain_big_enough']]} (needs {MIN_GAIN:+.2f})",
             f"- Gain was positive in {r['gain_repeats_in']:.0%} of splits: {ok[r['checks']['gain_repeats']]} (needs {MIN_REPEAT:.0%})",
             f"- Real threats missed: {r['mean_misses_delta']:+.2f} on average per split: {ok[r['checks']['no_more_misses']]} (must not rise)",
             f"- False alarms: {r['mean_false_alarms_delta']:+.2f} on average per split (informational)",
             f"- Catches {r['catches_panel_misses']} case(s) the panel got wrong; shares {r['shared_mistakes']} of the panel's mistakes "
             f"({r['shared_share_of_candidate_mistakes']:.0%} of its own).", "",
             "A passing result is a recommendation, not a switch. Turning the voice on is a reviewed change that quotes the before and after numbers above.", ""]
    return "\n".join(lines)


def _check_output_path(path: str) -> None:
    full = os.path.abspath(path)
    for forbidden in FORBIDDEN_OUTPUT_DIRS:
        if full.startswith(os.path.abspath(forbidden) + os.sep):
            raise SystemExit(f"refusing to write inside {forbidden}: an ablation report must never land in production settings")


def main(argv=None) -> int:
    """Command-line entry point: read a benchmark run, test the chosen model, print the report, and exit 0 only if it
    earns a vote."""
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("run", help="benchmark run .json written by ai_benchmark.py")
    ap.add_argument("--candidate", required=True, help="the model name exactly as it appears in the run")
    ap.add_argument("--splits", type=int, default=30)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out", help="write the report here (.md)")
    args = ap.parse_args(argv)
    if args.out:
        _check_output_path(args.out)
    with open(args.run, encoding="utf-8") as f:
        doc = json.load(f)
    report = ablate(doc["items"], doc["results"], args.candidate, splits=args.splits, seed=args.seed)
    text = to_markdown(report)
    print(text)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text)
    return 0 if report["earns_a_vote"] else 1


if __name__ == "__main__":
    sys.exit(main())
