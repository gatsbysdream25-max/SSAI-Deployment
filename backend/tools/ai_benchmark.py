#!/usr/bin/env python3
"""
AI verdict benchmark for the SwarmSentinel consensus engine.

Scores every AI provider (cloud APIs and local Ollama models) on labeled indicators using the
production prompt and the production consensus function, so the numbers describe the real pipeline.

  Ground truth
    malicious : recent, currently-online malware URLs from abuse.ch URLhaus (public, keyless export)
    benign    : a curated list of well-known sites ("easy") plus benign look-alikes ("hard": raw IPs of
                public resolvers, one-line installers, connectivity checks) so a model cannot win by
                pattern-matching "raw IP or .sh == bad".
  Blind         : the AI sees only the indicator. Production sends the threat description as the title,
                  which for feed items literally says "malware" -- that leaks the label, so it is NOT used.
  Safety        : indicators are only sent to the AIs as text; nothing is fetched or executed. No database
                  writes. Local models are paced (thermal) and cloud providers are rate limited.

Usage:  python3 backend/tools/ai_benchmark.py --n 15 --local 'wt-mistral=http://192.168.1.20:11434|mistral'
        (see --help; use --dry-run first)
"""
import argparse
import csv
import datetime
import json
import math
import os
import random
import re
import statistics
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

URLHAUS_CSV = 'https://urlhaus.abuse.ch/downloads/csv_recent/'
VALID = ('malicious', 'suspicious', 'benign')

BENIGN_EASY = [
    'https://www.google.com/', 'https://github.com/', 'https://www.wikipedia.org/', 'https://www.microsoft.com/',
    'https://www.apple.com/', 'https://www.mozilla.org/', 'https://www.cloudflare.com/', 'https://www.python.org/',
    'https://pypi.org/simple/requests/', 'https://registry.npmjs.org/express', 'https://www.debian.org/',
    'https://ubuntu.com/', 'https://www.amazon.com/', 'https://www.bbc.co.uk/news', 'https://www.nasa.gov/',
    'https://docs.docker.com/', 'https://stackoverflow.com/', 'https://www.reddit.com/', 'https://www.linkedin.com/',
    'https://www.netflix.com/', 'https://www.paypal.com/', 'https://www.dropbox.com/', 'https://zoom.us/',
    'https://slack.com/', 'https://www.ibm.com/', 'https://www.oracle.com/', 'https://www.adobe.com/',
    'https://nginx.org/', 'https://kernel.org/', 'https://www.gnu.org/',
]
BENIGN_HARD = [
    'http://1.1.1.1/', 'https://8.8.8.8/', 'https://1.1.1.1/dns-query', 'http://9.9.9.9/', 'http://example.com:80/',
    'http://neverssl.com/', 'http://info.cern.ch/', 'https://raw.githubusercontent.com/nvm-sh/nvm/master/install.sh',
    'https://get.docker.com/', 'https://sh.rustup.rs/', 'https://brew.sh/', 'https://deb.nodesource.com/setup_20.x',
    'https://install.python-poetry.org/', 'https://astral.sh/uv/install.sh', 'https://ollama.com/install.sh',
    'https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb', 'https://download.docker.com/linux/ubuntu/gpg',
    'http://archive.ubuntu.com/ubuntu/dists/noble/Release', 'http://security.debian.org/debian-security/',
    'http://ftp.gnu.org/gnu/bash/', 'https://api.github.com/repos/python/cpython', 'https://checkip.amazonaws.com/',
    'https://ifconfig.me/', 'http://connectivitycheck.gstatic.com/generate_204', 'http://www.msftconnecttest.com/connecttest.txt',
    'http://detectportal.firefox.com/success.txt', 'https://time.google.com/', 'https://speed.cloudflare.com/__down?bytes=1000',
    'https://get.helm.sh/helm-v3.14.0-linux-amd64.tar.gz', 'https://download.mozilla.org/?product=firefox-latest&os=linux64&lang=en-US',
]
_RAW_IP = re.compile(r'^https?://\d{1,3}(\.\d{1,3}){3}(:\d+)?/')


# ───────────────────────── dataset ─────────────────────────

def parse_urlhaus_csv(text):
    """Rows of currently-online URLs -> [{'url', 'tags', 'threat'}] (comment/header lines skipped)."""
    out, seen = [], set()
    for row in csv.reader(l for l in text.splitlines() if l and not l.startswith('#')):
        if len(row) < 9 or row[3] != 'online':
            continue
        url = row[2].strip()
        if url and url not in seen:
            seen.add(url)
            out.append({'url': url, 'tags': '' if row[6] in ('', 'None') else row[6], 'threat': row[5]})
    return out


def build_dataset(feed_rows, n, seed):
    """n malicious + n benign, interleaved 'half' tags (0=calibration, 1=test) within each class."""
    rng = random.Random(seed)
    ip_rows = sorted((r for r in feed_rows if _RAW_IP.match(r['url'])), key=lambda r: r['url'])
    dom_rows = sorted((r for r in feed_rows if not _RAW_IP.match(r['url'])), key=lambda r: r['url'])
    want_dom = min(len(dom_rows), n // 2)
    pos = rng.sample(dom_rows, want_dom) + rng.sample(ip_rows, min(len(ip_rows), n - want_dom))
    if len(pos) < n:  # not enough of one kind: top up from whatever remains
        rest = [r for r in ip_rows + dom_rows if r not in pos]
        pos += rng.sample(rest, min(len(rest), n - len(pos)))
    hard = rng.sample(BENIGN_HARD, min(len(BENIGN_HARD), n // 2 + n % 2))
    easy = rng.sample(BENIGN_EASY, min(len(BENIGN_EASY), n - len(hard)))
    neg = [(u, 'benign-hard') for u in hard] + [(u, 'benign-easy') for u in easy]
    items = []
    for i, r in enumerate(pos):
        items.append({'id': f'm{i}', 'url': r['url'], 'label': 1, 'group': 'urlhaus-ip' if _RAW_IP.match(r['url']) else 'urlhaus-domain',
                      'tags': r['tags'], 'half': i % 2})
    for i, (u, g) in enumerate(neg):
        items.append({'id': f'b{i}', 'url': u, 'label': 0, 'group': g, 'tags': '', 'half': i % 2})
    rng.shuffle(items)
    return items


def blind_threat_json(item):
    """Same fields production sends (title/category/severity/source/detail/agent) with NO label information."""
    return json.dumps({
        'title': 'Network indicator to assess', 'category': 'url', 'severity': 'MEDIUM',
        'source': item['url'], 'detail': 'URL observed in network traffic. Judge the indicator itself.',
        'agent': 'benchmark',
    }, indent=2)


def gated_threat_json(item, provider_name):
    """What a CLOUD provider may be asked in a benchmark: the same sanitizer.sanitize_for_cloud copy production sends, written to
    the same cloud audit log (audit F-12). None means the gate refused, so nothing is sent. A model on this network gets the
    plain blind_threat_json instead."""
    try:
        here = os.path.dirname(os.path.abspath(__file__))
        sys.path[:0] = [os.path.dirname(here)]
        import sanitizer
        out = sanitizer.sanitize_for_cloud({
            'severity': 'medium', 'threat_type': 'url',
            'sanitized_summary': f"Network indicator to assess\nIndicator: {item['url']}\nURL observed in network traffic. Judge the indicator itself.",
        }, destination=f'benchmark:{provider_name}')
    except Exception:  # noqa: BLE001 -- fail closed
        return None
    if not out.get('sanitized_summary'):
        return None
    return json.dumps({'category': out.get('threat_type', ''), 'severity': out.get('severity', '').upper(),
                       'summary': out['sanitized_summary']}, indent=2)


# ───────────────────────── provider calls ─────────────────────────

def pname(p):
    return getattr(p, 'label', None) or p.name


def call_provider(provider, prompt_fn, threat_json):
    """Ask one provider about one indicator and return its verdict, or an error description; a failure is recorded as
    data, never raised."""
    t0 = time.time()
    try:
        text = provider.analyze(prompt_fn(provider, threat_json))
    except Exception as e:  # noqa: BLE001 - any provider failure is data, not a crash
        body = ''
        resp = getattr(e, 'response', None)
        if resp is not None:
            try:
                body = ' -- ' + resp.text[:100]
            except Exception:  # noqa: BLE001
                # the response body is optional extra detail for the error message
                pass
        return {'verdict': None, 'error': f'{type(e).__name__}: {str(e)[:120]}{body}', 'latency': time.time() - t0}
    lat = time.time() - t0
    if not text:
        return {'verdict': None, 'error': 'empty response', 'latency': lat, 'raw': ''}
    # Models often wrap their JSON in extra words or code fences, so take everything from the first '{' to the last '}'.
    s, e = text.find('{'), text.rfind('}') + 1
    if s < 0 or e <= s:
        return {'verdict': None, 'error': 'no JSON object in response', 'latency': lat, 'raw': text[:150]}
    try:
        v = json.loads(text[s:e])
    except ValueError:
        return {'verdict': None, 'error': 'invalid JSON', 'latency': lat, 'raw': text[s:e][:150]}
    verdict = str(v.get('verdict', '')).strip().lower()
    if verdict not in VALID:
        return {'verdict': None, 'error': f'unrecognized verdict {verdict[:20]!r}', 'latency': lat, 'raw': text[s:e][:150]}
    try:
        conf = int(float(v.get('confidence')))
    except (TypeError, ValueError):
        conf = None
    return {'verdict': verdict, 'confidence': conf, 'severity': v.get('severity'), 'latency': lat, 'error': None}


def run_provider(provider, items, prompt_fn, cfg, results, meta, is_local):
    """Ask one provider about every indicator, pacing the calls, and stop early if it fails too many times in a row."""
    name = pname(provider)
    rpm = cfg.get('rpm_for', {}).get(name, cfg['rpm'])
    # Seconds to wait between calls: local models get a fixed pause to stay cool; cloud ones are spaced to stay under their requests-per-minute limit.
    interval = cfg['local_pause'] if is_local else (60.0 / rpm if rpm else 0)
    consecutive = 0
    results[name] = {}
    meta[name] = {'aborted': False, 'model': (provider.capabilities() or {}).get('model') if hasattr(provider, 'capabilities') else None,
                  'local': is_local}
    for i, item in enumerate(items):
        threat_json = blind_threat_json(item) if is_local else gated_threat_json(item, name)
        if threat_json is None:
            r = {'verdict': None, 'error': 'withheld by the cloud gate (nothing was sent)', 'latency': 0.0}
        else:
            r = call_provider(provider, prompt_fn, threat_json)
        results[name][item['id']] = r
        consecutive = consecutive + 1 if r['verdict'] is None else 0
        if cfg.get('progress') and (i + 1) % 5 == 0:
            print(f'  {name}: {i + 1}/{len(items)}', file=sys.stderr)
        if consecutive >= cfg['max_errors']:
            meta[name]['aborted'] = True
            meta[name]['abort_reason'] = r['error']
            break
        if interval and i + 1 < len(items):
            time.sleep(interval)


def run_benchmark(items, local_providers, cloud_providers, prompt_fn, cfg):
    """Run all providers at once: each cloud provider in its own thread, local models one after another in a single
    thread."""
    results, meta = {}, {}

    def local_worker():  # local models run one after another: they share CPUs and run hot
        for p in local_providers:
            run_provider(p, items, prompt_fn, cfg, results, meta, True)

    with ThreadPoolExecutor(max_workers=max(1, len(cloud_providers) + 1)) as ex:
        futs = [ex.submit(run_provider, p, items, prompt_fn, cfg, results, meta, False) for p in cloud_providers]
        if local_providers:
            futs.append(ex.submit(local_worker))
        for f in futs:
            f.result()
    return results, meta


# ───────────────────────── scoring ─────────────────────────

def wilson(k, n, z=1.96):
    if n == 0:
        return (None, None)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def _ratio(a, b):
    return a / b if b else None


def confusion(items, verdicts, positive):
    """verdicts: {item_id: verdict or None}. Items without a valid verdict are abstentions."""
    tp = fp = tn = fn = 0
    for it in items:
        v = verdicts.get(it['id'])
        if v is None:
            continue
        pred = v in positive
        if it['label'] and pred:
            tp += 1
        elif it['label']:
            fn += 1
        elif pred:
            fp += 1
        else:
            tn += 1
    prec, rec = _ratio(tp, tp + fp), _ratio(tp, tp + fn)
    return {'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn, 'scored': tp + fp + tn + fn,
            'precision': prec, 'recall': rec, 'fpr': _ratio(fp, fp + tn), 'accuracy': _ratio(tp + tn, tp + fp + tn + fn),
            'f1': (2 * prec * rec / (prec + rec)) if prec and rec else (0.0 if prec is not None and rec is not None else None),
            'recall_ci': wilson(tp, tp + fn), 'fpr_ci': wilson(fp, fp + tn),
            'youden': ((rec or 0) + (1 - (_ratio(fp, fp + tn) or 0)) - 1) if (tp + fn) and (fp + tn) else None}


def provider_stats(items, res):
    """Summarise one provider: strict and lenient accuracy figures, error rate, response times, and how confident it was
    when right and when wrong."""
    verdicts = {i['id']: (res.get(i['id']) or {}).get('verdict') for i in items}
    calls = [r for r in res.values()]
    ok = [r for r in calls if r['verdict']]
    lat = sorted(r['latency'] for r in ok)
    wrong_hi = 0
    rc, wc = [], []
    by_id = {i['id']: i for i in items}
    for iid, r in res.items():
        if not r['verdict'] or r.get('confidence') is None:
            continue
        correct = (r['verdict'] == 'malicious') == bool(by_id[iid]['label'])
        (rc if correct else wc).append(r['confidence'])
        if not correct and r['confidence'] >= 80:      # 80 = our cut-off for 'very sure'; a confident wrong answer is the costly kind
            wrong_hi += 1
    return {
        'strict': confusion(items, verdicts, {'malicious'}),
        'lenient': confusion(items, verdicts, {'malicious', 'suspicious'}),
        'calls': len(calls), 'errors': len(calls) - len(ok), 'error_rate': _ratio(len(calls) - len(ok), len(calls)),
        'latency_mean': statistics.mean(lat) if lat else None, 'latency_p50': lat[len(lat) // 2] if lat else None,
        'latency_p95': lat[min(len(lat) - 1, int(len(lat) * 0.95))] if lat else None,
        'conf_when_right': statistics.mean(rc) if rc else None, 'conf_when_wrong': statistics.mean(wc) if wc else None,
        'high_conf_wrong': wrong_hi,
        'last_error': next((r['error'] for r in reversed(calls) if r['error']), None),
    }


def production_consensus(item_verdicts, consensus_fn, weights=None):
    """Run the production _consensus() over the providers that answered."""
    results = [{'verdict': v['verdict'], 'confidence': v.get('confidence') or 50, 'severity': v.get('severity') or 'MEDIUM',
                'ai': n} for n, v in item_verdicts.items() if v.get('verdict')]
    if not results:
        return None
    try:
        return consensus_fn(results, weights={} if weights is None else weights)['consensus_verdict']   # {} = plain majority, ignoring any weights file
    except TypeError:
        return consensus_fn(results)['consensus_verdict']


def weighted_vote(item_verdicts, weights):
    """Combine providers' verdicts, trusting each by its weight (suspicious counts as half); returns 'malicious',
    'benign' or None."""
    num = den = 0.0
    for n, v in item_verdicts.items():
        w = weights.get(n, 0.0)
        if not v.get('verdict'):
            continue
        # malicious counts as 1, suspicious as half a vote for malicious, benign as 0
        num += w * (1 if v['verdict'] == 'malicious' else 0.5 if v['verdict'] == 'suspicious' else 0)
        den += w
    if den == 0:
        return None
    return 'malicious' if num / den >= 0.5 else 'benign'


def evaluate(items, results, consensus_fn, weights_doc=None):
    """Score every provider and, with two or more, test how different ways of combining their votes do on a held-out half
    of the indicators."""
    per = {n: provider_stats(items, r) for n, r in results.items()}
    out = {'providers': per}
    names = [n for n, r in results.items() if any(v['verdict'] for v in r.values())]
    # Weights are learned on one half of the indicators (calibration) and tested on the other, so a model is never scored on data that set its weight.
    calib = [i for i in items if i['half'] == 0]
    test = [i for i in items if i['half'] == 1]
    if len(names) >= 2 and calib and test:
        weights = {n: max(0.0, (confusion(calib, {i['id']: results[n].get(i['id'], {}).get('verdict') for i in calib}, {'malicious'})['youden'] or 0.0))
                   for n in names}
        per_item = {i['id']: {n: results[n].get(i['id'], {'verdict': None}) for n in names} for i in items}
        prod = {i['id']: production_consensus(per_item[i['id']], consensus_fn) for i in test}
        wtd = {i['id']: weighted_vote(per_item[i['id']], weights) for i in test}
        calib_ids = {i['id'] for i in calib}
        schemes = {}
        for mode in ('equal', 'strict', 'lenient', 'mean', 'two-tier'):
            if mode == 'equal':
                w = {n: 1.0 for n in names}
            elif mode == 'two-tier':
                calib_results = {n: {iid: r for iid, r in results[n].items() if iid in calib_ids} for n in names}
                cw = compute_weights(calib, calib_results, {}, min_scored=5)
                w = {n: {'firm': v['weight_firm'], 'flag': v['weight_flag']} for n, v in cw.items()}
            else:
                calib_results = {n: {iid: r for iid, r in results[n].items() if iid in calib_ids} for n in names}
                w = {n: v['weight'] for n, v in compute_weights(calib, calib_results, {}, min_scored=5, mode=mode).items()}
            preds = {i['id']: production_consensus(per_item[i['id']], consensus_fn, weights=w) for i in test}
            schemes[mode] = {'strict': confusion(test, preds, {'malicious'}), 'lenient': confusion(test, preds, {'malicious', 'suspicious'}), 'weights': w}
        out['consensus_test_half'] = {
            'weighting_schemes': schemes,
            'weights_youden_from_calibration_half': weights,
            'production_majority_strict': confusion(test, prod, {'malicious'}),
            'production_majority_lenient': confusion(test, prod, {'malicious', 'suspicious'}),
            'legacy_rule_lenient': confusion(test, {i['id']: production_consensus(per_item[i['id']], legacy_consensus) for i in test}, {'malicious', 'suspicious'}),
            'weighted_vote': confusion(test, wtd, {'malicious'}),
            'best_single_strict': max(((n, confusion(test, {i['id']: results[n].get(i['id'], {}).get('verdict') for i in test}, {'malicious'}))
                                       for n in names), key=lambda kv: (kv[1]['youden'] if kv[1]['youden'] is not None else -9)),
        }
    if weights_doc:
        by_harness = {v.get('harness_name', k): v for k, v in (weights_doc.get('weights') or {}).items()}
        wt_single = {n: by_harness[n]['weight'] for n in names if n in by_harness and 'weight' in by_harness[n]}
        wt_two = {n: {'firm': by_harness[n]['weight_firm'], 'flag': by_harness[n]['weight_flag']}
                  for n in names if n in by_harness and 'weight_firm' in by_harness[n]}
        per_all = {i['id']: {n: results[n].get(i['id'], {'verdict': None}) for n in names} for i in items}
        val = {}
        for label, w in (('equal (plain majority)', {n: 1.0 for n in names}), ('single weight (strict)', wt_single), ('two-tier weights', wt_two)):
            preds = {i['id']: production_consensus(per_all[i['id']], consensus_fn, weights=w) for i in items}
            val[label] = {'strict': confusion(items, preds, {'malicious'}), 'lenient': confusion(items, preds, {'malicious', 'suspicious'}), 'weights': w}
        out['validation'] = {'weights_from': weights_doc.get('source_report'), 'n_items': len(items), 'schemes': val}
    # items most providers get wrong (strict)
    hard = []
    for i in items:
        vs = [results[n].get(i['id'], {}).get('verdict') for n in names]
        vs = [v for v in vs if v]
        if len(vs) >= 2:
            wrong = sum(1 for v in vs if (v == 'malicious') != bool(i['label']))
            if wrong >= (len(vs) + 1) // 2:
                hard.append({'url': i['url'], 'label': 'malicious' if i['label'] else 'benign', 'group': i['group'],
                             'wrong': f'{wrong}/{len(vs)}'})
    out['hard_items'] = hard[:12]
    return out


# ───────────────────────── report ─────────────────────────

def _pct(x):
    return '  n/a' if x is None else f'{100 * x:5.1f}%'


def _ci(t):
    return 'n/a' if t[0] is None else f'{100 * t[0]:.0f}-{100 * t[1]:.0f}%'


def render_markdown(meta_run, items, ev, meta):
    """Turn the evaluation results into the Markdown report people read."""
    L = []
    pos = sum(1 for i in items if i['label'])
    L += [f"# AI benchmark {meta_run['when']}", '',
          f"- items: {len(items)} ({pos} malicious from URLhaus, {len(items) - pos} benign), seed {meta_run['seed']}, blind prompt (indicator only)",
          f"- groups: {meta_run['groups']}", f"- code: {meta_run['commit']}", '']
    for mode in ('strict', 'lenient'):
        L += [f"## {mode.capitalize()} ({'malicious only counts as a detection' if mode == 'strict' else 'malicious OR suspicious counts as a detection'})", '',
              '| provider | model | scored | precision | recall (95% CI) | false-pos rate (95% CI) | F1 | accuracy |', '|---|---|---|---|---|---|---|---|']
        for n, s in sorted(ev['providers'].items(), key=lambda kv: -(kv[1][mode]['youden'] or -9)):
            c = s[mode]
            L.append(f"| {n} | {meta.get(n, {}).get('model') or ''} | {c['scored']}/{s['calls']} | {_pct(c['precision'])} | {_pct(c['recall'])} ({_ci(c['recall_ci'])}) "
                     f"| {_pct(c['fpr'])} ({_ci(c['fpr_ci'])}) | {_pct(c['f1'])} | {_pct(c['accuracy'])} |")
        L.append('')
    L += ['## Reliability, speed, calibration', '',
          '| provider | errors | latency mean / p95 | confidence when right / wrong | wrong at >=80% confidence | note |', '|---|---|---|---|---|---|']
    for n, s in ev['providers'].items():
        note = ('ABORTED after repeated errors: ' + str(meta[n].get('abort_reason'))[:70]) if meta.get(n, {}).get('aborted') else (s['last_error'] or '')[:70]
        lm = 'n/a' if s['latency_mean'] is None else f"{s['latency_mean']:.1f}s / {s['latency_p95']:.1f}s"
        cr = 'n/a' if s['conf_when_right'] is None else f"{s['conf_when_right']:.0f} / {('n/a' if s['conf_when_wrong'] is None else format(s['conf_when_wrong'], '.0f'))}"
        L.append(f"| {n} | {s['errors']}/{s['calls']} | {lm} | {cr} | {s['high_conf_wrong']} | {note} |")
    L.append('')
    c = ev.get('consensus_test_half')
    if c:
        L += ['## Does the consensus add value? (held-out test half; weights learned on the other half)', '',
              '| method | precision | recall | false-pos rate | accuracy | n |', '|---|---|---|---|---|---|']
        rows = [('production consensus, current code (strict)', c['production_majority_strict']), ('production consensus, current code (lenient)', c['production_majority_lenient']),
                ('OLD rule: any suspicious vote wins (lenient)', c['legacy_rule_lenient']),
                ('weighted vote (Youden-J weights)', c['weighted_vote']), (f"best single: {c['best_single_strict'][0]}", c['best_single_strict'][1])]
        for label, m in rows:
            L.append(f"| {label} | {_pct(m['precision'])} | {_pct(m['recall'])} | {_pct(m['fpr'])} | {_pct(m['accuracy'])} | {m['scored']} |")
        if c.get('weighting_schemes'):
            L += ['', '## Weighting schemes through the production consensus (held-out test half; weights from the calibration half)', '',
                  '| weights from | strict acc | strict recall | strict FPR | lenient acc | lenient recall | lenient FPR |', '|---|---|---|---|---|---|---|']
            for mode, r in c['weighting_schemes'].items():
                a, b = r['strict'], r['lenient']
                L.append(f"| {mode} | {_pct(a['accuracy'])} | {_pct(a['recall'])} | {_pct(a['fpr'])} | {_pct(b['accuracy'])} | {_pct(b['recall'])} | {_pct(b['fpr'])} |")
            L.append('')
        L += ['', 'Weights: ' + ', '.join(f'{k}={v:.2f}' for k, v in c['weights_youden_from_calibration_half'].items()), '']
    v = ev.get('validation')
    if v:
        L += [f"## Out-of-sample validation: weights learned on {v['weights_from']} applied to THIS run's {v['n_items']} indicators", '',
              '| consensus | strict acc | strict recall | strict FPR | lenient acc | lenient recall | lenient FPR |', '|---|---|---|---|---|---|---|']
        for label, r in v['schemes'].items():
            a, b = r['strict'], r['lenient']
            L.append(f"| {label} | {_pct(a['accuracy'])} | {_pct(a['recall'])} | {_pct(a['fpr'])} | {_pct(b['accuracy'])} | {_pct(b['recall'])} | {_pct(b['fpr'])} |")
        L.append('')
    if ev['hard_items']:
        L += ['## Indicators most providers got wrong', '', '| indicator | truth | group | wrong |', '|---|---|---|---|']
        L += [f"| `{h['url'][:70]}` | {h['label']} | {h['group']} | {h['wrong']} |" for h in ev['hard_items']]
        L.append('')
    L += ['## Caveats', '', '- Small samples: read the confidence intervals, not just the point estimates.',
          '- "malicious" labels are URLhaus listings that were online at collection time; the AIs judge the URL text only.',
          '- Benign labels are curated well-known URLs; a real network also has long-tail benign traffic this list cannot cover.',
          '- Production sends the threat description as the title; for feed items that text contains the answer, so real-world consensus on those looks better than it is.', '']
    return '\n'.join(L)


# ───────────────────────── CLI ─────────────────────────

def _commit():
    try:
        return subprocess.check_output(['git', 'rev-parse', '--short', 'HEAD'], cwd=os.path.dirname(os.path.abspath(__file__)),
                                       stderr=subprocess.DEVNULL, timeout=5).decode().strip()
    except Exception:  # noqa: BLE001
        return 'unknown'


def build_real_providers(args):
    """Set up the real AI providers (local Ollama models, cloud APIs, extras) plus the production prompt and consensus
    function the benchmark needs."""
    here = os.path.dirname(os.path.abspath(__file__))
    backend = os.path.dirname(here)
    sys.path[:0] = [os.path.join(backend, 'agents'), backend]
    import ssai_config
    from dotenv import load_dotenv
    load_dotenv(ssai_config.ENV_PATH, override=False)
    import ai_swarm_agent as swarm
    analyzer = swarm.AiSwarmAnalyzer()
    skip = {s.strip() for s in args.skip.split(',') if s.strip()}
    want = None if args.cloud == 'auto' else {s.strip() for s in args.cloud.split(',') if s.strip()}
    cloud = [p for p in analyzer._providers if p.name != 'ollama' and p.name not in skip and (want is None or p.name in want)]
    local = []
    for spec in args.local or []:
        label, rest = spec.split('=', 1)
        url, model = rest.split('|', 1)
        p = swarm._OllamaProvider.__new__(swarm._OllamaProvider)
        p.base_url, p.model, p.available = url.rstrip('/'), model, True
        p.label, p.registry_id = f'ollama:{label}', 'ollama'
        local.append(p)

    for spec in getattr(args, 'extra', None) or []:
        label, rest = spec.split('=', 1)
        base_url, key_env, model = rest.split('|', 2)
        p = swarm._OpenAICompatProvider(label, key_env, base_url, model)
        if p.available:
            cloud.append(p)
        else:
            print(f'extra provider {label}: {key_env} is not set, skipping', file=sys.stderr)

    def prompt_fn(provider, threat_json):
        reg = swarm._REGISTRY_BY_ID.get(getattr(provider, 'registry_id', provider.name), {})
        return swarm._PROMPT.format(specialty=reg.get('specialty', 'General Cybersecurity'),
                                    focus=reg.get('focus', 'Focus on threat severity, attack type, and recommended action.'),
                                    threat_json=threat_json)
    return local, cloud, prompt_fn, swarm.AiSwarmAnalyzer._consensus


def legacy_consensus(results):
    """The pre-2026-09-19 production rule: ANY single suspicious vote makes the consensus suspicious."""
    v = [r['verdict'] for r in results]
    n, mal, sus = len(v), v.count('malicious'), v.count('suspicious')
    return {'consensus_verdict': 'malicious' if mal > n / 2 else 'suspicious' if sus > 0 else 'benign'}


def merge_reports(reports):
    """Combine several report JSONs that were run on the SAME indicators (use --items-from) into one comparison."""
    key = lambda items: [(i['id'], i['url'], i['label']) for i in items]
    base = reports[0]['items']
    results, meta = {}, {}
    for r in reports:
        if key(r['items']) != key(base):
            raise ValueError('reports were run on different indicator sets; rerun with --items-from <report.json>')
        results.update(r['results'])
        meta.update(r.get('meta', {}))
    return base, results, meta


def load_consensus_fn():
    here = os.path.dirname(os.path.abspath(__file__))
    backend = os.path.dirname(here)
    sys.path[:0] = [os.path.join(backend, 'agents'), backend]
    import ai_swarm_agent as swarm
    return swarm.AiSwarmAnalyzer._consensus


MIN_PER_CLASS_FOR_ADOPTION = 40


def compute_weights(items, results, meta, min_scored=10, mode='strict'):
    """Vote weight per provider = Youden's J (recall + true-negative rate - 1) using the 95% Wilson LOWER bounds,
    normalised so the best provider is 1.0. Providers no better than chance get 0. Small samples give wide
    intervals, hence low weights: a lucky 20-item run cannot promote a provider."""
    out = {}
    def j_lb(st):
        if st['scored'] < min_scored or st['recall_ci'][0] is None or st['fpr_ci'][0] is None:
            return None
        return max(0.0, st['recall_ci'][0] + (1 - st['fpr_ci'][1]) - 1)

    for name, res in results.items():
        stats = provider_stats(items, res)
        js, jl = j_lb(stats['strict']), j_lb(stats['lenient'])
        if js is None or jl is None:
            continue
        j = {'strict': js, 'lenient': jl, 'mean': (js + jl) / 2}[mode]
        st = stats['strict']
        out[name] = {'youden_lb': round(j, 4), 'youden_lb_strict': round(js, 4), 'youden_lb_lenient': round(jl, 4),
                     'recall': st['recall'], 'fpr': st['fpr'], 'scored': st['scored'], 'model': (meta.get(name) or {}).get('model')}
    top = max((v['youden_lb'] for v in out.values()), default=0.0)
    top_s = max((v['youden_lb_strict'] for v in out.values()), default=0.0)
    top_l = max((v['youden_lb_lenient'] for v in out.values()), default=0.0)
    for v in out.values():
        v['weight'] = round(v['youden_lb'] / top, 3) if top > 0 else 1.0
        # two-tier: `firm` decides "malicious" (strict skill), `flag` decides "suspicious" (lenient skill)
        v['weight_firm'] = round(v['youden_lb_strict'] / top_s, 3) if top_s > 0 else 1.0
        v['weight_flag'] = round(v['youden_lb_lenient'] / top_l, 3) if top_l > 0 else 1.0
    return out


def build_weights_doc(items, results, meta, aliases, source, mode='strict'):
    """Build the vote-weights file (one weight per provider) from a benchmark run, marked provisional when there are too
    few indicators per class."""
    weights = compute_weights(items, results, meta, mode=mode)
    mapped = {}
    for harness_name, v in weights.items():
        prod = aliases.get(harness_name, harness_name)
        if prod in mapped:
            raise ValueError(f'two benchmark entries map to the production provider {prod!r}; fix --weights-alias')
        mapped[prod] = dict(v, harness_name=harness_name)
    pos = sum(1 for i in items if i['label'])
    per_class = min(pos, len(items) - pos)
    return {'generated': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'source_report': source, 'n_per_class': per_class,
            'provisional': per_class < MIN_PER_CLASS_FOR_ADOPTION,
            'method': f'Youden J ({mode} scoring) from 95% Wilson lower bounds, normalised to max=1',
            'note': f'Production ignores this file while provisional (needs >= {MIN_PER_CLASS_FOR_ADOPTION} indicators per class). '
                    'Providers absent from the file vote with weight 1.0, so benchmark the whole deployed panel before adopting.',
            'weights': mapped}


def emit(args, items, results, meta, ev, groups, tag=''):
    """Write the finished benchmark as a Markdown and a JSON file (and the weights file if asked), print the report, and
    return 0."""
    when = datetime.datetime.now().strftime('%Y%m%d-%H%M') + tag
    out = args.out or os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'instance', 'benchmarks')
    os.makedirs(out, exist_ok=True)
    run_meta = {'when': when, 'seed': args.seed, 'groups': groups, 'commit': _commit()}
    md = render_markdown(run_meta, items, ev, meta)
    with open(os.path.join(out, f'{when}.md'), 'w', encoding='utf-8') as f:
        f.write(md)
    with open(os.path.join(out, f'{when}.json'), 'w', encoding='utf-8') as f:
        json.dump({'run': run_meta, 'items': items, 'results': results, 'meta': meta, 'evaluation': ev}, f, indent=1, default=str)
    if getattr(args, 'write_weights', None):
        aliases = dict(x.split('=', 1) for x in (getattr(args, 'weights_alias', None) or []))
        doc = build_weights_doc(items, results, meta, aliases, f'{when}.json', mode=getattr(args, 'weights_mode', 'strict'))
        with open(args.write_weights, 'w', encoding='utf-8') as f:
            json.dump(doc, f, indent=1)
        print(f"\nweights written to {args.write_weights} (provisional={doc['provisional']}, n_per_class={doc['n_per_class']})")
    print(md)
    print(f'\nreport written to {out}/{when}.md and .json')
    return 0


def merge_main(args):
    items, results, meta = merge_reports([json.load(open(p)) for p in args.merge])
    groups = {}
    for i in items:
        groups[i['group']] = groups.get(i['group'], 0) + 1
    wdoc = json.load(open(args.validate_weights)) if getattr(args, 'validate_weights', None) else None
    ev = evaluate(items, results, load_consensus_fn(), wdoc)
    return emit(args, items, results, meta, ev, groups, tag='-merged')


def main(argv=None):
    """Command-line entry point: build the indicator set, ask every provider, score the answers and write the report."""
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0], formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--n', type=int, default=15, help='indicators per class (malicious and benign), default 15')
    ap.add_argument('--seed', type=int, default=7)
    ap.add_argument('--local', action='append', help='local Ollama model as label=http://host:11434|model (repeatable)')
    ap.add_argument('--cloud', default='auto', help='comma list of cloud providers, or auto (every provider with a key)')
    ap.add_argument('--skip', default='', help='comma list of providers to leave out')
    ap.add_argument('--rpm', type=int, default=12, help='max calls per minute per cloud provider')
    ap.add_argument('--rpm-for', action='append', default=[], help='per-provider rate override, e.g. gemini=4 (free tiers differ)')
    ap.add_argument('--local-pause', type=float, default=5.0, help='seconds between local-model calls (keeps the CPU cool)')
    ap.add_argument('--max-errors', type=int, default=3, help='abort a provider after this many consecutive errors')
    ap.add_argument('--out', default=None, help='report directory (default backend/instance/benchmarks)')
    ap.add_argument('--urlhaus-file', help='use a saved URLhaus CSV instead of downloading')
    ap.add_argument('--extra', action='append', default=[], help='extra OpenAI-compatible candidate: label=base_url|KEY_ENV|model (repeatable)')
    ap.add_argument('--weights-mode', choices=['strict', 'lenient', 'mean'], default='strict', help='skill measure the weights use (default strict: it raised firm-malicious recall from 50%% to 80%% at 0%% false positives in the 2026-09-19 experiment)')
    ap.add_argument('--validate-weights', help='score THIS run with weights learned earlier (a weights .json): the out-of-sample check')
    ap.add_argument('--write-weights', help='write per-provider vote weights (JSON) computed from this run')
    ap.add_argument('--weights-alias', action='append', default=[], help='map a benchmark provider name to a production name, e.g. ollama:wt-mistral=ollama')
    ap.add_argument('--items-from', help='reuse the indicator set from a previous report .json (makes runs comparable)')
    ap.add_argument('--merge', nargs='+', help='combine report .json files run on the SAME indicators and re-evaluate (no AI calls)')
    ap.add_argument('--dry-run', action='store_true', help='build the dataset and show the plan; call no AI')
    ap.add_argument('--yes', action='store_true', help='allow more than 300 planned calls')
    args = ap.parse_args(argv)

    if args.merge:
        return merge_main(args)
    if args.items_from:
        items = json.load(open(args.items_from))['items']
    else:
        if args.urlhaus_file:
            text = open(args.urlhaus_file, encoding='utf-8', errors='replace').read()
        else:
            import requests
            r = requests.get(URLHAUS_CSV, timeout=60)
            r.raise_for_status()
            text = r.text
        items = build_dataset(parse_urlhaus_csv(text), args.n, args.seed)
    groups = {}
    for i in items:
        groups[i['group']] = groups.get(i['group'], 0) + 1

    local, cloud, prompt_fn, consensus_fn = build_real_providers(args)
    names = [pname(p) for p in local + cloud]
    planned = len(items) * len(names)
    print(f'dataset: {len(items)} items {groups}\nproviders: {names}\nplanned calls: {planned}')
    if args.dry_run:
        for i in items[:6]:
            print(' ', i['group'], i['url'][:80])
        return 0
    if not names:
        print('no providers available', file=sys.stderr)
        return 2
    if planned > 300 and not args.yes:
        print('more than 300 calls planned: rerun with --yes', file=sys.stderr)
        return 2

    rpm_for = {k: int(v) for k, v in (x.split('=', 1) for x in args.rpm_for)}
    cfg = {'rpm': args.rpm, 'rpm_for': rpm_for, 'local_pause': args.local_pause, 'max_errors': args.max_errors, 'progress': True}
    results, meta = run_benchmark(items, local, cloud, prompt_fn, cfg)
    wdoc = json.load(open(args.validate_weights)) if getattr(args, 'validate_weights', None) else None
    ev = evaluate(items, results, consensus_fn, wdoc)
    return emit(args, items, results, meta, ev, groups)

if __name__ == '__main__':
    sys.exit(main())
