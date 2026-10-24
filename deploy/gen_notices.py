#!/usr/bin/env python3
"""Generate THIRD-PARTY-NOTICES.md from the packages actually installed in the runtime virtualenv."""
import importlib.metadata as md
import re
import sys
import time

SKIP = {'pip', 'setuptools', 'wheel', 'pkg-resources', 'distro', 'lockfile'}


def licence(metadata):
    """Work out a package's licence name from its metadata, trying the licence expression, the licence field, then the trove classifiers; says UNKNOWN if none gives an answer.
    A long or multi-line licence field is ignored because it is usually the full licence text, not a name.
    """
    licence_name = (metadata.get('License-Expression') or '').strip()
    if not licence_name:
        licence_name = (metadata.get('License') or '').strip()
        if len(licence_name) > 60 or '\n' in licence_name:
            licence_name = ''
    if not licence_name:
        classifiers = [c.split('::')[-1].strip() for c in (metadata.get_all('Classifier') or []) if c.startswith('License ::')]
        licence_name = ', '.join(classifiers)
    return re.sub(r'\s+', ' ', licence_name) or 'UNKNOWN - check upstream'


rows = []
for d in sorted(md.distributions(), key=lambda d: (d.metadata['Name'] or '').lower()):
    name = d.metadata['Name']
    if not name or name.lower() in SKIP:
        continue
    home = (d.metadata.get('Home-page') or '').strip()
    if not home:
        for u in d.metadata.get_all('Project-URL') or []:
            if 'home' in u.lower() or 'source' in u.lower():
                home = u.split(',', 1)[-1].strip()
                break
    rows.append((name, d.version, licence(d.metadata), home))

print(f'''# Third-party notices

SwarmSentinel is proprietary software (see `LICENSE`). It depends on the open-source components below, each under its own
licence. This list is generated from the packages installed in the runtime environment on {time.strftime('%Y-%m-%d')}
(`python gen_notices.py`). It is engineering documentation, not legal advice: have counsel review it before distribution.

## Python packages

| Package | Version | Licence | Project |
|---|---|---|---|''')
for name, ver, lic, home in rows:
    print(f'| {name} | {ver} | {lic} | {home or "-"} |')
    if 'UNKNOWN' in lic:
        print(f'warning: no licence metadata for {name}', file=sys.stderr)

print('''
`certifi` is MPL-2.0 (file-level copyleft). It is used unmodified as a dependency, which does not affect the licence of
SwarmSentinel's own code.

## Operating-system packages in the Docker image

The image installs these from Debian; they are separate programs the application runs, not linked into it.

| Program | Licence | Note |
|---|---|---|
| nmap | Nmap Public Source License (NPSL) | **Restricts redistribution and commercial bundling.** Shipping nmap inside a product you sell needs an OEM licence from Nmap Software, or the customer must install it themselves, or it must be replaced. Unresolved. |
| ufw, iproute2, git, procps, iputils-ping | GPL-2.0 / GPL-3.0 | Used as separate executables; source available from Debian. |
| supervisor | BSD-like (Repoze) | |
| curl | curl licence (MIT-style) | |
| ieee-data | IEEE public registry data | Used to look up device vendors. |
| Python (base image) | PSF licence | |

## External services and data (not bundled)

| Item | Terms | Note |
|---|---|---|
| abuse.ch URLhaus, ThreatFox, Feodo Tracker | CC0 | The only threat feeds used, chosen because CC0 permits commercial use. Do not add feeds under non-commercial terms (for example Spamhaus DROP) without a licence. |
| Groq, Google Gemini, Anthropic, Hugging Face APIs | Each provider's API terms | The customer supplies their own keys; review each provider's terms for commercial resale use. |
| Grafana, Loki, Promtail | AGPL-3.0 | Not distributed with SwarmSentinel; only referenced for an optional monitoring setup. AGPL obligations apply if you modify and offer them over a network. |
| RDAP registry data (rdap.org and the regional registries) | Public registry data | Queried on demand for public IP addresses only. |
| Browser extensions (`client/`) | See the extension folders | Review the permissions requested before store submission. |
''')
