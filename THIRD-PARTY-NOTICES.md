# Third-party notices

SwarmSentinel is proprietary software (see `LICENSE`). It depends on the open-source components below, each under its own
licence. This list is generated from the packages installed in the runtime environment on 2026-09-30
(`python gen_notices.py`). It is engineering documentation, not legal advice: have counsel review it before distribution.

## Python packages

| Package | Version | Licence | Project |
|---|---|---|---|
| blinker | 1.9.0 | MIT License | https://github.com/pallets-eco/blinker/ |
| certifi | 2026.7.22 | MPL-2.0 | https://github.com/certifi/python-certifi |
| cffi | 2.1.1 | MIT-0 | https://github.com/python-cffi/cffi |
| charset-normalizer | 3.5.1 | MIT | - |
| click | 8.4.2 | BSD-3-Clause | https://github.com/pallets/click/ |
| cryptography | 50.0.1 | Apache-2.0 OR BSD-3-Clause | https://github.com/pyca/cryptography |
| Flask | 3.1.3 | BSD-3-Clause | https://github.com/pallets/flask/ |
| flask-cors | 6.0.2 | MIT | https://corydolphin.github.io/flask-cors/ |
| Flask-SQLAlchemy | 3.1.1 | BSD License | https://github.com/pallets-eco/flask-sqlalchemy/ |
| greenlet | 3.5.5 | MIT AND PSF-2.0 | https://greenlet.readthedocs.io |
| gunicorn | 26.0.0 | MIT | https://gunicorn.org |
| idna | 3.18 | BSD-3-Clause | https://github.com/kjd/idna |
| itsdangerous | 2.2.0 | BSD License | https://github.com/pallets/itsdangerous/ |
| Jinja2 | 3.1.6 | BSD License | https://github.com/pallets/jinja/ |
| MarkupSafe | 3.0.3 | BSD-3-Clause | https://github.com/pallets/markupsafe/ |
| packaging | 26.3 | Apache-2.0 OR BSD-2-Clause | https://github.com/pypa/packaging |
| pycparser | 3.0 | BSD-3-Clause | https://github.com/eliben/pycparser |
| PyJWT | 2.15.1 | MIT | https://github.com/jpadilla/pyjwt |
| python-dotenv | 1.2.2 | BSD-3-Clause | https://github.com/theskumar/python-dotenv |
| requests | 2.34.2 | Apache-2.0 | https://github.com/psf/requests |
| SQLAlchemy | 2.0.52 | MIT | https://www.sqlalchemy.org |
| typing_extensions | 4.16.0 | PSF-2.0 | https://github.com/python/typing_extensions |
| urllib3 | 2.7.0 | MIT | - |
| Werkzeug | 3.1.8 | BSD-3-Clause | https://github.com/pallets/werkzeug/ |

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

