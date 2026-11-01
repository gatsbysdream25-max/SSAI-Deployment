"""Fleet view: which version is each machine running, and does it match what this hub expects?

Machines tell the hub their version in the register and heartbeat calls they already make. The hub only RECORDS and
COMPARES it here; nothing in this file tells a machine to do anything. Updating stays an act on the machine itself
(deploy/update.sh on Linux, re-running the installer on Windows), so a stolen admin login can never push code to the fleet.

Two kinds of machine, two things to compare against:
  * a Linux machine runs the same code as this hub, so it should report the same version as the hub;
  * a Windows PC runs the small agent in windows_agent/, which has its own version number, kept in that package.
"""
import os
import re

_BACKEND = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_BACKEND)
_WINDOWS_VERSION_LINE = re.compile(r'^__version__\s*=\s*["\']([^"\']+)["\']', re.MULTILINE)
_UNSAFE = re.compile(r'[^A-Za-z0-9._ ()+-]')

CURRENT = 'current'          # matches what the hub expects
DIFFERENT = 'different'      # reports a version, but not the expected one: time to update that machine
UNKNOWN = 'unknown'          # the machine reports no version (an older agent) or the hub cannot tell what to expect


def clean_version(text):
    """A version string safe to store and show: a short run of letters, digits and . _ - + ( ). Anything else is dropped."""
    return _UNSAFE.sub('', str(text or ''))[:40].strip()


def hub_version():
    """The version this hub runs (the same text a Linux machine reports about itself)."""
    from agents.lineage import code_version
    return code_version()


def windows_agent_version():
    """The Windows agent version shipped in this hub's package, or '' if the package has no windows_agent folder."""
    path = os.path.join(_ROOT, 'windows_agent', 'ssai_agent', '__init__.py')
    try:
        with open(path, encoding='utf-8') as handle:
            found = _WINDOWS_VERSION_LINE.search(handle.read())
    except OSError:
        return ''
    return found.group(1) if found else ''


def expected_version(platform):
    """What a machine of this platform should be running, or '' when the hub cannot say."""
    if str(platform or '').lower().startswith('windows'):
        return windows_agent_version()
    return hub_version()


def version_state(reported, expected):
    """CURRENT, DIFFERENT or UNKNOWN. 'unknown' on either side never counts as a mismatch: the hub must not nag about a
    difference it cannot see."""
    if not reported or reported == 'unknown' or not expected or expected == 'unknown':
        return UNKNOWN
    return CURRENT if reported == expected else DIFFERENT


def describe(node):
    """The three fleet fields for one machine's dict: version, expected_version, version_state."""
    expected = expected_version(node.get('platform'))
    reported = node.get('version') or ''
    return {'version': reported, 'expected_version': expected, 'version_state': version_state(reported, expected)}
