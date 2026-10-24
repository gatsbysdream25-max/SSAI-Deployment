"""Single source of truth for every filesystem path the app touches.

DATA_DIR defaults to the directory this code is installed in (deploy/install.sh
also sets it explicitly for the services); a Docker container sets
DATA_DIR=/data instead and gets a clean, generic layout with no other code
changes needed.
"""
import os

# The install's own directory (the one holding backend/). It used to be hard-coded to the lab's /mnt/ssd/SwarmSentinel,
# so any tool run by hand on another machine (no DATA_DIR in its environment) read and wrote the wrong place; found by
# the first clean-machine sandbox install, 2026-10-10. The services and Docker still set DATA_DIR explicitly.
CODE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.environ.get('DATA_DIR') or CODE_DIR

ENV_PATH = os.path.join(DATA_DIR, '.env')

BACKEND_DIR       = os.path.join(DATA_DIR, 'backend')
INSTANCE_DIR      = os.path.join(BACKEND_DIR, 'instance')
DB_PATH           = os.path.join(INSTANCE_DIR, 'swarmsentinel.db')
SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', f'sqlite:///{DB_PATH}')

ALLOWLIST_PATH      = os.path.join(INSTANCE_DIR, 'allowlist.json')
GITHUB_STATE_PATH   = os.path.join(INSTANCE_DIR, 'github_reporter_state.json')
QUARANTINE_DROPBOX_PATH = os.path.join(INSTANCE_DIR, 'quarantine_dropbox.json')

LOG_DIR  = os.path.join(DATA_DIR, 'logs')
LOG_PATH = os.path.join(LOG_DIR, 'agents.log')

# Where github_reporter.py's git clone/commit/push lives. Kept as DATA_DIR
# itself by default so the live boxes (which already run this as their
# git checkout root) are unaffected; a Docker container gets a dedicated
# subdirectory instead since /data is not itself a git repo there.
THREAT_INTEL_REPO = os.environ.get(
    'THREAT_INTEL_REPO_DIR',
    DATA_DIR if DATA_DIR == CODE_DIR else os.path.join(DATA_DIR, 'threat-intel-repo'),
)


def ensure_dirs():
    """Idempotent — safe to call on every boot."""
    os.makedirs(INSTANCE_DIR, exist_ok=True)
    os.makedirs(LOG_DIR, exist_ok=True)
    os.makedirs(THREAT_INTEL_REPO, exist_ok=True)
