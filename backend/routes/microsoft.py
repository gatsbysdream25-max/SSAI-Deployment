"""The Microsoft Copilot / Teams settings: where a person adds their own Entra ID and Azure bot details (2026-11-04).

    GET  /api/settings/microsoft    what is set (secrets are never sent back, only whether they are set)
    POST /api/settings/microsoft    save any of the fields below; an empty field is left alone, "clear" removes them all

The hub's own settings go to the hub .env (the same names backend/entra.py reads):
    SSAI_COPILOT_KEY, SSAI_COPILOT_TENANT_ID, SSAI_COPILOT_AUDIENCE, SSAI_COPILOT_APPROVERS
The Azure bot's credentials go to copilot/.env, which only the separate Copilot service reads (owner-only file):
    MICROSOFT_APP_ID and the Agents SDK names CONNECTIONS__SERVICE_CONNECTION__SETTINGS__{CLIENTID,CLIENTSECRET,TENANTID}

Admin only (a signed-in person or the admin key). The hub restarts itself a moment after saving so every worker sees the new
values; the Copilot service is started separately and reads its file when it starts. Nothing here talks to Microsoft: a wrong
value is caught the first time the bot signs in, and the test of that is the Teams "status" message (copilot/README.md).
"""
import os
import re
import secrets
import subprocess

from flask import Blueprint, jsonify, request

import auth as _auth
import envfile

microsoft_bp = Blueprint("microsoft", __name__)

_GUID = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
_AUDIENCE = re.compile(r'^(?:[0-9a-fA-F-]{36}|api://[\w.\-:/]{1,200})$')
_BOT_SECRET_MAX = 256

_HUB_KEYS = ('SSAI_COPILOT_KEY', 'SSAI_COPILOT_TENANT_ID', 'SSAI_COPILOT_AUDIENCE', 'SSAI_COPILOT_APPROVERS')
_BOT_PREFIX = 'CONNECTIONS__SERVICE_CONNECTION__SETTINGS__'
_BOT_KEYS = ('MICROSOFT_APP_ID', _BOT_PREFIX + 'CLIENTID', _BOT_PREFIX + 'CLIENTSECRET', _BOT_PREFIX + 'TENANTID')


def _hub_env_path():
    """The hub's .env, looked up when needed: app.py owns the setting and tests point it somewhere else."""
    from app import _ENV_PATH
    return _ENV_PATH


def _bot_env_path():
    """copilot/.env beside the hub's .env (the Copilot service reads this one)."""
    return os.path.join(os.path.dirname(os.path.abspath(_hub_env_path())), 'copilot', '.env')


def _read(path):
    """KEY=value lines of an env file as a dict ({} if it is missing)."""
    values = {}
    try:
        with open(path, encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    k, v = line.split('=', 1)
                    values[k.strip()] = v.strip()
    except OSError:
        pass
    return values


def _guid_list(text, label):
    """Split a comma/space separated list of Entra object ids; each must be a GUID."""
    items = [x for x in re.split(r'[,\s]+', text or '') if x]
    for item in items:
        if not _GUID.match(item):
            raise ValueError(f'{label}: "{item[:40]}" is not an id like 11111111-2222-3333-4444-555555555555')
    return [i.lower() for i in items]


def _plan(body, hub, bot):
    """Check the submitted fields and return (hub_updates, bot_updates, notes). Raises ValueError with a plain message."""
    hub_up, bot_up, notes = {}, {}, []
    tenant = (body.get('tenant_id') or '').strip()
    if tenant:
        if not _GUID.match(tenant):
            raise ValueError('Tenant ID must look like 11111111-2222-3333-4444-555555555555 (Entra admin center, Overview)')
        hub_up['SSAI_COPILOT_TENANT_ID'] = tenant.lower()
        bot_up[_BOT_PREFIX + 'TENANTID'] = tenant.lower()
    app_id = (body.get('app_id') or '').strip()
    if app_id:
        if not _GUID.match(app_id):
            raise ValueError('Application (client) ID must look like 11111111-2222-3333-4444-555555555555')
        bot_up['MICROSOFT_APP_ID'] = app_id.lower()
        bot_up[_BOT_PREFIX + 'CLIENTID'] = app_id.lower()
        if not (body.get('audience') or '').strip() and not hub.get('SSAI_COPILOT_AUDIENCE'):
            hub_up['SSAI_COPILOT_AUDIENCE'] = app_id.lower()          # the usual audience is the app's own id
    audience = (body.get('audience') or '').strip()
    if audience:
        parts = [p for p in re.split(r'[,\s]+', audience) if p]
        if not parts or not all(_AUDIENCE.match(p) for p in parts):
            raise ValueError('Audience must be the app (client) ID and/or an api://... address, separated by commas')
        hub_up['SSAI_COPILOT_AUDIENCE'] = ','.join(parts)
    approvers = body.get('approvers')
    if isinstance(approvers, list):
        approvers = ','.join(str(a) for a in approvers)
    if (approvers or '').strip():
        hub_up['SSAI_COPILOT_APPROVERS'] = ','.join(_guid_list(approvers, 'Approvers'))
    secret = body.get('app_secret')
    if isinstance(secret, str) and secret.strip():
        secret = secret.strip()
        if len(secret) > _BOT_SECRET_MAX or any(c in secret for c in '\n\r\x00') or ' ' in secret:
            raise ValueError('The client secret looks wrong (one line, no spaces, under 256 characters). Copy the secret VALUE, not its ID')
        bot_up[_BOT_PREFIX + 'CLIENTSECRET'] = secret
    if body.get('generate_key') or (not hub.get('SSAI_COPILOT_KEY') and (hub_up or bot_up)):
        key = secrets.token_urlsafe(32)
        hub_up['SSAI_COPILOT_KEY'] = key
        bot_up['SSAI_COPILOT_KEY'] = key
        notes.append('A new lane key was made and written to both files; the bot and the hub always share it.')
    elif hub.get('SSAI_COPILOT_KEY') and (hub_up or bot_up) and bot.get('SSAI_COPILOT_KEY') != hub['SSAI_COPILOT_KEY']:
        bot_up['SSAI_COPILOT_KEY'] = hub['SSAI_COPILOT_KEY']             # keep the two files in step
    hub_url = (body.get('hub_url') or '').strip()
    if hub_url:
        if not re.match(r'^https?://[A-Za-z0-9.\-\[\]:]{1,253}(?::\d{1,5})?$', hub_url):
            raise ValueError('Hub address must look like http://192.168.1.10:5000')
        bot_up['SSAI_HUB_URL'] = hub_url
    return hub_up, bot_up, notes


def _state():
    """What is set, without any secret."""
    hub = _read(_hub_env_path())
    bot = _read(_bot_env_path())
    return {
        'tenant_id': hub.get('SSAI_COPILOT_TENANT_ID', ''),
        'audience': hub.get('SSAI_COPILOT_AUDIENCE', ''),
        'approvers': [a for a in hub.get('SSAI_COPILOT_APPROVERS', '').split(',') if a],
        'lane_key_set': bool(hub.get('SSAI_COPILOT_KEY')),
        'app_id': bot.get('MICROSOFT_APP_ID', ''),
        'app_secret_set': bool(bot.get(_BOT_PREFIX + 'CLIENTSECRET')),
        'hub_url': bot.get('SSAI_HUB_URL', ''),
        'approvals_from_teams': bool(hub.get('SSAI_COPILOT_TENANT_ID') and hub.get('SSAI_COPILOT_AUDIENCE')
                                     and hub.get('SSAI_COPILOT_APPROVERS')),
    }


@microsoft_bp.route('/api/settings/microsoft', methods=['GET'])
def get_microsoft():
    """What the Copilot / Teams connection has so far (never the key or the secret, only whether they are set)."""
    if not _auth.is_admin():
        return jsonify({'error': 'Unauthorized'}), 401
    return jsonify(_state())


def _restart_hub_soon():
    """Restart the dashboard in two seconds (after this reply is sent) so every worker reads the new .env. False when this
    machine does not allow it; the settings are saved either way."""
    try:
        subprocess.Popen(['sh', '-c', 'sleep 2; sudo -n /usr/bin/systemctl restart swarmsentinel'],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        return True
    except OSError:
        return False


@microsoft_bp.route('/api/settings/microsoft', methods=['POST'])
def save_microsoft():
    """Save the Entra / Azure bot fields (empty ones are left as they are), or {"clear": true} to remove them all."""
    if not _auth.is_admin():
        return jsonify({'error': 'Unauthorized'}), 401
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({'error': 'expected a JSON object'}), 400
    hub_path, bot_path = _hub_env_path(), _bot_env_path()
    if body.get('clear') is True:
        return _clear(hub_path, bot_path)
    hub, bot = _read(hub_path), _read(bot_path)
    try:
        hub_up, bot_up, notes = _plan(body, hub, bot)
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    if not hub_up and not bot_up:
        return jsonify({'error': 'nothing to change'}), 400
    try:
        for key in hub_up:
            envfile.check(key, hub_up[key])
        for key in bot_up:
            envfile.check(key, bot_up[key])
        if hub_up:
            envfile.set_values(hub_path, hub_up)
        if bot_up:
            envfile.set_values(bot_path, bot_up)
    except envfile.EnvError as exc:
        return jsonify({'error': str(exc)}), 400
    except OSError as exc:
        return jsonify({'error': f'Could not write the settings file: {exc.strerror or exc}. '
                                 f'The account running SwarmSentinel must own {os.path.dirname(os.path.abspath(hub_path))}',
                        'fix': f'sudo chown -R "$USER": {os.path.dirname(os.path.abspath(hub_path))}'}), 500
    for key, value in hub_up.items():
        os.environ[key] = value
    return jsonify({'ok': True, 'restarting': _restart_hub_soon(), 'notes': notes, **_state()})


def _clear(hub_path, bot_path):
    """Remove every Microsoft setting from both files (so approvals from Teams and the Copilot lane switch off)."""
    try:
        for path, keys in ((hub_path, _HUB_KEYS), (bot_path, _BOT_KEYS + ('SSAI_COPILOT_KEY',))):
            if os.path.exists(path):
                with open(path, encoding='utf-8') as f:
                    kept = [ln for ln in f.read().splitlines() if ln.split('=', 1)[0].strip() not in keys]
                envfile._write_atomic(path, '\n'.join(kept) + ('\n' if kept else ''))
    except OSError as exc:
        return jsonify({'error': f'Could not write the settings file: {exc.strerror or exc}'}), 500
    for key in _HUB_KEYS:
        os.environ.pop(key, None)
    return jsonify({'ok': True, 'restarting': _restart_hub_soon(), 'notes': [], **_state()})

