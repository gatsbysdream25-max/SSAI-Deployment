"""Signing in and out, single sign-on, and changing the admin password (the /login, /logout and /api/admin/password routes).

Who counts as an admin is decided in auth.py; this file only runs the sign-in conversation. Every attempt, good or bad, is written
to the audit file.
"""
from flask import Blueprint, jsonify, make_response, redirect, render_template, request, session

import auth as _auth

login_bp = Blueprint("login", __name__)


def _audit_path():
    """The audit file, looked up when needed: app.py owns it and tests point it somewhere else after start-up."""
    from app import _AUDIT_PATH
    return _AUDIT_PATH


def _safe_next(target):
    """Where to go after login: a path on this site only (no scheme, no //host, no backslash tricks, never /login)."""
    t = str(target or '')
    # Control characters and spaces are refused outright: a browser strips tabs and newlines out of a URL, so "/<TAB>/evil.example"
    # becomes "//evil.example" and leaves the site (found by review, 2026-10-18).
    if any(ord(c) <= 0x20 or ord(c) == 0x7f for c in t):
        return '/dashboard'
    if t.startswith('/') and not t.startswith('//') and '\\' not in t and not t.startswith('/login') and len(t) < 300:
        return t
    return '/dashboard'


@login_bp.route('/login', methods=['GET'])
def login_page():
    """Show the sign-in page, or go straight on when already signed in. The no-store header stops the browser keeping a
    copy of the page."""
    import sso
    nxt = _safe_next(request.args.get('next'))
    if _auth.session_admin():
        return redirect(nxt)
    resp = make_response(render_template('login.html', next=nxt, configured=_auth.load_admin() is not None,
                                              sso=sso.configured(), sso_only=sso.only(), sso_error=request.args.get('sso_error') == '1'))
    resp.headers['Cache-Control'] = 'no-store'
    return resp


@login_bp.route('/login/sso', methods=['GET'])
def sso_start():
    """Send the browser to the identity provider. The one-time values for this attempt live in the signed session
    cookie, so the callback can prove the answer belongs to the attempt this browser started."""
    import sso
    if not sso.configured():
        return redirect('/login')
    flow = sso.new_flow()
    session['sso_flow'] = {**flow, 'next': _safe_next(request.args.get('next'))}
    return redirect(sso.authorize_url(flow))


@login_bp.route('/login/sso/callback', methods=['GET'])
def sso_callback():
    """Where the identity provider sends the browser back after sign-in. It checks this is the attempt this browser
    started (the state value), swaps the code for a verified identity and starts a session. Any failure is audited and
    shows only a generic error."""
    import remediation
    import sso
    ip = _auth.client_ip()
    flow = session.pop('sso_flow', None)

    def refuse(reason):
        remediation.audit(_audit_path(), action='sso-login', ok=False, by=ip, detail=reason)
        return redirect('/login?sso_error=1')

    if not sso.configured() or not isinstance(flow, dict):
        return refuse('no sign-in attempt in progress')
    if request.args.get('error') or not request.args.get('code'):
        return refuse('the identity provider returned an error' if request.args.get('error') else 'no code')
    if not sso.state_matches(request.args.get('state'), flow.get('state')):
        return refuse('state does not match')
    try:
        who = sso.verify_id_token(sso.exchange_code(request.args['code'], flow['verifier']), flow['nonce'])
    except sso.SsoError as exc:
        return refuse(str(exc)[:200])
    _auth.start_sso_session(who['subject'])
    remediation.audit(_audit_path(), action='sso-login', ok=True, by=who['subject'], detail=who['name'])
    return redirect(_safe_next(flow.get('next')))


@login_bp.route('/login', methods=['POST'])
def login_submit():
    """Password sign-in. Failed attempts are counted per address and overall, and too many gets a 429 (wait and retry).
    Every outcome is audited."""
    import remediation
    import sso
    if sso.only():
        return jsonify({'error': 'Password sign-in is turned off on this hub. Use single sign-on.'}), 403
    ip = _auth.client_ip()
    if _auth.login_failures.count(ip) >= _auth.login_failures.limit or _auth.login_failures_all.count('all') >= _auth.login_failures_all.limit:
        resp = jsonify({'error': 'Too many failed sign-in attempts. Wait a few minutes and try again.'})
        resp.status_code = 429
        resp.headers['Retry-After'] = '300'
        return resp
    if _auth.load_admin() is None:
        return jsonify({'error': 'No admin password has been set yet. On the hub machine run: deploy/set-password.sh'}), 503
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        data = request.form
    if not _auth.verify_password(str(data.get('password', ''))):
        _auth.login_failures.hit(ip)
        _auth.login_failures_all.hit('all')
        remediation.audit(_audit_path(), action='login', ok=False, by=ip)
        return jsonify({'error': 'Incorrect password'}), 401
    _auth.start_session()
    remediation.audit(_audit_path(), action='login', ok=True, by=ip)
    return jsonify({'ok': True, 'next': _safe_next(data.get('next'))})


@login_bp.route('/logout', methods=['POST'])
def logout():
    _auth.end_session()
    return jsonify({'ok': True})


@login_bp.route('/api/admin/password', methods=['POST'])
def change_admin_password():
    """Change the admin password (needs the current one). Every other session ends; this one continues."""
    import remediation
    if not _auth.is_admin():
        return jsonify({'error': 'Unauthorized'}), 401
    ip = _auth.client_ip()
    if _auth.login_failures.count(ip) >= _auth.login_failures.limit:
        return jsonify({'error': 'Too many failed attempts. Wait a few minutes.'}), 429
    data = request.get_json(silent=True) or {}
    if _auth.load_admin() is not None and not _auth.verify_password(str(data.get('current', ''))):
        _auth.login_failures.hit(ip)
        remediation.audit(_audit_path(), action='password-change', ok=False, by=ip)
        return jsonify({'error': 'The current password is not correct'}), 403
    was_a_person = _auth.session_admin()     # decided BEFORE the change: afterwards the old session no longer matches
    try:
        _auth.set_admin_password(str(data.get('new', '')))
    except ValueError as e:
        return jsonify({'error': f'The new password is not acceptable: {e}'}), 400
    if was_a_person:
        _auth.start_session()                # the old sessions died with the old password; keep this person signed in
    remediation.audit(_audit_path(), action='password-change', ok=True, by=ip)
    return jsonify({'ok': True})
