"""Single sign-on for the dashboard admin (OpenID Connect, authorization-code flow with PKCE).

A bank signs its administrators in with its own identity provider (Microsoft Entra ID out of the box, any OIDC
provider with the three URL overrides) instead of a password stored on this machine, so MFA, conditional access and
offboarding are the bank's, not ours. The hub verifies the ID token itself: signature (RS256 only) against the provider's
published keys, issuer, audience (this app), expiry, the one-time nonce it issued, the tenant, and that the person is on
the hub's admin list. A person removed from that list loses the session on their next request.

Settings (hub .env). SSO stays OFF until the first four are set:
    SSAI_SSO_TENANT_ID      the organisation's Entra tenant id (GUID)
    SSAI_SSO_CLIENT_ID      this app's registration (application/client id); it is the token audience
    SSAI_SSO_CLIENT_SECRET  the app registration's client secret (a certificate-based flow is not supported yet)
    SSAI_SSO_REDIRECT_URI   exactly as registered, e.g. https://ssai.bank.example/login/sso/callback
    SSAI_SSO_ADMINS         who may sign in: Entra object ids (oid), comma-separated. The oid is immutable and unique.
                            Empty means NOBODY: an unset list never means "everyone in the tenant".
    SSAI_SSO_ADMINS_BY_NAME=1   also accept sign-in names (UPN/email) on that list. Off by default: Microsoft says
                            preferred_username and email must not be used for authorization (they can be edited or reused, and a
                            guest can carry a chosen address), so use this only if you accept that risk.
    SSAI_SSO_ONLY=1         turn the local admin password off (the API key still works for machines). Ignored unless
                            the admin list is non-empty, so a missing list cannot lock everyone out.
    SSAI_SSO_SESSION_MINUTES  how long a single-sign-on session lasts (default 120, 5 to 720)
    SSAI_SSO_AUTHORIZE_URL / SSAI_SSO_TOKEN_URL / SSAI_SSO_JWKS_URL / SSAI_SSO_ISSUER   optional overrides for a
                            non-Entra OIDC provider (defaults are the Entra v2.0 endpoints for the tenant)
"""
import base64
import hashlib
import hmac
import os
import secrets
from urllib.parse import urlencode

import jwt

import entra

LEEWAY_SECONDS = 60
SCOPE = 'openid profile email'


class SsoError(Exception):
    """The sign-in cannot be accepted. The message is for the audit log, never for the browser."""


def _csv(name):
    return [x.strip().lower() for x in os.environ.get(name, '').split(',') if x.strip()]


def settings():
    """The SSO settings, or None when SSO is off (anything missing = off)."""
    tenant = os.environ.get('SSAI_SSO_TENANT_ID', '').strip().lower()
    client_id = os.environ.get('SSAI_SSO_CLIENT_ID', '').strip()
    secret = os.environ.get('SSAI_SSO_CLIENT_SECRET', '').strip()
    redirect = os.environ.get('SSAI_SSO_REDIRECT_URI', '').strip()
    if not (tenant and client_id and secret and redirect):
        return None
    base = f'https://login.microsoftonline.com/{tenant}'
    return {
        'tenant': tenant, 'client_id': client_id, 'secret': secret, 'redirect': redirect, 'admins': set(_csv('SSAI_SSO_ADMINS')),
        'authorize_url': os.environ.get('SSAI_SSO_AUTHORIZE_URL') or f'{base}/oauth2/v2.0/authorize',
        'token_url': os.environ.get('SSAI_SSO_TOKEN_URL') or f'{base}/oauth2/v2.0/token',
        'jwks_url': os.environ.get('SSAI_SSO_JWKS_URL') or f'{base}/discovery/v2.0/keys',
        'issuers': [os.environ['SSAI_SSO_ISSUER']] if os.environ.get('SSAI_SSO_ISSUER') else [f'{base}/v2.0'],
    }


def configured():
    return settings() is not None


def only():
    """True when the local admin password is switched off. Only ever true while SSO is configured AND someone is on the
    admin list, so a typo or a missing list cannot lock everyone out of the dashboard."""
    cfg = settings()
    return bool(cfg and cfg['admins']) and os.environ.get('SSAI_SSO_ONLY', '').lower() in ('1', 'true', 'yes')


def by_name():
    return os.environ.get('SSAI_SSO_ADMINS_BY_NAME', '').lower() in ('1', 'true', 'yes')


def session_minutes():
    try:
        return max(5, min(720, int(os.environ.get('SSAI_SSO_SESSION_MINUTES', '120'))))
    except ValueError:
        return 120


def is_admin_subject(subject, cfg=None):
    """Is this signed-in subject (the value stored in the session) still on the admin list?"""
    cfg = cfg or settings()
    return bool(cfg and subject and str(subject).lower() in cfg['admins'])


# ── the authorization-code flow ──────────────────────────────────────────────

def new_flow():
    """Fresh one-time values for one sign-in attempt: {'state', 'nonce', 'verifier', 'challenge'}."""
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode('ascii')).digest()).rstrip(b'=').decode('ascii')
    return {'state': secrets.token_urlsafe(32), 'nonce': secrets.token_urlsafe(32), 'verifier': verifier, 'challenge': challenge}


def authorize_url(flow, cfg=None):
    cfg = cfg or settings()
    if cfg is None:
        raise SsoError('single sign-on is not configured on this hub')
    query = urlencode({'client_id': cfg['client_id'], 'response_type': 'code', 'redirect_uri': cfg['redirect'],
                       'response_mode': 'query', 'scope': SCOPE, 'state': flow['state'], 'nonce': flow['nonce'],
                       'code_challenge': flow['challenge'], 'code_challenge_method': 'S256', 'prompt': 'select_account'})
    return f"{cfg['authorize_url']}?{query}"


def state_matches(sent, expected):
    return bool(sent and expected and hmac.compare_digest(str(sent).encode('utf-8'), str(expected).encode('utf-8')))


def exchange_code(code, verifier, cfg=None, post=None):
    """Trade the one-time code for the provider's ID token. `post` is injectable for tests."""
    cfg = cfg or settings()
    if cfg is None:
        raise SsoError('single sign-on is not configured on this hub')
    if post is None:
        import requests
        post = requests.post
    try:
        resp = post(cfg['token_url'], timeout=10, data={
            'grant_type': 'authorization_code', 'code': code, 'redirect_uri': cfg['redirect'],
            'client_id': cfg['client_id'], 'client_secret': cfg['secret'], 'code_verifier': verifier})
        body = resp.json()
    except Exception as exc:       # network failure, bad JSON: the person is told only "sign-in failed"
        raise SsoError(f'token request failed: {type(exc).__name__}') from exc
    if resp.status_code != 200 or not isinstance(body, dict) or not isinstance(body.get('id_token'), str):
        raise SsoError(f"token endpoint refused the code (HTTP {resp.status_code}: {str(body.get('error') if isinstance(body, dict) else '')[:60]})")
    return body['id_token']


def verify_id_token(token, nonce, cfg=None, key_for=None):
    """{'subject', 'name'} for a valid admin's ID token, else SsoError."""
    cfg = cfg or settings()
    if cfg is None:
        raise SsoError('single sign-on is not configured on this hub')
    key_for = key_for or entra._signing_key
    try:
        if jwt.get_unverified_header(token).get('alg') != 'RS256':
            raise SsoError('unexpected token algorithm')
        try:
            key = key_for(token, cfg['jwks_url'])
        except SsoError:
            raise
        except Exception as exc:          # the provider's key list unreachable or unreadable: a refusal, never a 500
            raise SsoError(f'could not get the provider signing keys: {type(exc).__name__}') from exc
        claims = jwt.decode(token, key, algorithms=['RS256'], audience=cfg['client_id'],
                            issuer=cfg['issuers'], leeway=LEEWAY_SECONDS,
                            options={'require': ['exp', 'iat', 'aud', 'iss', 'nonce', 'sub']})
    except entra.TokenError as exc:
        raise SsoError(str(exc)) from exc
    except jwt.PyJWTError as exc:
        raise SsoError(f'invalid ID token: {type(exc).__name__}: {exc}') from exc
    if not state_matches(claims.get('nonce'), nonce):
        raise SsoError('nonce does not match this sign-in attempt')
    if cfg['issuers'] == [f"https://login.microsoftonline.com/{cfg['tenant']}/v2.0"] and str(claims.get('tid', '')).lower() != cfg['tenant']:
        raise SsoError('token from another tenant')
    claim_names = ('oid', 'preferred_username', 'email', 'upn') if by_name() else ('oid',)
    names = {str(claims.get(k, '')).lower() for k in claim_names if claims.get(k)}
    match = names & cfg['admins']
    if not match:
        raise SsoError(f"{sorted(names)[:2]} is not on the admin list")
    # The session keeps the admin-list entry that matched, so removing that entry ends the session (is_admin_subject).
    return {'subject': sorted(match)[0], 'name': str(claims.get('name') or claims.get('preferred_username') or 'unknown')[:60]}
