"""Who pressed Approve in Teams? Verify a Microsoft Entra ID user token (2026-09-30).

Approving a block from Teams must never rest on the Copilot lane key alone: that key lives with the agent in
Microsoft's cloud, and whoever holds it could otherwise block anything. So the agent forwards the signed-in person's own
Entra token (Teams single sign-on), and the hub checks it here: signature against Microsoft's published keys, issuer
and tenant, audience, expiry, and that the person's object id is on the hub's approver list.

Settings (hub .env). Approvals from Teams stay OFF until all three are set:
    SSAI_COPILOT_TENANT_ID   the organisation's Entra tenant id (GUID)
    SSAI_COPILOT_AUDIENCE    accepted token audience(s), comma-separated: the agent's app (client) id and/or its
                             Application ID URI (api://...)
    SSAI_COPILOT_APPROVERS   Entra object ids (oid) of the people allowed to approve or reject, comma-separated
    SSAI_COPILOT_JWKS_URL    optional; default https://login.microsoftonline.com/<tenant>/discovery/v2.0/keys
"""
import os
import threading

import jwt

LEEWAY_SECONDS = 60


class TokenError(Exception):
    """The token is missing, invalid, from the wrong place, or not an approver's. The message is for the audit log."""


def _csv(name):
    return [x.strip() for x in os.environ.get(name, '').split(',') if x.strip()]


def settings():
    """The approval settings, or None when approvals from Teams are off (anything missing = off)."""
    tenant = os.environ.get('SSAI_COPILOT_TENANT_ID', '').strip().lower()
    audiences = _csv('SSAI_COPILOT_AUDIENCE')
    approvers = {a.lower() for a in _csv('SSAI_COPILOT_APPROVERS')}
    if not (tenant and audiences and approvers):
        return None
    return {
        'tenant': tenant, 'audiences': audiences, 'approvers': approvers,
        'issuers': [f'https://login.microsoftonline.com/{tenant}/v2.0', f'https://sts.windows.net/{tenant}/'],
        'jwks_url': os.environ.get('SSAI_COPILOT_JWKS_URL')
                    or f'https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys',
    }


_clients, _clients_lock = {}, threading.Lock()


def _signing_key(token, jwks_url):
    """Microsoft's current public key for this token (the key set is fetched once and cached for a day)."""
    with _clients_lock:
        client = _clients.get(jwks_url)
        if client is None:
            client = _clients[jwks_url] = jwt.PyJWKClient(jwks_url, cache_keys=True, lifespan=86400, timeout=10)
    try:
        return client.get_signing_key_from_jwt(token).key
    except jwt.PyJWKClientError as exc:
        raise TokenError(f'signing key not found: {exc}') from exc


def verify(token, cfg=None, key_for=None):
    """{'oid', 'name', 'tid'} for a valid approver's token, else TokenError."""
    key_for = key_for or _signing_key
    cfg = cfg or settings()
    if cfg is None:
        raise TokenError('approvals from Teams are not configured on this hub')
    if not token or not isinstance(token, str):
        raise TokenError('no user token')
    try:
        if jwt.get_unverified_header(token).get('alg') != 'RS256':
            raise TokenError('unexpected token algorithm')
        claims = jwt.decode(token, key_for(token, cfg['jwks_url']), algorithms=['RS256'],
                            audience=cfg['audiences'], issuer=cfg['issuers'], leeway=LEEWAY_SECONDS,
                            options={'require': ['exp', 'iat', 'aud', 'iss', 'tid', 'oid']})
    except jwt.PyJWTError as exc:
        raise TokenError(f'invalid token: {type(exc).__name__}: {exc}') from exc
    if str(claims.get('tid', '')).lower() != cfg['tenant']:
        raise TokenError('token from another tenant')
    if claims.get('idtyp') == 'app':
        raise TokenError('an application token, not a person')
    oid = str(claims.get('oid', '')).lower()
    if oid not in cfg['approvers']:
        raise TokenError(f'{oid} is not on the approver list')
    name = str(claims.get('name') or claims.get('preferred_username') or 'unknown')
    return {'oid': oid, 'name': name[:60], 'tid': cfg['tenant']}
