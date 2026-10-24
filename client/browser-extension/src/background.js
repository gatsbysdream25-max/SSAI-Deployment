'use strict';
// SwarmSentinel Shield: background part. It does nothing at all until a person turns it on AND enrols it with their hub.
//
// What it holds: the hub address and ITS OWN node token (from a single-use enrolment code). It never holds the hub's admin key,
// so a stolen browser profile can report threats and nothing more (audit F-05). What it sends: a short list of signals and the host
// name of a suspicious link. Never the e-mail's subject, sender, recipient or text.

const api = globalThis.browser || globalThis.chrome;
const BROWSER = '__BROWSER__';              // chrome | brave | edge | firefox, filled in by build.py
const MAX_REPORTS_PER_HOUR = 30;
const SEVERITIES = ['low', 'medium', 'high'];

const DEFAULTS = { enabled: false, apiBase: '', nodeId: '', token: '', sent: 0, lastReport: '' };

async function load() {
  return Object.assign({}, DEFAULTS, await api.storage.local.get(Object.keys(DEFAULTS)));
}

// A hub must be reached over HTTPS. Plain http is allowed only for a machine on your own network, and only if you said so.
function checkHub(raw, allowPlain) {
  let u;
  try { u = new URL(raw.trim()); } catch (_) { return { error: 'That is not a web address.' }; }
  const host = u.hostname;
  const own = host === 'localhost' || /^127\./.test(host) || /^10\./.test(host) || /^192\.168\./.test(host) ||
              /^172\.(1[6-9]|2\d|3[01])\./.test(host) || host.endsWith('.local');
  if (u.protocol === 'https:') return { origin: u.origin };
  if (u.protocol === 'http:' && own && allowPlain) return { origin: u.origin };
  if (u.protocol === 'http:' && own) return { error: 'This hub is not using HTTPS. If it is on your own network and you accept that, tick the box.' };
  return { error: 'The hub address must start with https://' };
}

async function enrol(hubUrl, code, allowPlain) {
  const hub = checkHub(hubUrl || '', allowPlain);
  if (hub.error) return { ok: false, error: hub.error };
  let r;
  try {
    r = await fetch(hub.origin + '/api/node/register', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enrollCode: String(code || '').trim(), hostname: 'browser-' + BROWSER, platform: 'browser-' + BROWSER }),
    });
  } catch (_) { return { ok: false, error: 'Could not reach the hub. Check the address and that you allowed access to it.' }; }
  const body = await r.json().catch(() => ({}));
  if (!r.ok || !body.token) return { ok: false, error: body.error || ('The hub refused the code (' + r.status + ').') };
  await api.storage.local.set({ apiBase: hub.origin + '/api', nodeId: body.nodeId, token: body.token });
  return { ok: true, nodeId: body.nodeId };
}

async function status() {
  const s = await load();
  return { enabled: s.enabled, enrolled: !!s.token, nodeId: s.nodeId, hub: s.apiBase.replace(/\/api$/, ''),
           key: s.token ? '...' + s.token.slice(-4) : '', sent: s.sent, lastReport: s.lastReport, browser: BROWSER };
}

async function recentCount() {
  const { recent = [] } = await api.storage.local.get('recent');
  const cutoff = Date.now() - 3600 * 1000;
  const fresh = recent.filter(t => t > cutoff);
  return fresh;
}

async function submit(data) {
  const s = await load();
  if (!s.enabled || !s.token || !s.apiBase) return { ok: false, error: 'off' };
  const fresh = await recentCount();
  if (fresh.length >= MAX_REPORTS_PER_HOUR) return { ok: false, error: 'rate-limited' };
  // The page cannot make this extension send anything it likes: the shape is rebuilt here from a few checked fields.
  const severity = SEVERITIES.includes(data.severity) ? data.severity : 'low';
  const flags = (Array.isArray(data.flags) ? data.flags : []).slice(0, 10).map(f => String(f).slice(0, 80));
  const body = {
    url: String(data.host ? 'https://' + String(data.host).slice(0, 200) + '/' : 'gmail-message').slice(0, 300),
    type: 'phishing-email', severity,
    description: 'Possible phishing e-mail seen in the browser. Signals: ' + (flags.join(', ') || 'none'),
    detected_by: 'browser-extension-' + BROWSER,
  };
  try {
    const r = await fetch(s.apiBase + '/threats/', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-API-Key': s.token }, body: JSON.stringify(body) });
    if (r.status === 401) { await api.storage.local.set({ token: '', enabled: false }); return { ok: false, error: 'credential-revoked' }; }
    if (!r.ok) return { ok: false, error: 'hub ' + r.status };
  } catch (_) { return { ok: false, error: 'unreachable' }; }
  fresh.push(Date.now());
  await api.storage.local.set({ recent: fresh, sent: s.sent + 1, lastReport: new Date().toISOString() });
  return { ok: true };
}

async function heartbeat() {
  const s = await load();
  if (!s.enabled || !s.token) return;
  try { await fetch(s.apiBase + '/node/heartbeat', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-API-Key': s.token }, body: '{}' }); } catch (_) { /* hub down: try again later */ }
}

api.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  const fromPopup = !sender.tab;                                    // only the extension's own popup may change settings
  const run = async () => {
    switch (msg && msg.type) {
      case 'STATUS': return fromPopup ? status() : { enabled: (await load()).enabled };
      case 'ENROL': return fromPopup ? enrol(msg.hubUrl, msg.code, !!msg.allowPlain) : { ok: false };
      case 'SET_ENABLED': {
        if (!fromPopup) return { ok: false };
        const s = await load();
        if (msg.enabled && !s.token) return { ok: false, error: 'Enrol with your hub first.' };
        await api.storage.local.set({ enabled: !!msg.enabled });
        return { ok: true };
      }
      case 'DISCONNECT': if (!fromPopup) return { ok: false }; await api.storage.local.clear(); return { ok: true };
      case 'SUBMIT_THREAT': return sender.tab ? submit(msg.data || {}) : { ok: false };
      default: return { ok: false };
    }
  };
  run().then(sendResponse, () => sendResponse({ ok: false }));
  return true;                                                      // the answer is sent asynchronously
});

api.alarms.create('heartbeat', { periodInMinutes: 5 });
api.alarms.onAlarm.addListener(a => { if (a.name === 'heartbeat') heartbeat(); });
