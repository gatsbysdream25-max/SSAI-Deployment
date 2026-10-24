'use strict';
// The popup is the only place settings change. It asks the browser for access to ONE address (the hub) when you connect.

const api = globalThis.browser || globalThis.chrome;
const $ = id => document.getElementById(id);
const say = (text, bad) => { $('msg').textContent = text; $('msg').className = bad ? 'bad' : ''; };
const ask = msg => api.runtime.sendMessage(msg);

async function refresh() {
  const s = await ask({ type: 'STATUS' });
  $('on').checked = !!s.enabled;
  $('on').disabled = !s.enrolled;
  $('enrol').hidden = s.enrolled;
  $('connected').hidden = !s.enrolled;
  $('state').textContent = s.enrolled
    ? (s.enabled ? 'On: checking Gmail and reporting to your hub.' : 'Connected, but turned off.')
    : 'Off. Connect to your hub to use it.';
  if (s.enrolled) { $('node').textContent = s.nodeId; $('key').textContent = s.key; $('sent').textContent = s.sent; }
}

$('enrolBtn').addEventListener('click', async () => {
  const hubUrl = $('hub').value.trim();
  let origin;
  try { origin = new URL(hubUrl).origin + '/*'; } catch (_) { return say('That is not a web address.', true); }
  // Ask the browser for access to this one address, from a click, so the person sees exactly what they allow.
  let granted = false;
  try { granted = await api.permissions.request({ origins: [origin] }); } catch (_) { granted = false; }
  if (!granted) return say('Access to the hub was not allowed, so it cannot connect.', true);
  const r = await ask({ type: 'ENROL', hubUrl, code: $('code').value, allowPlain: $('plain').checked });
  if (!r.ok) return say(r.error || 'Could not connect.', true);
  $('code').value = '';
  say('Connected. It stays off until you tick the box above.');
  refresh();
});

$('on').addEventListener('change', async () => {
  const r = await ask({ type: 'SET_ENABLED', enabled: $('on').checked });
  if (!r.ok) say(r.error || 'Could not change that.', true);
  refresh();
});

$('disconnectBtn').addEventListener('click', async () => {
  await ask({ type: 'DISCONNECT' });
  say('Disconnected. Ask your administrator to revoke this browser in the dashboard too.');
  refresh();
});

refresh();
