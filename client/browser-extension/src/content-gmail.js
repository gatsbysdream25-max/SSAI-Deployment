'use strict';
// SwarmSentinel Shield: Gmail part. It reads nothing unless a person has turned the extension on. When on, it looks for common
// phishing signals in the message you have open, and reports ONLY the signals and the host name of a suspicious link. The
// subject, sender, recipient and text of your mail never leave this page.

const api = globalThis.browser || globalThis.chrome;

const PHISHING_KEYWORDS = [
  'verify your account', 'confirm your identity', 'your account has been suspended', 'unusual sign-in activity',
  'click here to unlock', 'update your payment', 'your account will be closed', 'action required', 'validate your email',
  'we detected suspicious', 'reset your password immediately', 'your account is at risk', 'wire transfer', 'gift card',
  'send bitcoin', 'urgent transfer',
];
const SHORTENERS = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'short.link', 'rebrand.ly'];
const RISKY_FILES = ['.exe', '.zip', '.rar', '.bat', '.cmd', '.scr', '.vbs'];

function scoreMessage(subject, body) {
  let score = 0;
  const flags = [];
  let host = '';
  const text = (subject + ' ' + body).toLowerCase();
  for (const kw of PHISHING_KEYWORDS) if (text.includes(kw)) { score += 20; flags.push('keyword: ' + kw); }
  for (const url of new Set(body.match(/https?:\/\/[^\s"'<>()]+/gi) || [])) {
    try {
      const h = new URL(url).hostname;
      if (SHORTENERS.some(d => h === d || h.endsWith('.' + d))) { score += 30; flags.push('link shortener: ' + h); host = host || h; }
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) { score += 40; flags.push('link to a raw address'); host = host || h; }
    } catch (_) { /* not a valid link */ }
  }
  for (const ext of RISKY_FILES) if (text.includes(ext)) { score += 25; flags.push('risky attachment type: ' + ext); }
  return { score, flags, host };
}

function severityOf(score) {
  return score >= 60 ? 'high' : score >= 30 ? 'medium' : score >= 15 ? 'low' : null;
}

const seen = new Set();                                              // in memory only, gone when the tab closes
let on = false;

function scan() {
  if (!on) return;
  for (const thread of document.querySelectorAll('[data-legacy-thread-id]')) {
    const id = thread.getAttribute('data-legacy-thread-id');
    const bodyEl = thread.querySelector('.a3s, .ii.gt');
    if (seen.has(id) || !bodyEl) continue;
    const subjectEl = document.querySelector('h2.hP');
    const body = bodyEl.innerText || '';
    if (!body.trim()) continue;
    seen.add(id);
    const { score, flags, host } = scoreMessage(subjectEl ? subjectEl.innerText || '' : '', body);
    const severity = severityOf(score);
    if (!severity) continue;
    api.runtime.sendMessage({ type: 'SUBMIT_THREAT', data: { severity, flags, host } }).catch(() => {});
    if (subjectEl && !subjectEl.querySelector('.ssai-badge')) {
      const badge = document.createElement('span');
      badge.className = 'ssai-badge';
      badge.textContent = ' SSAI: ' + severity.toUpperCase() + ' RISK';
      badge.style.cssText = 'color:#ff1a3c;font-weight:bold;font-size:11px;margin-left:8px;';
      subjectEl.appendChild(badge);
    }
  }
}

async function start() {
  const { enabled } = await api.storage.local.get('enabled');
  on = enabled === true;                                             // off unless a person turned it on
  scan();
}

api.storage.onChanged.addListener(changes => { if (changes.enabled) { on = changes.enabled.newValue === true; scan(); } });
new MutationObserver(scan).observe(document.body, { childList: true, subtree: true });
start();
