'use strict';
// SwarmSentinel Shield: Gmail part. It reads nothing unless a person has turned the extension on. When on, it looks for common
// phishing signals in each message you OPEN (Gmail shows a message's text only once it is opened), and reports ONLY the signals
// and the host name of a suspicious link. The subject, sender, recipient and text of your mail never leave this page.
//
// 2026-11-18 rewrite: it used to look for the message text inside the element that carries the thread id (Gmail's subject
// heading), where there is none, so it could skip every message; and it read links only when the address was written out in
// the text, while phishing hides it behind "Click here" (and Gmail rewrites it through google.com/url?q=...).
//
// What is reported (owner's rules, 2026-11-18):
//   * it looks only right after the person acts (opens a message, clicks, presses a key), never on its own;
//   * a message in Gmail's Spam folder is ALREADY handled by Gmail: one low record, stored as resolved ("spam");
//   * a message elsewhere with warning signs is reported by its signs ("open");
//   * a click on a link inside a message that shows warning signs, or inside a spam message, is the moment of real danger:
//     reported as high and left open ("click"). A click in an ordinary message is never reported.

const api = globalThis.browser || globalThis.chrome;

const PHISHING_KEYWORDS = [
  'verify your account', 'confirm your identity', 'your account has been suspended', 'unusual sign-in activity',
  'click here to unlock', 'update your payment', 'your account will be closed', 'action required', 'validate your email',
  'we detected suspicious', 'reset your password immediately', 'your account is at risk', 'wire transfer', 'gift card',
  'send bitcoin', 'urgent transfer', 'account has been locked', 'unusual activity', 'payment was declined',
  'payment failed', 'confirm your password', 'verify your identity', 'suspended your account', 'final notice',
  'your subscription has expired', 'renewal has been processed', 'claim your prize', 'you have won', 'tax refund',
  'delivery attempt failed', 'package could not be delivered', 'customs fee', 'invoice attached', 'outstanding invoice',
  'login attempt', 'security alert', 'limited access', 'restore access', 'within 24 hours', 'within 48 hours',
];
const SHORTENERS = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'short.link', 'rebrand.ly',
  'cutt.ly', 'shorturl.at', 'rb.gy', 't.ly', 'tiny.cc'];
const RISKY_FILES = ['.exe', '.zip', '.rar', '.bat', '.cmd', '.scr', '.vbs', '.js', '.iso', '.img', '.html', '.htm'];
// A sender name that claims one of these, from an address on another domain, is the classic impersonation.
const BRANDS = {
  paypal: ['paypal.com'], amazon: ['amazon.com', 'amazon.co.uk', 'amazonses.com'], apple: ['apple.com', 'icloud.com'],
  microsoft: ['microsoft.com', 'outlook.com', 'office.com', 'live.com'], netflix: ['netflix.com'], google: ['google.com'],
  'wells fargo': ['wellsfargo.com'], chase: ['chase.com', 'jpmorgan.com'], 'bank of america': ['bankofamerica.com', 'bofa.com'],
  usps: ['usps.com'], fedex: ['fedex.com'], ups: ['ups.com'], dhl: ['dhl.com'], 'geek squad': ['geeksquad.com', 'bestbuy.com'],
  norton: ['norton.com', 'nortonlifelock.com', 'gen.digital'], mcafee: ['mcafee.com'], coinbase: ['coinbase.com'],
  irs: ['irs.gov'], docusign: ['docusign.com', 'docusign.net'], facebook: ['facebook.com', 'facebookmail.com', 'meta.com'],
  instagram: ['instagram.com', 'facebookmail.com'], walmart: ['walmart.com'], costco: ['costco.com'],
};

// Gmail sends clicks through https://www.google.com/url?q=<real link>; judge the real link.
function realLink(href) {
  try {
    const u = new URL(href);
    if ((u.hostname === 'www.google.com' || u.hostname === 'google.com') && u.pathname === '/url') {
      return u.searchParams.get('q') || u.searchParams.get('url') || href;
    }
    return href;
  } catch (_) { return href; }
}

function hostOf(url) {
  try { return new URL(url).hostname.toLowerCase(); } catch (_) { return ''; }
}

function sameSite(a, b) {
  const tail = h => h.split('.').slice(-2).join('.');
  return !!a && !!b && tail(a) === tail(b);
}

// links: [{href, text}], sender: {name, email}; returns {score, flags, host}
function scoreMessage(subject, body, links, sender, inSpam) {
  let score = 0;
  const flags = [];
  let host = '';
  const add = (points, flag, h) => { if (flags.includes(flag)) return; score += points; flags.push(flag); if (h && !host) host = h; };
  const text = (subject + ' ' + body).toLowerCase();
  for (const kw of PHISHING_KEYWORDS) if (text.includes(kw)) add(20, 'keyword: ' + kw);

  const written = (body.match(/https?:\/\/[^\s"'<>()]+/gi) || []).map(u => ({ href: u, text: '' }));
  for (const link of written.concat(links || [])) {
    const url = realLink(link.href);
    const shown = (link.text || '').trim();
    const h = hostOf(url);
    if (!h) continue;
    if (SHORTENERS.some(d => h === d || h.endsWith('.' + d))) add(30, 'link shortener: ' + h, h);
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h) || h.startsWith('[')) add(40, 'link to a raw address', h);
    if (h.startsWith('xn--') || h.includes('.xn--')) add(30, 'look-alike (punycode) link: ' + h, h);
    const looksLikeAddress = /^(https?:\/\/)?([a-z0-9-]+\.)+[a-z]{2,}(\/\S*)?$/i.test(shown);
    const shownHost = looksLikeAddress ? hostOf(shown.startsWith('http') ? shown : 'https://' + shown) : '';
    if (shownHost && !sameSite(shownHost, h)) add(40, 'link text shows ' + shownHost + ' but goes to another site', h);
  }
  for (const ext of RISKY_FILES) if (new RegExp('\\w\\' + ext + '\\b').test(text)) add(25, 'risky attachment type: ' + ext);

  const name = ((sender && sender.name) || '').toLowerCase();
  const domain = (((sender && sender.email) || '').split('@')[1] || '').toLowerCase();
  if (name && domain) {
    for (const [brand, domains] of Object.entries(BRANDS)) {
      if (new RegExp('\\b' + brand + '\\b').test(name) && !domains.some(d => domain === d || domain.endsWith('.' + d))) {
        add(40, 'sender name says ' + brand + ' but the address is from another domain');
        break;
      }
    }
  }
  if (inSpam) add(20, 'Gmail put it in Spam');
  return { score, flags, host };
}

function severityOf(score) {
  return score >= 60 ? 'high' : score >= 30 ? 'medium' : score >= 15 ? 'low' : null;
}

const seen = new Set();                                              // in memory only, gone when the tab closes
const verdicts = new Map();                                          // message key -> {flags, host, risky}, for link clicks
let on = false;
let lastAction = 0;                                                  // when the person last clicked or pressed a key
const ACTION_WINDOW_MS = 15000;                                      // Gmail draws an opened message within a few seconds

function messageKey(bodyEl, body) {
  const holder = bodyEl.closest('[data-legacy-message-id], [data-message-id]');
  const id = holder && (holder.getAttribute('data-legacy-message-id') || holder.getAttribute('data-message-id'));
  if (id) return id;
  let h = 0;                                                         // no id: a short hash of the first 500 characters
  for (const ch of body.slice(0, 500)) h = (h * 31 + ch.charCodeAt(0)) | 0;
  return 'h' + h;
}

function senderOf(bodyEl) {
  const box = bodyEl.closest('.adn, .gs, [role="listitem"]') || document;
  const el = box.querySelector('span.gD[email], span[email]');
  return el ? { name: el.getAttribute('name') || el.textContent || '', email: el.getAttribute('email') || '' } : { name: '', email: '' };
}

function scan() {
  if (!on) return;
  if (Date.now() - lastAction > ACTION_WINDOW_MS) return;            // only right after the person did something
  const subjectEl = document.querySelector('h2.hP');
  const inSpam = /^#spam(\/|$)/.test(location.hash);
  for (const bodyEl of document.querySelectorAll('div.a3s')) {      // the text of each OPEN message in the conversation
    const body = bodyEl.innerText || '';
    if (!body.trim()) continue;
    const key = messageKey(bodyEl, body);
    if (seen.has(key)) continue;
    seen.add(key);
    const links = Array.from(bodyEl.querySelectorAll('a[href]')).slice(0, 200)
      .map(a => ({ href: a.getAttribute('data-saferedirecturl') || a.href, text: a.innerText || '' }));
    const { score, flags, host } = scoreMessage(subjectEl ? subjectEl.innerText || '' : '', body, links, senderOf(bodyEl), inSpam);
    const severity = severityOf(score);
    verdicts.set(key, { flags, host, risky: inSpam || !!severity });
    if (!severity) continue;
    const kind = inSpam ? 'spam' : 'open';                           // Gmail already caught spam: a resolved record
    api.runtime.sendMessage({ type: 'SUBMIT_THREAT', data: { severity, flags, host, kind } }).catch(() => {});
    if (subjectEl && !subjectEl.querySelector('.ssai-badge')) {
      const badge = document.createElement('span');
      badge.className = 'ssai-badge';
      badge.textContent = ' SSAI: ' + severity.toUpperCase() + ' RISK';
      badge.style.cssText = 'color:#ff1a3c;font-weight:bold;font-size:11px;margin-left:8px;';
      subjectEl.appendChild(badge);
    }
  }
}

let pending = null;                                                  // Gmail changes the page constantly: scan at most twice a second
function soon() {
  if (pending) return;
  pending = setTimeout(() => { pending = null; scan(); }, 500);
}

// A click on a link inside an opened message. Reported only when that message looked risky (warning signs, or in Spam).
function onLinkClick(event) {
  if (!on) return;
  const a = event.target && event.target.closest ? event.target.closest('div.a3s a[href]') : null;
  if (!a) return;
  const bodyEl = a.closest('div.a3s');
  const v = verdicts.get(messageKey(bodyEl, bodyEl.innerText || ''));
  if (!v || !v.risky) return;
  const target = hostOf(realLink(a.getAttribute('data-saferedirecturl') || a.href));
  const flags = ['the person clicked a link' + (target ? ' to ' + target : '')].concat(v.flags).slice(0, 10);
  api.runtime.sendMessage({ type: 'SUBMIT_THREAT', data: { severity: 'high', flags, host: target || v.host, kind: 'click' } })
    .catch(() => {});
}

function acted() {
  lastAction = Date.now();
  soon();
}

async function start() {
  const { enabled } = await api.storage.local.get('enabled');
  on = enabled === true;                                             // off unless a person turned it on
  scan();
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { scoreMessage, severityOf, realLink };           // the tests load this file in Node; nothing below runs there
} else {
  api.storage.onChanged.addListener(changes => { if (changes.enabled) { on = changes.enabled.newValue === true; scan(); } });
  new MutationObserver(soon).observe(document.body, { childList: true, subtree: true });   // drawing finishes after the click
  document.addEventListener('click', onLinkClick, true);            // before Gmail opens the link
  document.addEventListener('click', acted, true);
  document.addEventListener('keydown', acted, true);                // keyboard users open messages with Enter or o
  window.addEventListener('hashchange', acted);                     // opening a message changes the address
  start();
}
