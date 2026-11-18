// Scoring checks for the Gmail scanner (run: node client/browser-extension/test_scoring.js). Made-up messages only; example.* and
// documentation addresses. Exits non-zero on the first failure. backend/tools/test_browser_extension.py runs it when Node is present.
'use strict';
const assert = require('assert');
const { scoreMessage, severityOf, realLink } = require('./src/content-gmail.js');

const sev = (subject, body, links = [], sender = {}, spam = false) => severityOf(scoreMessage(subject, body, links, sender, spam).score);

// Gmail's redirect is unwrapped to the real link
assert.strictEqual(realLink('https://www.google.com/url?q=https://evil.example.net/login&sa=D'), 'https://evil.example.net/login');

// classic credential phish: brand name from another domain, link text lies about where it goes
let r = scoreMessage('Your account has been suspended', 'Please verify your account within 24 hours.',
  [{ href: 'https://www.google.com/url?q=https://paypa1-secure.example.net/x', text: 'www.paypal.com' }],
  { name: 'PayPal Support', email: 'service@paypa1-secure.example.net' }, false);
assert.strictEqual(severityOf(r.score), 'high');
assert.ok(r.flags.some(f => f.startsWith('sender name says paypal')));
assert.ok(r.flags.some(f => f.startsWith('link text shows www.paypal.com')));
assert.strictEqual(r.host, 'paypa1-secure.example.net');

// a link hidden behind "Click here" to a raw address is caught (it used to be invisible)
assert.strictEqual(sev('Invoice', 'See the document.', [{ href: 'http://203.0.113.9/doc.html', text: 'Click here' }]), 'medium');

// shortener behind link text
assert.ok(scoreMessage('', 'Track it', [{ href: 'https://bit.ly/3abc', text: 'Track package' }], {}, false).flags
  .includes('link shortener: bit.ly'));

// Gmail's own spam verdict counts, but alone it is only "low"
assert.strictEqual(sev('Hello', 'Nothing special here.', [], {}, true), 'low');

// ordinary mail is not flagged
assert.strictEqual(sev('Lunch tomorrow?', 'Are we still on for noon? See https://www.example.com/menu',
  [{ href: 'https://www.example.com/menu', text: 'the menu' }], { name: 'Sam', email: 'sam@example.com' }), null);
// the real PayPal from paypal.com, with matching link text, is not flagged
assert.strictEqual(sev('Receipt for your payment', 'Thanks for your payment.',
  [{ href: 'https://www.paypal.com/activity', text: 'www.paypal.com' }], { name: 'PayPal', email: 'service@paypal.com' }), null);
// link text that shows the same site under another subdomain is fine
assert.strictEqual(sev('News', 'Read more', [{ href: 'https://news.example.org/a', text: 'www.example.org' }]), null);
// a file name mentioned in passing ("the .zip file") is not an attachment; "invoice.zip" is
assert.strictEqual(sev('', 'Send me the .zip format please'), null);
assert.ok(scoreMessage('', 'Open invoice.zip now', [], {}, false).flags.includes('risky attachment type: .zip'));

// flags are never repeated and stay short enough for the hub (80 characters each is enforced again in background.js)
r = scoreMessage('action required action required', 'action required', [], {}, false);
assert.strictEqual(r.flags.filter(f => f === 'keyword: action required').length, 1);

console.log('scoring checks passed');
