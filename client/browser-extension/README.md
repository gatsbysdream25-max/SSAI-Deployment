# SwarmSentinel Shield (browser extension)

Optional. For Chrome, Brave, Edge and Firefox. **Off until you turn it on.**

## What it does

When you turn it on, it looks at the Gmail message you have open for common phishing signs (urgent wording, link shorteners,
links to a raw address, risky attachment types). If it finds some, it tells **your own SwarmSentinel hub** the warning signs and the
host name of the suspicious link, and shows a small badge next to the subject.

## What it never does

- It never sends the subject, sender, recipient or text of your mail. Only the signs ("link shortener: bit.ly") and a host name.
- It never holds your hub's admin key. It holds one credential of its own, a node token from a **single-use enrolment code**, so a
  stolen browser profile can report threats and do nothing else. The popup shows that credential as its last four characters.
- It never contacts anything except the hub you typed. The browser asks you to allow that one address, from a click.
- It never talks to a hub over plain `http://` unless the hub is on your own network **and** you ticked the box saying so.

## Install

1. `python client/browser-extension/build.py` writes `dist/chrome`, `dist/brave`, `dist/edge`, `dist/firefox` and a zip of each.
2. Load the folder for your browser (see the main README), or submit the zip to the browser's add-on store.
3. Click the toolbar icon. Enter your hub's address and an enrolment code (the dashboard's Nodes page makes one). Click **Connect**.
4. Tick **Scan my Gmail for phishing** when you want it on. Untick it any time.

To remove it completely: **Disconnect and forget** in the popup, then ask the administrator to revoke this node in the dashboard.

## For administrators

Each browser appears in the dashboard as a node named `browser-<browser>` and is revoked like any other node. Reports arrive as
findings of type `phishing-email` detected by `browser-extension-<browser>` and go through the same AI panel as everything else.
A browser cannot approve or block anything: a node token can only submit findings.

Developing: `python backend/tools/test_browser_extension.py` checks the source and every built package (off by default, narrow
permissions, no key or address baked in, nothing about the e-mail sent).
