#!/usr/bin/env python3
"""The browser extension (audit F-05): off by default, a node credential and never the admin key, HTTPS, narrow permissions, and
nothing about the e-mail itself sent to the hub. Static checks on the source and on every built package.
Run:  swarmsentinel-env/bin/python3 backend/tools/test_browser_extension.py"""
import importlib.util
import json
import os
import re
import shutil
import sys
import tempfile
import unittest
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
EXT = os.path.join(os.path.dirname(os.path.dirname(HERE)), "client", "browser-extension")
spec = importlib.util.spec_from_file_location("ext_build", os.path.join(EXT, "build.py"))
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


def read(name):
    with open(os.path.join(EXT, "src", name), encoding="utf-8") as f:
        return f.read()


class Source(unittest.TestCase):
    def test_it_is_off_until_a_person_turns_it_on(self):
        self.assertRegex(read("background.js"), r"enabled:\s*false")
        self.assertIn("enabled === true", read("content-gmail.js"))
        self.assertIn("if (!on) return;", read("content-gmail.js"))

    def test_it_never_holds_the_admin_key_or_a_hard_coded_hub(self):
        for name in build.FILES:
            text = read(name)
            self.assertNotIn("__SSAI_API_KEY__", text, name)
            self.assertNotRegex(text, r"192\.168\.\d|(?<![\w.])10\.\d+\.\d+\.\d+", name)
        self.assertIn("/api/node/register", read("background.js"))               # it enrols as a node with a single-use code
        self.assertIn("'X-API-Key': s.token", read("background.js"))              # and speaks with that node token

    def test_nothing_about_the_email_itself_is_sent(self):
        content, background = read("content-gmail.js"), read("background.js")
        send = re.search(r"sendMessage\(\{ type: 'SUBMIT_THREAT', data: \{([^}]*)\}", content).group(1)
        self.assertEqual(sorted(x.strip() for x in send.split(",")), ["flags", "host", "severity"])   # no subject, sender or body
        for word in ("subject", "sender", "recipient"):
            self.assertNotIn(word, re.search(r"const body = \{.*?\};", background, re.S).group(0).lower())

    def test_the_hub_must_use_https_unless_it_is_on_your_own_network_and_you_said_so(self):
        text = read("background.js")
        self.assertIn("The hub address must start with https://", text)
        self.assertIn("allowPlain", text)

    def test_only_the_popup_can_change_settings_and_only_a_tab_can_report(self):
        text = read("background.js")
        self.assertIn("const fromPopup = !sender.tab;", text)
        self.assertIn("case 'SUBMIT_THREAT': return sender.tab ?", text)

    def test_nothing_is_written_into_the_page_or_popup_as_html(self):
        for name in ("popup.js", "content-gmail.js"):
            self.assertNotRegex(read(name), r"innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(", name)


class Packages(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.old = build.DIST
        build.DIST = cls.tmp
        cls.zips = {b: build.build(b) for b in build.BROWSERS}

    @classmethod
    def tearDownClass(cls):
        build.DIST = cls.old
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def manifest(self, browser):
        with zipfile.ZipFile(self.zips[browser]) as z:
            return json.loads(z.read("manifest.json"))

    def test_one_package_per_browser_each_named_for_its_browser(self):
        self.assertEqual(sorted(self.zips), ["brave", "chrome", "edge", "firefox"])
        for browser, label in build.BROWSERS.items():
            self.assertIn(label, self.manifest(browser)["name"])
            with zipfile.ZipFile(self.zips[browser]) as z:
                self.assertIn(f"'{browser}'", z.read("background.js").decode())       # the build stamped the browser in

    def test_permissions_are_narrow_and_no_site_access_is_granted_up_front(self):
        for browser in build.BROWSERS:
            m = self.manifest(browser)
            self.assertEqual(sorted(m["permissions"]), ["alarms", "storage"], browser)
            self.assertEqual(m["host_permissions"], [], browser)
            self.assertEqual(m["content_scripts"][0]["matches"], ["https://mail.google.com/*"], browser)
            self.assertNotIn("tabs", m["permissions"], browser)
            self.assertNotIn("<all_urls>", json.dumps(m), browser)

    def test_chromium_and_firefox_get_the_right_background_form(self):
        for browser in ("chrome", "brave", "edge"):
            self.assertEqual(self.manifest(browser)["background"], {"service_worker": "background.js"})
        ff = self.manifest("firefox")
        self.assertEqual(ff["background"], {"scripts": ["background.js"]})
        self.assertIn("gecko", ff["browser_specific_settings"])

    def test_the_build_refuses_a_source_with_a_key_in_it(self):
        path = os.path.join(EXT, "src", "background.js")
        with open(path, encoding="utf-8") as f:
            original = f.read()
        try:
            with open(path, "w", encoding="utf-8", newline="") as f:
                f.write(original + "\nconst API_KEY = '__SSAI_API_KEY__';\n")
            with self.assertRaises(SystemExit):
                build.check_source()
        finally:
            with open(path, "w", encoding="utf-8", newline="") as f:
                f.write(original)
        build.check_source()


if __name__ == "__main__":
    unittest.main()
