#!/usr/bin/env python3
"""change_evidence: a protected account-file change is skipped only with proof it is harmless (2026-11-15 sync).
Run:  swarmsentinel-env/bin/python3 backend/tools/test_change_evidence.py"""
import os
import sys
import unittest
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(os.path.dirname(HERE), 'agents'), os.path.dirname(HERE)]
import change_evidence as CE  # noqa: E402

T = datetime(2026, 11, 15, 14, 30, 0, tzinfo=timezone.utc)
PASSWD = ("root:x:0:0:root:/root:/bin/bash\n"
          "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
          "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n")
GROUP = "root:x:0:\nsudo:x:27:alice\ndocker:x:998:\nalice:x:1000:\n"
SHADOW = "root:*:20000:0:99999:7:::\ndaemon:*:20000:0:99999:7:::\nalice:$y$j9T$abc$def:20000:0:99999:7:::\n"

PG_USER = "postgres:x:120:126:PostgreSQL administrator:/var/lib/postgresql:/bin/bash\n"
SVC_USER = "svcmon:x:121:127::/nonexistent:/usr/sbin/nologin\n"
DPKG = ["2026-11-15 14:29:40 status unpacked svcmon:amd64 1.0",
        "2026-11-15 14:29:58 configure svcmon:amd64 1.0 <none>",
        "2026-11-15 14:29:59 status installed svcmon:amd64 1.0"]
USERADD = ["2026-11-15T14:29:58.123456+00:00 hub useradd[4242]: new user: name=svcmon, UID=121, GID=127, home=/nonexistent, shell=/usr/sbin/nologin, from=none"]
SUDO = ["2026-11-15T14:27:10.000000+00:00 hub sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/sbin/useradd -r -s /usr/sbin/nologin svcmon"]


def passwd_assess(new_text, logs, old=PASSWD, when=T):
    return CE.assess('/etc/passwd', old, new_text, logs, when, passwd_text=new_text, group_text=GROUP)


class Harmless(unittest.TestCase):
    def test_system_account_from_a_package_install_is_skipped(self):
        r = passwd_assess(PASSWD + SVC_USER, DPKG + USERADD)
        self.assertTrue(r['harmless'], r)
        self.assertIn('package', r['reason'])

    def test_system_account_minutes_after_a_persons_sudo_is_skipped(self):
        r = passwd_assess(PASSWD + SVC_USER, SUDO + USERADD)
        self.assertTrue(r['harmless'], r)
        self.assertIn('alice', r['reason'])

    def test_its_own_locked_shadow_entry_and_group_are_skipped(self):
        new_shadow = SHADOW + "svcmon:!:20407::::::\n"
        r = CE.assess('/etc/shadow', SHADOW, new_shadow, DPKG, T, passwd_text=PASSWD + SVC_USER)
        self.assertTrue(r['harmless'], r)
        r = CE.assess('/etc/group', GROUP, GROUP + "svcmon:x:127:\n", DPKG, T, passwd_text=PASSWD + SVC_USER)
        self.assertTrue(r['harmless'], r)

    def test_classic_syslog_timestamps_are_understood(self):
        logs = ["Nov 15 14:29:58 hub useradd[4242]: new user: name=svcmon, UID=121, GID=127, home=/nonexistent, shell=/usr/sbin/nologin",
                "Nov 15 14:27:10 hub sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt install svcmon"]
        self.assertTrue(passwd_assess(PASSWD + SVC_USER, logs)['harmless'])


class StillAlerts(unittest.TestCase):
    def test_no_evidence_means_alert(self):
        r = passwd_assess(PASSWD + SVC_USER, [])
        self.assertFalse(r['harmless'])

    def test_evidence_outside_the_window_does_not_count(self):
        late = ["2026-11-15 16:00:00 status installed svcmon:amd64 1.0"]
        self.assertFalse(passwd_assess(PASSWD + SVC_USER, late)['harmless'])

    def test_new_account_that_can_log_in(self):
        r = passwd_assess(PASSWD + PG_USER, DPKG)
        self.assertFalse(r['harmless'])
        self.assertIn('can log in', r['reason'])

    def test_new_persons_account(self):
        r = passwd_assess(PASSWD + "mallory:x:1001:1001::/home/mallory:/usr/sbin/nologin\n", DPKG)
        self.assertFalse(r['harmless'])

    def test_second_uid_zero_account(self):
        r = passwd_assess(PASSWD + "toor:x:0:0::/root:/usr/sbin/nologin\n", DPKG)
        self.assertFalse(r['harmless'])

    def test_privileged_group_additions(self):
        for grp in ('sudo', 'adm', 'root', 'shadow', 'docker'):
            old = GROUP + "adm:x:4:\nshadow:x:42:\n"
            new = old.replace(f"{grp}:x:", f"{grp}:x:", 1)
            lines = new.splitlines()
            lines = [ln + (',' if ln.split(':')[3] else '') + 'daemon' if ln.startswith(grp + ':') else ln for ln in lines]
            r = CE.assess('/etc/group', old, "\n".join(lines) + "\n", DPKG, T, passwd_text=PASSWD)
            self.assertFalse(r['harmless'], grp)
            self.assertIn('privileged', r['reason'], grp)

    def test_person_added_to_an_ordinary_group(self):
        r = CE.assess('/etc/group', GROUP + "audio:x:29:\n", GROUP + "audio:x:29:alice\n", DPKG, T, passwd_text=PASSWD)
        self.assertFalse(r['harmless'])

    def test_password_change(self):
        r = CE.assess('/etc/shadow', SHADOW, SHADOW.replace('$def', '$xyz'), DPKG, T, passwd_text=PASSWD)
        self.assertFalse(r['harmless'])
        self.assertIn('password', r['reason'])

    def test_new_shadow_entry_with_empty_password(self):
        r = CE.assess('/etc/shadow', SHADOW, SHADOW + "svcmon::20407::::::\n", DPKG, T, passwd_text=PASSWD + SVC_USER)
        self.assertFalse(r['harmless'])
        self.assertIn('EMPTY', r['reason'])

    def test_deleted_user(self):
        r = passwd_assess(PASSWD.replace("daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n", ""), DPKG)
        self.assertFalse(r['harmless'])
        self.assertIn('deleted', r['reason'])

    def test_unrecognised_account_tool_line(self):
        odd = ["2026-11-15T14:29:58+00:00 hub usermod[4243]: change user 'svcmon' shell from '/usr/sbin/nologin' to '/bin/bash'"]
        r = passwd_assess(PASSWD + SVC_USER, DPKG + odd)
        self.assertFalse(r['harmless'])
        self.assertIn('not recognised', r['reason'])

    def test_sudo_by_a_system_account_is_not_a_person(self):
        logs = ["2026-11-15T14:27:10+00:00 hub sudo:   daemon : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/sbin/useradd x"]
        self.assertFalse(passwd_assess(PASSWD + SVC_USER, logs)['harmless'])

    def test_non_account_files_always_alert(self):
        r = CE.assess('/etc/sudoers', 'a', 'b', DPKG, T)
        self.assertFalse(r['harmless'])

    def test_errors_inside_the_check_mean_alert(self):
        r = CE.assess('/etc/passwd', PASSWD, None, DPKG, T)            # None text makes the parser fail
        self.assertFalse(r['harmless'])
        r = CE.assess('/etc/passwd', PASSWD, PASSWD + SVC_USER, [object()], T)
        self.assertFalse(r['harmless'])
        self.assertIn('failed', r['reason'])


if __name__ == '__main__':
    unittest.main()
