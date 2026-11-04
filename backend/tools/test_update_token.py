#!/usr/bin/env python3
"""A private releases repository (2026-11-04): the install can be given a read-only GitHub access token. The token must reach
GitHub's API and nowhere else, must never be on a command line or in output, and a public repository must keep working with none.
GitHub is faked (a stand-in curl and a stand-in urlopen), so nothing here touches the internet.
Run:  swarmsentinel-env/bin/python3 backend/tools/test_update_token.py"""
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
SOURCE = os.path.dirname(os.path.dirname(HERE))
sys.path[:0] = [os.path.join(os.path.dirname(HERE), 'agents')]
import release_check  # noqa: E402

TOKEN = 'github_pat_11AAAAAAA0abcdefghijklmnopqrstuvwxyz0123456789'
CAN_RUN = os.name == 'posix' and all(shutil.which(tool) for tool in ('bash', 'tar', 'sha256sum', 'python3'))

# A stand-in for curl that behaves like GitHub: the API answers only to the right token, asset addresses are API addresses,
# and any other address is refused if the token was sent to it. Every call is logged (arguments and the config sent on stdin).
FAKE_CURL = r'''#!%(python)s
import json, os, shutil, sys
args = sys.argv[1:]
out = args[args.index('-o') + 1] if '-o' in args else None
url = args[-1]
config = sys.stdin.read() if '-K' in args else ''
with open(os.environ['FAKE_LOG'], 'a') as log:
    log.write(json.dumps({'argv': args, 'config': config}) + '\n')
base = os.environ['FAKE_DIR']
have_token = ('Bearer ' + os.environ['FAKE_TOKEN']) in config
if not url.startswith('https://api.github.com/'):
    sys.exit(99 if have_token else 22)           # private files have no public address; the token must never go elsewhere
if not have_token:
    sys.exit(22)
if url.endswith('/releases/latest') or '/releases/tags/' in url:
    shutil.copy(os.path.join(base, 'release.json'), out)
elif url.endswith('/assets/1'):
    shutil.copy(os.path.join(base, 'package.tar.gz'), out)
elif url.endswith('/assets/2'):
    shutil.copy(os.path.join(base, 'package.tar.gz.sha256'), out)
else:
    sys.exit(22)
'''


def make_release(work, tag='v9.9.9'):
    """A release whose files can be reached only through API addresses, as in a private repository."""
    top = os.path.join(work, 'stage', 'SwarmSentinel')
    for relative, text in (('backend/app.py', 'print(1)\n'), ('VERSION', f'{tag} (abc)\n'),
                           ('deploy/install.sh', '#!/bin/bash\necho "$@" > "$(dirname "$0")/../.installer-ran"\n')):
        path = os.path.join(top, relative)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8', newline='\n') as handle:
            handle.write(text)
    package = os.path.join(work, 'package.tar.gz')
    with tarfile.open(package, 'w:gz') as archive:
        archive.add(top, arcname='SwarmSentinel')
    with open(package, 'rb') as handle:
        digest = hashlib.sha256(handle.read()).hexdigest()
    with open(package + '.sha256', 'w', encoding='utf-8') as handle:
        handle.write(f'{digest}  swarmsentinel-{tag}.tar.gz\n')
    name = f'swarmsentinel-{tag}.tar.gz'
    release = {'tag_name': tag, 'body': 'notes', 'assets': [
        {'name': name, 'url': 'https://api.github.com/repos/o/r/releases/assets/1',
         'browser_download_url': 'https://github.com/o/r/releases/download/%s/%s' % (tag, name)},
        {'name': name + '.sha256', 'url': 'https://api.github.com/repos/o/r/releases/assets/2',
         'browser_download_url': 'https://github.com/o/r/releases/download/%s/%s.sha256' % (tag, name)}]}
    with open(os.path.join(work, 'release.json'), 'w', encoding='utf-8') as handle:
        json.dump(release, handle)
    return release


def install_fake_curl(work):
    bindir = os.path.join(work, 'bin')
    os.makedirs(bindir)
    path = os.path.join(bindir, 'curl')
    with open(path, 'w', encoding='utf-8', newline='\n') as handle:
        handle.write(FAKE_CURL % {'python': sys.executable})
    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)
    return bindir


class FakeResponse:
    def __init__(self, body):
        self.body = body

    def read(self):
        return json.dumps(self.body).encode()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class TokenInTheReleaseCheck(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.work, True)
        self.release = make_release(self.work)
        for name in ('SSAI_UPDATE_TOKEN', 'SSAI_UPDATE_API', 'SSAI_UPDATE_REPO'):
            patcher = mock.patch.dict(os.environ)
            patcher.start()
            self.addCleanup(patcher.stop)
            os.environ.pop(name, None)

    def ask(self, root=''):
        with mock.patch('release_check.urllib.request.urlopen', return_value=FakeResponse(self.release)) as opened:
            answer = release_check.fetch_latest(root=root)
        return answer, opened.call_args[0][0]

    def test_no_token_means_the_ordinary_public_request(self):
        answer, request = self.ask()
        self.assertIsNone(request.get_header('Authorization'))
        self.assertTrue(answer['package_url'].startswith('https://github.com/'))

    def test_a_token_in_the_environment_is_sent_to_the_api_and_the_api_addresses_are_used(self):
        os.environ['SSAI_UPDATE_TOKEN'] = TOKEN
        answer, request = self.ask()
        self.assertEqual(request.get_header('Authorization'), 'Bearer ' + TOKEN)
        self.assertEqual(answer['package_url'], 'https://api.github.com/repos/o/r/releases/assets/1')
        self.assertEqual(answer['checksum_url'], 'https://api.github.com/repos/o/r/releases/assets/2')

    def test_the_token_file_in_the_install_folder_is_used(self):
        with open(os.path.join(self.work, '.update-token'), 'w') as handle:
            handle.write(TOKEN + '\n')
        answer, request = self.ask(self.work)
        self.assertEqual(request.get_header('Authorization'), 'Bearer ' + TOKEN)
        self.assertEqual(release_check.token(self.work), TOKEN)

    def test_the_token_is_never_sent_to_another_address(self):
        os.environ['SSAI_UPDATE_TOKEN'] = TOKEN
        os.environ['SSAI_UPDATE_API'] = 'https://example.org/latest.json'
        answer, request = self.ask()
        self.assertIsNone(request.get_header('Authorization'))
        self.assertTrue(answer['package_url'].startswith('https://github.com/'))

    def test_a_token_that_does_not_look_like_one_is_an_error_that_does_not_repeat_it(self):
        os.environ['SSAI_UPDATE_TOKEN'] = 'bad token\nwith lines'
        with self.assertRaises(release_check.ReleaseError) as caught:
            release_check.token()
        self.assertNotIn('bad token', str(caught.exception))

    def test_a_refusal_says_what_to_do(self):
        import urllib.error
        error = urllib.error.HTTPError('https://api.github.com/x', 404, 'Not Found', {}, None)
        with mock.patch('release_check.urllib.request.urlopen', side_effect=error):
            with self.assertRaises(release_check.ReleaseError) as caught:
                release_check.fetch_latest()
        self.assertIn('access token', str(caught.exception))
        os.environ['SSAI_UPDATE_TOKEN'] = TOKEN
        with mock.patch('release_check.urllib.request.urlopen', side_effect=error):
            with self.assertRaises(release_check.ReleaseError) as caught:
                release_check.fetch_latest()
        self.assertIn('refused', str(caught.exception))
        self.assertNotIn(TOKEN, str(caught.exception))


@unittest.skipUnless(CAN_RUN, 'needs bash, tar, sha256sum and python3 on Linux')
class TokenInTheScripts(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.work, True)
        make_release(self.work)
        self.bindir = install_fake_curl(self.work)
        self.log = os.path.join(self.work, 'curl.log')
        self.env = dict(os.environ, PATH=self.bindir + os.pathsep + os.environ['PATH'], FAKE_LOG=self.log,
                        FAKE_DIR=self.work, FAKE_TOKEN=TOKEN, SSAI_UPDATE_REPO='o/r')
        for name in ('SSAI_UPDATE_API', 'SSAI_UPDATE_TOKEN', 'SSAI_GET_BASE'):
            self.env.pop(name, None)

    def calls(self):
        with open(self.log, encoding='utf-8') as handle:
            return [json.loads(line) for line in handle if line.strip()]

    def test_the_one_line_installer_installs_from_a_private_release_and_keeps_the_token_for_updates(self):
        target = os.path.join(self.work, 'SwarmSentinel')
        env = dict(self.env, SSAI_UPDATE_TOKEN=TOKEN)
        result = subprocess.run(['bash', os.path.join(SOURCE, 'deploy/get-ssai.sh'), '--dir', target, '--dry-run'],
                                capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(os.path.exists(os.path.join(target, '.installer-ran')), 'the installer ran on the unpacked release')
        saved = os.path.join(target, '.update-token')
        with open(saved, encoding='utf-8') as handle:
            self.assertEqual(handle.read().strip(), TOKEN)
        self.assertEqual(stat.S_IMODE(os.stat(saved).st_mode), 0o600)
        self.assertNotIn(TOKEN, result.stdout + result.stderr)
        for call in self.calls():
            self.assertNotIn(TOKEN, ' '.join(call['argv']), 'the token must not be on a command line')
            self.assertIn(TOKEN, call['config'])

    def test_a_wrong_token_stops_with_a_plain_message_and_installs_nothing(self):
        target = os.path.join(self.work, 'SwarmSentinel')
        env = dict(self.env, SSAI_UPDATE_TOKEN='github_pat_' + 'B' * 40)
        result = subprocess.run(['bash', os.path.join(SOURCE, 'deploy/get-ssai.sh'), '--dir', target, '--dry-run'],
                                capture_output=True, text=True, env=env, timeout=60)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('access token', result.stderr)
        self.assertFalse(os.path.exists(target))

    def test_a_token_that_does_not_look_like_one_is_refused_before_any_request(self):
        env = dict(self.env, SSAI_UPDATE_TOKEN='short')
        result = subprocess.run(['bash', os.path.join(SOURCE, 'deploy/get-ssai.sh'), '--dir', os.path.join(self.work, 'x'), '--dry-run'],
                                capture_output=True, text=True, env=env, timeout=60)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(os.path.exists(self.log))

    def test_the_package_updater_sends_the_token_to_the_api_only(self):
        """fetch_file from deploy/update-package.sh, run on its own: token from .update-token, stdin only, API addresses only."""
        script = os.path.join(SOURCE, 'deploy/update-package.sh')
        with open(os.path.join(self.work, '.update-token'), 'w', encoding='utf-8') as handle:
            handle.write(TOKEN + '\n')
        driver = os.path.join(self.work, 'drive.sh')
        with open(driver, 'w', encoding='utf-8', newline='\n') as handle:
            handle.write('set -e\nREPO="$1"\n'
                         "eval \"$(sed -n '/^fetch_file()/,/^}/p' \"$2\")\"\n"
                         'fetch_file https://api.github.com/repos/o/r/releases/assets/1 "$3/out.tar.gz" 30\n'
                         'if fetch_file https://example.org/elsewhere.tar.gz "$3/no.tar.gz" 30; then echo LEAKED; fi\n')
        result = subprocess.run(['bash', driver, self.work, script, self.work], capture_output=True, text=True, env=self.env, timeout=60)
        self.assertNotIn('LEAKED', result.stdout)
        self.assertTrue(os.path.exists(os.path.join(self.work, 'out.tar.gz')))
        calls = self.calls()
        self.assertEqual(len(calls), 2)
        self.assertIn(TOKEN, calls[0]['config'])
        self.assertEqual(calls[1]['config'], '', 'a non-GitHub address gets no token')
        for call in calls:
            self.assertNotIn(TOKEN, ' '.join(call['argv']))

    def test_the_updater_keeps_the_token_file_through_an_update(self):
        with open(os.path.join(SOURCE, 'deploy/update-package.sh'), encoding='utf-8') as handle:
            text = handle.read()
        self.assertIn('.update-token', text.split('KEEP_TOP=(', 1)[1].split(')', 1)[0])


if __name__ == '__main__':
    unittest.main(verbosity=2)
