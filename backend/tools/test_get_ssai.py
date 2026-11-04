#!/usr/bin/env python3
"""The one-line installer (deploy/get-ssai.sh): checked download, unpack, hand over to install.sh.
The "release" is a folder of local files and install.sh is a stand-in that records how it was called, so nothing here touches
the internet or installs anything. Needs bash, curl, tar and sha256sum (Linux).
Run:  swarmsentinel-env/bin/python3 backend/tools/test_get_ssai.py"""
import hashlib
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SOURCE = os.path.dirname(os.path.dirname(HERE))
SCRIPT = os.path.join(SOURCE, 'deploy', 'get-ssai.sh')
CAN_RUN = os.name == 'posix' and all(shutil.which(tool) for tool in ('bash', 'curl', 'tar', 'sha256sum'))

# Stands in for deploy/install.sh: writes the arguments it was given next to itself so the test can read them back.
FAKE_INSTALLER = '#!/usr/bin/env bash\nprintf \'%s\\n\' "$@" > "$(dirname "$0")/../installer-was-called-with.txt"\n'


def write(path, text, mode=None):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as handle:
        handle.write(text)
    if mode:
        os.chmod(path, mode)


def make_release(folder, tag, claimed_version=None, evil_path=False, bad_checksum=False):
    """Write swarmsentinel-<tag>.tar.gz and its .sha256 into folder, plus the JSON the 'newest release' check reads."""
    stage = os.path.join(folder, 'stage-' + tag)
    top = os.path.join(stage, 'SwarmSentinel')
    write(os.path.join(top, 'backend', 'app.py'), 'print("app")\n')
    write(os.path.join(top, 'deploy', 'install.sh'), FAKE_INSTALLER, 0o755)
    write(os.path.join(top, 'VERSION'), f'{claimed_version or tag} (abc123)\n')
    package = os.path.join(folder, f'swarmsentinel-{tag}.tar.gz')
    with tarfile.open(package, 'w:gz') as archive:
        archive.add(top, arcname='SwarmSentinel')
        if evil_path:
            outside = os.path.join(stage, 'evil.txt')
            write(outside, 'x\n')
            archive.add(outside, arcname='../evil.txt')
    with open(package, 'rb') as handle:
        digest = hashlib.sha256(handle.read()).hexdigest()
    if bad_checksum:
        digest = '0' * 64
    write(package + '.sha256', f'{digest} *swarmsentinel-{tag}.tar.gz\n')
    write(os.path.join(folder, 'latest.json'), json.dumps({'tag_name': tag}))


@unittest.skipUnless(CAN_RUN, 'needs bash, curl, tar and sha256sum on Linux')
class OneLineInstaller(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.release = os.path.join(self.tmp, 'release')
        self.dir = os.path.join(self.tmp, 'home', 'SwarmSentinel')
        os.makedirs(self.release)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_script(self, *args, uid='0', tag_file=True):
        env = dict(os.environ, SSAI_GET_UID=uid, SSAI_GET_BASE='file://' + self.release)
        if tag_file:
            env['SSAI_UPDATE_API'] = 'file://' + os.path.join(self.release, 'latest.json')
        return subprocess.run(['bash', SCRIPT, '--dir', self.dir, *args], env=env, capture_output=True, text=True, timeout=60)

    def installer_args(self):
        with open(os.path.join(self.dir, 'installer-was-called-with.txt'), encoding='utf-8') as handle:
            return handle.read().split()

    def test_installs_the_newest_release_and_hands_the_options_to_the_installer(self):
        make_release(self.release, 'v1.2.3')
        done = self.run_script('--role', 'node', '--hub-url', 'http://hub:5000', '--enroll-code', 'AAAA-BBBB-CCCC-DDDD')
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual(self.installer_args(), ['--role', 'node', '--hub-url', 'http://hub:5000', '--enroll-code', 'AAAA-BBBB-CCCC-DDDD'])
        self.assertTrue(os.path.isfile(os.path.join(self.dir, 'backend', 'app.py')))
        with open(os.path.join(self.dir, '.release-files'), encoding='utf-8') as handle:
            self.assertIn('backend/app.py', handle.read().split())     # so a later update can remove files a release drops

    def test_a_named_version_is_installed_instead_of_the_newest(self):
        make_release(self.release, 'v1.0.0')
        make_release(self.release, 'v2.0.0')                          # 'latest' now points at v2.0.0
        done = self.run_script('--version', 'v1.0.0')
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        with open(os.path.join(self.dir, 'VERSION'), encoding='utf-8') as handle:
            self.assertTrue(handle.read().startswith('v1.0.0'))

    def test_a_damaged_or_swapped_download_installs_nothing(self):
        make_release(self.release, 'v1.2.3', bad_checksum=True)
        done = self.run_script()
        self.assertNotEqual(done.returncode, 0)
        self.assertIn('checksum', done.stderr)
        self.assertFalse(os.path.exists(self.dir))

    def test_a_package_that_claims_another_version_is_refused(self):
        make_release(self.release, 'v1.2.3', claimed_version='v0.0.1')     # an old package replayed under a new name
        done = self.run_script()
        self.assertNotEqual(done.returncode, 0)
        self.assertIn('not v1.2.3', done.stderr)
        self.assertFalse(os.path.exists(self.dir))

    def test_a_package_with_paths_outside_its_folder_is_refused(self):
        make_release(self.release, 'v1.2.3', evil_path=True)
        done = self.run_script()
        self.assertNotEqual(done.returncode, 0)
        self.assertIn('outside', done.stderr)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, 'evil.txt')))

    def test_an_unusable_tag_is_refused(self):
        make_release(self.release, 'v1.2.3')
        done = self.run_script('--version', 'v1; rm -rf ~')
        self.assertNotEqual(done.returncode, 0)
        self.assertIn('usable version tag', done.stderr)

    def test_without_root_it_stops_and_says_how_to_run_it(self):
        make_release(self.release, 'v1.2.3')
        done = self.run_script(uid='1000')
        self.assertNotEqual(done.returncode, 0)
        self.assertIn('needs root', done.stderr)
        self.assertFalse(os.path.exists(self.dir))

    def test_a_trial_run_or_an_install_without_services_does_not_need_root(self):
        make_release(self.release, 'v1.2.3')
        self.assertEqual(self.run_script('--no-systemd', uid='1000').returncode, 0)

    def test_running_it_again_repairs_in_place_and_keeps_the_machines_own_files(self):
        make_release(self.release, 'v1.2.3')
        self.assertEqual(self.run_script().returncode, 0)
        write(os.path.join(self.dir, '.env'), 'KEY=keep\n')
        again = self.run_script('--re-enroll')
        self.assertEqual(again.returncode, 0, again.stdout + again.stderr)
        self.assertIn('already unpacked', again.stdout)
        self.assertEqual(self.installer_args(), ['--re-enroll'])
        with open(os.path.join(self.dir, '.env'), encoding='utf-8') as handle:
            self.assertEqual(handle.read(), 'KEY=keep\n')

    def test_a_different_version_already_there_is_not_overwritten(self):
        make_release(self.release, 'v1.0.0')
        self.assertEqual(self.run_script().returncode, 0)
        make_release(self.release, 'v2.0.0')
        done = self.run_script()
        self.assertNotEqual(done.returncode, 0)
        self.assertIn('update.sh', done.stderr)

    def test_a_folder_that_holds_something_else_is_not_touched(self):
        make_release(self.release, 'v1.2.3')
        write(os.path.join(self.dir, 'my-notes.txt'), 'mine\n')
        done = self.run_script()
        self.assertNotEqual(done.returncode, 0)
        self.assertIn('not empty', done.stderr)
        self.assertTrue(os.path.isfile(os.path.join(self.dir, 'my-notes.txt')))

    def test_a_truncated_download_runs_nothing(self):
        # curl | bash: if the connection drops before the last line, bash has not seen main, so nothing is executed.
        with open(SCRIPT, encoding='utf-8') as handle:
            lines = handle.read().splitlines()
        cut = os.path.join(self.tmp, 'cut.sh')
        write(cut, '\n'.join(lines[:-2]) + '\n')                      # everything except the final call
        done = subprocess.run(['bash', cut], capture_output=True, text=True, timeout=30)
        self.assertEqual((done.returncode, done.stdout, done.stderr), (0, '', ''))


if __name__ == '__main__':
    unittest.main(verbosity=2)
