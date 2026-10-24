#!/usr/bin/env python3
"""A packaged install updates itself from the newest release: checked download, kept settings, rollback on failure.
The "release" is a local file, so nothing here touches the internet. Needs bash, curl, tar and sha256sum (Linux).
Run:  swarmsentinel-env/bin/python3 backend/tools/test_update_package.py"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SOURCE = os.path.dirname(os.path.dirname(HERE))
sys.path[:0] = [os.path.join(os.path.dirname(HERE), 'agents')]
import release_check  # noqa: E402

CAN_RUN = os.name == 'posix' and all(shutil.which(tool) for tool in ('bash', 'curl', 'tar', 'sha256sum'))


def write(path, text, mode=None):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as handle:
        handle.write(text)
    if mode:
        os.chmod(path, mode)


def copy_real_files_into(root):
    """The pieces of the real product that the updater uses, so the test exercises the real scripts."""
    for relative in ('deploy/update-package.sh', 'deploy/update-lib.sh', 'backend/agents/release_check.py'):
        target = os.path.join(root, relative)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        shutil.copy(os.path.join(SOURCE, relative), target)
        os.chmod(target, 0o755)


def make_install(root, version='v1'):
    """An installed copy: code, a virtualenv that is just this python, and the machine's own settings and data."""
    copy_real_files_into(root)
    write(os.path.join(root, 'backend/app.py'), 'print("app", "%s")\n' % version)
    write(os.path.join(root, 'VERSION'), f'{version} (abc)\n')
    write(os.path.join(root, 'requirements.txt'), 'flask\n')
    write(os.path.join(root, 'only_in_old.txt'), 'dropped by the next release\n')
    write(os.path.join(root, '.release-files'), 'only_in_old.txt\n')
    write(os.path.join(root, 'backend/instance/secret.txt'), 'keep me\n')
    write(os.path.join(root, '.env'), 'KEY=keep\n')
    os.makedirs(os.path.join(root, 'swarmsentinel-env/bin'), exist_ok=True)
    os.symlink(sys.executable, os.path.join(root, 'swarmsentinel-env/bin/python3'))


def make_package(workdir, version, passing_tests=True, claimed_version=None, evil_path=False):
    """A release package for `version` (its tag), plus the checksum file and the 'latest release' JSON that points at them."""
    stage = os.path.join(workdir, 'stage-' + version)
    shutil.rmtree(stage, ignore_errors=True)
    top = os.path.join(stage, 'SwarmSentinel')
    copy_real_files_into(top)
    write(os.path.join(top, 'backend/app.py'), 'print("app", "%s")\n' % version)
    write(os.path.join(top, 'VERSION'), f'{claimed_version or version} (def)\n')
    write(os.path.join(top, 'requirements.txt'), 'flask\n')
    write(os.path.join(top, 'brand_new.txt'), 'only in the new release\n')
    body = 'import sys\nsys.exit(0)\n' if passing_tests else 'import sys\nsys.exit(1)\n'
    write(os.path.join(top, 'backend/tools/test_dummy.py'), body)
    package = os.path.join(workdir, f'swarmsentinel-{version}.tar.gz')
    with tarfile.open(package, 'w:gz') as archive:
        archive.add(top, arcname='SwarmSentinel')
        if evil_path:
            leak = os.path.join(workdir, 'leak.txt')
            write(leak, 'x')
            archive.add(leak, arcname='SwarmSentinel/../escaped.txt')
    with open(package, 'rb') as handle:
        digest = hashlib.sha256(handle.read()).hexdigest()
    checksum = package + '.sha256'
    write(checksum, f'{digest}  {os.path.basename(package)}\n')
    release = {'tag_name': version, 'body': 'what changed', 'assets': [
        {'name': os.path.basename(package), 'browser_download_url': 'file://' + package},
        {'name': os.path.basename(checksum), 'browser_download_url': 'file://' + checksum}]}
    latest = os.path.join(workdir, 'latest.json')
    write(latest, json.dumps(release))
    return package, checksum, 'file://' + latest


def run_updater(root, api, *args):
    env = dict(os.environ, SSAI_UPDATE_API=api)
    return subprocess.run(['bash', os.path.join(root, 'deploy/update-package.sh'), '--no-restart', *args],
                          capture_output=True, text=True, env=env, timeout=120)


def read(root, relative):
    with open(os.path.join(root, relative), encoding='utf-8') as handle:
        return handle.read()


class ReleaseCheck(unittest.TestCase):
    def test_version_is_the_first_word_of_the_version_file(self):
        with tempfile.TemporaryDirectory() as root:
            write(os.path.join(root, 'VERSION'), 'v0.4.0 (abc123def456)\n')
            self.assertEqual(release_check.installed_version(root), 'v0.4.0')
            self.assertEqual(release_check.installed_version(os.path.join(root, 'nowhere')), 'unknown')

    def test_check_can_be_switched_off(self):
        os.environ['SSAI_UPDATE_CHECK'] = 'off'
        try:
            answer = release_check.check('.')
        finally:
            del os.environ['SSAI_UPDATE_CHECK']
        self.assertFalse(answer['enabled'])
        self.assertFalse(answer['update_available'])

    def test_a_plain_http_download_address_is_refused(self):
        with self.assertRaises(release_check.ReleaseError):
            release_check._check_url_is_safe('http://example.com/pkg.tar.gz')

    def test_check_reports_newer_release(self):
        with tempfile.TemporaryDirectory() as work:
            _, _, api = make_package(work, 'v2')
            write(os.path.join(work, 'VERSION'), 'v1 (abc)\n')
            os.environ['SSAI_UPDATE_API'] = api
            try:
                answer = release_check.check(work)
            finally:
                del os.environ['SSAI_UPDATE_API']
        self.assertTrue(answer['update_available'])
        self.assertEqual((answer['installed'], answer['latest']), ('v1', 'v2'))


@unittest.skipUnless(CAN_RUN, 'needs bash, curl, tar and sha256sum on Linux')
class PackageUpdate(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.mkdtemp()
        self.root = os.path.join(self.work, 'install')
        make_install(self.root)

    def tearDown(self):
        shutil.rmtree(self.work, ignore_errors=True)

    def test_check_exits_10_when_a_newer_release_exists(self):
        _, _, api = make_package(self.work, 'v2')
        result = run_updater(self.root, api, '--check')
        self.assertEqual(result.returncode, 10, result.stdout + result.stderr)
        self.assertEqual(read(self.root, 'VERSION').split()[0], 'v1')     # checking changes nothing

    def test_update_replaces_code_and_keeps_the_machines_own_files(self):
        _, _, api = make_package(self.work, 'v2')
        result = run_updater(self.root, api)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(read(self.root, 'VERSION').split()[0], 'v2')
        self.assertTrue(os.path.exists(os.path.join(self.root, 'brand_new.txt')))
        self.assertFalse(os.path.exists(os.path.join(self.root, 'only_in_old.txt')), 'a file the release dropped is removed')
        self.assertEqual(read(self.root, 'backend/instance/secret.txt'), 'keep me\n')
        self.assertEqual(read(self.root, '.env'), 'KEY=keep\n')

    def test_running_again_says_already_up_to_date(self):
        _, _, api = make_package(self.work, 'v2')
        run_updater(self.root, api)
        again = run_updater(self.root, api)
        self.assertEqual(again.returncode, 0)
        self.assertIn('already up to date', again.stdout)

    def test_a_package_that_does_not_match_its_checksum_is_refused(self):
        package, checksum, api = make_package(self.work, 'v2')
        write(checksum, '0' * 64 + '  ' + os.path.basename(package) + '\n')
        result = run_updater(self.root, api)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('checksum', result.stderr)
        self.assertEqual(read(self.root, 'VERSION').split()[0], 'v1')
        self.assertFalse(os.path.exists(os.path.join(self.root, 'brand_new.txt')))

    def test_a_package_claiming_another_version_is_refused(self):
        _, _, api = make_package(self.work, 'v2', claimed_version='v0')
        result = run_updater(self.root, api)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(read(self.root, 'VERSION').split()[0], 'v1')

    def test_a_package_with_paths_outside_its_folder_is_refused(self):
        _, _, api = make_package(self.work, 'v2', evil_path=True)
        result = run_updater(self.root, api)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(os.path.exists(os.path.join(self.work, 'escaped.txt')))
        self.assertEqual(read(self.root, 'VERSION').split()[0], 'v1')

    def test_failing_tests_put_the_previous_version_back(self):
        _, _, api = make_package(self.work, 'v2', passing_tests=False)
        result = run_updater(self.root, api)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('previous version is restored', result.stderr)
        self.assertEqual(read(self.root, 'VERSION').split()[0], 'v1')
        self.assertIn('"v1"', read(self.root, 'backend/app.py'))
        self.assertFalse(os.path.exists(os.path.join(self.root, 'brand_new.txt')), 'files only the new version brought are removed')
        self.assertTrue(os.path.exists(os.path.join(self.root, 'only_in_old.txt')), 'files the new version removed come back')
        self.assertEqual(read(self.root, 'backend/instance/secret.txt'), 'keep me\n')

    def test_update_sh_hands_a_non_git_install_to_the_package_updater(self):
        shutil.copy(os.path.join(SOURCE, 'deploy/update.sh'), os.path.join(self.root, 'deploy/update.sh'))
        _, _, api = make_package(self.work, 'v2')
        env = dict(os.environ, SSAI_UPDATE_API=api)
        result = subprocess.run(['bash', os.path.join(self.root, 'deploy/update.sh'), '--no-restart'],
                                capture_output=True, text=True, env=env, timeout=120)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(read(self.root, 'VERSION').split()[0], 'v2')

    def test_target_option_updates_an_install_from_a_fresh_package(self):
        """How an install that predates this updater is brought up to date: run the new package's script on the old folder."""
        shutil.rmtree(self.root)
        os.makedirs(os.path.join(self.root, 'backend'))
        write(os.path.join(self.root, 'backend/app.py'), 'old\n')
        write(os.path.join(self.root, 'VERSION'), 'oldsha (oldsha)\n')
        write(os.path.join(self.root, 'requirements.txt'), 'flask\n')
        os.makedirs(os.path.join(self.root, 'swarmsentinel-env/bin'))
        os.symlink(sys.executable, os.path.join(self.root, 'swarmsentinel-env/bin/python3'))
        package, _, api = make_package(self.work, 'v2')
        fresh = os.path.join(self.work, 'fresh')
        os.makedirs(fresh)
        with tarfile.open(package) as archive:
            archive.extractall(fresh, filter='data') if hasattr(tarfile, 'data_filter') else archive.extractall(fresh)
        env = dict(os.environ, SSAI_UPDATE_API=api)
        result = subprocess.run(['bash', os.path.join(fresh, 'SwarmSentinel/deploy/update-package.sh'),
                                 '--no-restart', '--target', self.root], capture_output=True, text=True, env=env, timeout=120)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(read(self.root, 'VERSION').split()[0], 'v2')
        self.assertTrue(os.path.exists(os.path.join(self.root, 'deploy/update-package.sh')))


if __name__ == '__main__':
    unittest.main()
