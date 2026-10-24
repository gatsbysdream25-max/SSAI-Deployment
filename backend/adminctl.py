#!/usr/bin/env python3
"""Admin account command line. Run on the hub machine (deploy/set-password.sh wraps this).

  adminctl.py set-password               prompt for a new dashboard password
  adminctl.py set-password --generate    make a strong random one and print it once
  adminctl.py set-password --generate --out FILE   ...and write it to FILE (mode 600) instead of printing it
  adminctl.py status                     say whether a password is set

The password is stored only as a salted scrypt hash in <data dir>/backend/instance/admin.json. There is no way to
read it back: to recover access, set a new one. Every signed-in session ends when the password changes.
"""
import argparse
import getpass
import os
import secrets
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [HERE, os.path.join(HERE, 'agents')]
import auth  # noqa: E402


def main(argv=None):
    """Read the command-line arguments and either report whether an admin password is set or set a new one.
    Returns the process exit code (0 on success, 1 if the password was rejected or the two entries differed).
    """
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)
    sp = sub.add_parser('set-password')
    sp.add_argument('--generate', action='store_true')
    sp.add_argument('--out')
    sub.add_parser('status')
    args = ap.parse_args(argv)

    if args.cmd == 'status':
        print('admin password: ' + ('set' if auth.load_admin() else 'NOT SET (run: deploy/set-password.sh)'))
        return 0

    if args.generate:
        pw = secrets.token_urlsafe(18)
    else:
        pw = getpass.getpass('New admin password (at least %d characters): ' % auth.MIN_PASSWORD_LEN)
        if pw != getpass.getpass('Again: '):
            print('The two entries do not match.', file=sys.stderr)
            return 1
    try:
        auth.set_admin_password(pw)
    except ValueError as e:
        print(f'Not accepted: {e}', file=sys.stderr)
        return 1
    if args.generate:
        if args.out:
            fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'w') as f:
                f.write(pw + '\n')
            print(f'Password written to {args.out} (mode 600). Read it, then delete the file.', file=sys.stderr)
        else:
            print(pw)
    else:
        print('Admin password set.', file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main())
