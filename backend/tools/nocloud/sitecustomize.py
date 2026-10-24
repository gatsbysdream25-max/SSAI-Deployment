"""Test guard: nothing in a test run may reach the internet.

Python imports a module called `sitecustomize` by itself at start-up if its folder is on PYTHONPATH.
run_all_tests.py puts this folder there, so every test file runs with this guard and no test file had to change.

What it does, in plain words:
  * a connection to a public address is refused (loopback and private LAN addresses stay allowed, because a test may
    talk to a local fake server, and a local Ollama is never "the cloud");
  * a DNS lookup for any real name (api.groq.com, ...) fails, so a forgotten mock cannot quietly go out;
  * every refusal is appended to the file named in NOCLOUD_LOG, so the runner can report it.
"""
import ipaddress
import os
import socket

_LOG = os.environ.get("NOCLOUD_LOG")
_real_getaddrinfo = socket.getaddrinfo
_real_connect = socket.socket.connect
_real_connect_ex = socket.socket.connect_ex


def _note(what):
    if _LOG:
        try:
            with open(_LOG, "a", encoding="utf-8") as f:
                f.write(f"{os.getpid()} {os.path.basename(os.environ.get('NOCLOUD_TEST', '?'))} {what}\n")
        except OSError:
            pass


def _is_local(host):
    """True for localhost and for loopback / private / link-local addresses written as numbers."""
    if host in ("localhost", "localhost.localdomain", "", None):
        return True
    try:
        ip = ipaddress.ip_address(str(host).strip("[]"))
    except ValueError:
        return False                                   # a real name: only allowed if it is localhost
    return ip.is_loopback or ip.is_private or ip.is_link_local


def _guarded_getaddrinfo(host, *args, **kwargs):
    if isinstance(host, bytes):
        host = host.decode("ascii", "ignore")
    if not _is_local(host):
        _note(f"BLOCKED lookup {host}")
        raise socket.gaierror(socket.EAI_NONAME, f"test guard: no internet lookups in tests ({host})")
    return _real_getaddrinfo(host, *args, **kwargs)


def _guarded_connect(self, address):
    if isinstance(address, tuple) and self.family in (socket.AF_INET, socket.AF_INET6) and not _is_local(address[0]):
        _note(f"BLOCKED connect {address[0]}:{address[1] if len(address) > 1 else ''}")
        raise OSError(f"test guard: no internet connections in tests ({address[0]})")
    return _real_connect(self, address)


def _guarded_connect_ex(self, address):
    if isinstance(address, tuple) and self.family in (socket.AF_INET, socket.AF_INET6) and not _is_local(address[0]):
        _note(f"BLOCKED connect {address[0]}")
        return 111                                     # ECONNREFUSED
    return _real_connect_ex(self, address)


if os.environ.get("NOCLOUD_GUARD") == "1":
    socket.getaddrinfo = _guarded_getaddrinfo
    socket.socket.connect = _guarded_connect
    socket.socket.connect_ex = _guarded_connect_ex
