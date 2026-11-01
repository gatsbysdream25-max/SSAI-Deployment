"""The command line:  ssai-agent enroll | run | scan | status | version

  enroll   trade a one-time code from the hub's admin for this PC's own credential
  run      watch this PC and report to the hub (the Windows scheduled task runs this)
  scan     look once and print what the sensors find, without sending anything (to see what it does)
  status   show the settings and whether the hub accepts this PC's credential
"""
import argparse
import logging
import logging.handlers
import os
import signal
import sys
import threading

from . import __version__, agent, config, hub, sensors, state as state_module


def build_parser():
    parser = argparse.ArgumentParser(prog="ssai-agent", description="SwarmSentinel agent for Windows")
    commands = parser.add_subparsers(dest="command", required=True)
    enroll = commands.add_parser("enroll", help="join a hub with a one-time enrollment code")
    enroll.add_argument("--hub", required=True, help="the hub's address, e.g. http://192.168.1.20:5000")
    enroll.add_argument("--code", required=True, help="the single-use enrollment code from the hub's Settings page")
    enroll.add_argument("--node-id", default=None, help="how this PC is named on the dashboard (default: its computer name)")
    commands.add_parser("run", help="watch this PC and report to the hub")
    commands.add_parser("scan", help="look once and print the findings, sending nothing")
    commands.add_parser("status", help="show the settings and test the hub connection")
    commands.add_parser("version", help="print the agent's version")
    return parser


def start_logging(to_file):
    """Log to the console, and to a size-limited file in the agent's folder when running for real."""
    handlers = [logging.StreamHandler()]
    if to_file:
        os.makedirs(config.data_folder(), exist_ok=True)
        handlers.append(logging.handlers.RotatingFileHandler(
            os.path.join(config.data_folder(), "agent.log"), maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"))
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s %(message)s", handlers=handlers)


def command_enroll(args):
    if not config.can_write_data_folder():
        print(f"This account cannot write to {config.data_folder()}. Run in an administrator PowerShell. "
              "(Your enrollment code has NOT been used.)", file=sys.stderr)
        return 1
    node_id = args.node_id or config.default_node_id()
    saved, problem = hub.enroll(args.hub, args.code, node_id, config.default_node_id())
    if saved is None:
        print(f"Could not enroll: {problem}", file=sys.stderr)
        return 1
    try:
        config.save_settings(config.Settings(**saved))
    except OSError as error:
        print(f"Enrolled, but could not save the credential ({error}). Ask the hub admin for a new code made for "
              f"'{saved['node_id']}' and enroll again.", file=sys.stderr)
        return 1
    print(f"Enrolled as '{saved['node_id']}'. The credential is stored in {config.data_folder()} (not shown here).")
    return 0


def command_run(_args):
    settings = config.load_settings()
    if settings is None:
        print("This PC is not enrolled yet. Run: ssai-agent enroll --hub URL --code CODE", file=sys.stderr)
        return 1
    start_logging(to_file=True)
    state = state_module.State()
    runner = agent.AgentRunner(hub.HubClient(settings), state, sensors.all_sensors(state))
    stop = threading.Event()
    for name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), lambda *_: stop.set())
    runner.run_forever(stop)
    return 0


def command_scan(_args):
    start_logging(to_file=False)
    state = state_module.State(path=os.path.join(config.data_folder(), "dry-run-state.json"))
    runner = agent.AgentRunner(None, state, sensors.all_sensors(state))
    total = 0
    for sensor in runner.sensors:
        for finding in runner.run_sensor(sensor, send=False):
            total += 1
            print(f"[{finding.severity.upper():6}] {sensor.agent_name}: {finding.description}")
    for sensor in runner.sensors:
        if sensor.problem:
            print(f"[BLIND ] {sensor.agent_name}: {sensor.problem}")
    print(f"{total} finding(s). (The first look of the port and sign-in sensors only records what is normal.)")
    return 0


def command_status(_args):
    settings = config.load_settings()
    print(f"ssai-agent {__version__}")
    if settings is None:
        print("Not enrolled.")
        return 1
    print(f"Machine name: {settings.node_id}\nHub:          {settings.api}")
    code, _ = hub.http_transport("POST", settings.api + "/node/heartbeat", {}, settings.token)
    messages = {200: "connected; the hub accepts this PC's credential", 0: "cannot reach the hub",
                401: "the hub rejected the credential (revoked or replaced): ask for a new enrollment code"}
    print("Connection:   " + messages.get(code, f"unexpected answer (HTTP {code})"))
    return 0 if code == 200 else 1


def main(argv=None):
    args = build_parser().parse_args(argv)
    handlers = {"enroll": command_enroll, "run": command_run, "scan": command_scan, "status": command_status,
                "version": lambda _a: print(f"ssai-agent {__version__}") or 0}
    return handlers[args.command](args)
