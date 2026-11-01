"""The agent's main loop: run each sensor when it is due and send what it finds to the hub.

One sensor failing (a Windows tool missing, a permission refused) is logged and the others carry on, so one broken check
never silences the whole PC.
"""
import logging
import os
import time
from datetime import datetime, timezone

log = logging.getLogger("agent")
TICK_SECONDS = 5                    # how often the loop wakes to see whether any sensor is due


def interval_scale():
    """SSAI_AGENT_INTERVAL_SCALE=0.1 makes every sensor look ten times as often (for testing); 1 is normal.
    Never below 0.02, so a typo cannot make the agent hammer the PC."""
    try:
        return max(float(os.environ.get("SSAI_AGENT_INTERVAL_SCALE", "1")), 0.02)
    except ValueError:
        return 1.0


class AgentRunner:
    def __init__(self, client, state, sensors, clock=time.monotonic):
        self.client = client
        self.state = state
        self.sensors = sensors
        self.clock = clock
        self.next_due = {s.agent_name: 0.0 for s in sensors}
        self.scans = {s.agent_name: 0 for s in sensors}
        self.found = {s.agent_name: 0 for s in sensors}
        self.told = {}                    # the last 'I am blind' reason already logged, per sensor
        self.interval_scale = interval_scale()

    def register_all(self):
        """Tell the hub every sensor exists, so they all show on the dashboard from the start."""
        for sensor in self.sensors:
            self.client.register(sensor.agent_name, sensor.role, sensor.description)

    def run_sensor(self, sensor, send=True):
        """One look by one sensor. Returns the findings (also when send=False, which the dry run uses)."""
        name = sensor.agent_name
        try:
            findings = sensor.scan()
        except Exception as error:                                   # a broken check must not stop the others
            log.error("%s failed: %s", name, error)
            findings = []
        self.scans[name] += 1
        self._report_problem(sensor)
        if send:
            self._send_new(sensor, findings)
            self._heartbeat(sensor)
            self.state.save()
        return findings

    def _report_problem(self, sensor):
        """Log a sensor's 'I cannot see' reason once (and again if it changes), not every minute."""
        name = sensor.agent_name
        if sensor.problem and sensor.problem != self.told.get(name):
            log.warning("%s is blind: %s", name, sensor.problem)
        self.told[name] = sensor.problem

    def _send_new(self, sensor, findings):
        for finding in findings:
            if self.state.should_send(finding.key):
                log.warning("FINDING [%s] %s: %s", finding.severity.upper(), finding.threat_type, finding.url)
                self.client.send_finding(finding, sensor.agent_name)
                self.state.mark_sent(finding.key)
                self.found[sensor.agent_name] += 1

    def _heartbeat(self, sensor):
        name = sensor.agent_name
        when = datetime.now(timezone.utc).isoformat()
        if self.client.heartbeat(name, self.scans[name], self.found[name], when) == 404:
            self.client.register(name, sensor.role, sensor.description)      # the hub lost us (new database): introduce again

    def run_due(self):
        """Run every sensor whose time has come."""
        now = self.clock()
        for sensor in self.sensors:
            if now >= self.next_due[sensor.agent_name]:
                self.run_sensor(sensor)
                self.next_due[sensor.agent_name] = now + sensor.interval * self.interval_scale

    def run_forever(self, stop_event):
        """Loop until stop_event is set (Ctrl-C, or the Windows task being stopped)."""
        self.register_all()
        log.info("watching with %d sensors", len(self.sensors))
        while not stop_event.is_set():
            self.run_due()
            if self.client.credential_rejected:
                log.error("the hub rejected this machine's credential; ask the admin for a new enrollment code")
            stop_event.wait(TICK_SECONDS)
