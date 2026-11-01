"""What the agent remembers between runs, so a restart does not forget or repeat itself.

Two things are kept: small facts the sensors need (like 'the newest failed-login I have already read'), and when each
finding was last sent, so the same problem is not re-sent every minute.
"""
import os
import time

from . import config, util

REPEAT_AFTER_SECONDS = 24 * 3600           # a problem that is still there is mentioned again once a day


class State:
    def __init__(self, path=None, clock=time.time):
        self.path = path or os.path.join(config.data_folder(), "state.json")
        self.clock = clock
        saved = util.read_json(self.path, {})
        self.facts = saved.get("facts", {})
        self.sent = saved.get("sent", {})          # finding key -> when it was last sent

    def save(self):
        util.write_json(self.path, {"facts": self.facts, "sent": self.sent})

    def get(self, name, default=None):
        return self.facts.get(name, default)

    def put(self, name, value):
        self.facts[name] = value

    def should_send(self, key):
        """True if this finding was never sent, or was last sent more than a day ago."""
        last = self.sent.get(key)
        return last is None or self.clock() - last >= REPEAT_AFTER_SECONDS

    def mark_sent(self, key):
        self.sent[key] = self.clock()
        self._forget_old_keys()

    def _forget_old_keys(self):
        """Keep the file small: drop findings not sent for a week."""
        cutoff = self.clock() - 7 * 24 * 3600
        for key in [k for k, when in self.sent.items() if when < cutoff]:
            del self.sent[key]
