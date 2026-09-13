"""
rule_detectors.py
=================
The two SIMPLE detectors. No machine learning here on purpose -- these two
attacks have such obvious fingerprints that a rule is clearer, faster, and
much easier to defend in the Q&A than a model would be.

    Detector 1: RECONNAISSANCE   -> looks at WHO is sending packets
    Detector 2: QUERY FLOODING   -> looks at HOW MANY packets arrive

A good rule of thumb, and a good line for the presentation:
    use a rule when you can write down exactly what "wrong" looks like,
    and use machine learning when you cannot.
We can write down "a computer we have never heard of is talking to us."
We cannot easily write down "this distance reading is subtly fake" --
that one goes to the ML model in ml_detector.py.
"""

from collections import defaultdict

from sensor_stream import KNOWN_DEVICES


class ReconDetector:
    """Detector 1 -- spot an unknown computer probing our devices.

    The idea is deliberately simple. We know which computers belong on this
    network. If packets arrive from an address that is not on that list, that
    alone is worth reporting. If that stranger is also poking at lots of
    DIFFERENT parts of the device, it is mapping us, which is reconnaissance.

    Why counting registers matters: a normal computer reads the same one or
    two registers over and over, forever. A scanner walks through many
    different ones, because it is trying to find out what exists.
    """

    def __init__(self, min_registers=8, known_devices=None):
        # How many different registers a stranger must touch before we call
        # it reconnaissance rather than a one-off stray packet.
        self.min_registers = min_registers

        # The addresses allowed on this network. The offline demo uses the
        # simulator's list; the live server passes in its own.
        self.known_devices = (KNOWN_DEVICES if known_devices is None
                              else known_devices)

        self.registers_seen = defaultdict(set)   # ip -> set of registers
        self.packet_count = defaultdict(int)     # ip -> how many packets
        self.first_seen = {}                     # ip -> time
        self.already_reported = set()

    def check(self, packets, now):
        """Look at this tick's packets. Return a list of new alerts."""
        alerts = []

        for p in packets:
            if p.source_ip in self.known_devices:
                continue                          # a computer we expect

            # This is a stranger. Start keeping notes on it.
            if p.source_ip not in self.first_seen:
                self.first_seen[p.source_ip] = now
            self.registers_seen[p.source_ip].add(p.register)
            self.packet_count[p.source_ip] += 1

        for ip, registers in self.registers_seen.items():
            if ip in self.already_reported:
                continue
            if len(registers) >= self.min_registers:
                self.already_reported.add(ip)
                alerts.append({
                    "type": "RECONNAISSANCE",
                    "time": now,
                    "ip": ip,
                    "registers_probed": len(registers),
                    "packets": self.packet_count[ip],
                    "rate": self.packet_count[ip] / max(now - self.first_seen[ip], 0.1),
                })
        return alerts


class FloodDetector:
    """Detector 2 -- spot a query flood.

    Even simpler: count how many packets arrive for each sensor each second.
    We learn what "normal" looks like during a quiet period at the start, then
    alarm when the count goes far above it.

    We wait for the rate to stay high for a few ticks in a row before
    alarming. One noisy tick is not an attack, and false alarms are expensive:
    if we cry wolf, the operator stops listening.
    """

    def __init__(self, multiplier=5.0, ticks_to_confirm=3):
        self.multiplier = multiplier            # how many times normal = attack
        self.ticks_to_confirm = ticks_to_confirm
        self.normal_rate = {}                   # sensor -> packets per second
        self.high_ticks = defaultdict(int)      # sensor -> consecutive hot ticks
        self.currently_flooding = set()

    def learn_normal(self, sensor, rate):
        """Called during the quiet training period at the start."""
        if sensor not in self.normal_rate:
            self.normal_rate[sensor] = rate
        else:
            # A slow running average, so one odd second does not move it much.
            self.normal_rate[sensor] = 0.9 * self.normal_rate[sensor] + 0.1 * rate

    def check(self, rates, now, packets=None):
        """rates:   {sensor: packets per second right now}
        packets: this tick's packets, so we can name who is responsible.

        Naming the source matters more than it looks. It is what lets the AI
        agent notice that the flood came from the same computer that did the
        reconnaissance earlier, which turns two separate alerts into one
        story about one attacker.
        """
        alerts = []
        top_talker = self._busiest_sender(packets)

        for sensor, rate in rates.items():
            normal = self.normal_rate.get(sensor, rate)
            limit = normal * self.multiplier

            if rate > limit:
                self.high_ticks[sensor] += 1
            else:
                self.high_ticks[sensor] = 0
                self.currently_flooding.discard(sensor)

            confirmed = self.high_ticks[sensor] >= self.ticks_to_confirm
            if confirmed and sensor not in self.currently_flooding:
                self.currently_flooding.add(sensor)
                alerts.append({
                    "type": "QUERY_FLOODING",
                    "time": now,
                    "sensor": sensor,
                    "ip": top_talker.get(sensor, "unknown"),
                    "rate": rate,
                    "normal_rate": normal,
                    "times_normal": rate / max(normal, 1.0),
                })
        return alerts

    @staticmethod
    def _busiest_sender(packets):
        """Which computer sent the most packets to each sensor this tick."""
        if not packets:
            return {}
        tally = {}
        for p in packets:
            tally.setdefault(p.sensor, {})
            tally[p.sensor][p.source_ip] = tally[p.sensor].get(p.source_ip, 0) + 1
        return {sensor: max(senders, key=senders.get)
                for sensor, senders in tally.items()}
