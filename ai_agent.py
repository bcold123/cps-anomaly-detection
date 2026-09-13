"""
ai_agent.py
===========
The AI agent.

WHAT IT IS FOR
    The detectors produce facts: "unknown IP", "rate is 30x normal", "the
    model flagged this reading". Facts are not much use to a person at 2 a.m.
    The agent's job is to turn those facts into a decision and a to-do list.

WHAT MAKES IT AN AGENT RATHER THAN A PRINT STATEMENT
    Three things, and these are the three worth saying in the presentation:

    1. IT REMEMBERS. It keeps a picture of the whole incident, not just the
       latest alert.
    2. IT CONNECTS EVENTS. If the same IP address did the reconnaissance and
       then the flood, that is one attacker running a campaign, not two
       unrelated problems. Saying so changes what the operator should do.
    3. IT DECIDES AND PRIORITISES. It puts a severity on the situation and
       orders the steps, so the most urgent thing is first.

    Notice there is no language model in here. Everything the agent says is
    built from numbers the detectors actually measured, which means it CANNOT
    make something up. There is an optional hook at the bottom if we want to
    add a language model later to reword things more naturally, but we keep it
    off the decision path on purpose.
"""


class AIAgent:
    def __init__(self):
        self.incidents = []          # everything that has happened
        self.suspects = {}           # ip -> list of what it did

    # ------------------------------------------------------------------
    def observe(self, alert):
        """Take in one alert and remember it."""
        self.incidents.append(alert)

        ip = alert.get("ip")
        if ip:
            self.suspects.setdefault(ip, []).append(alert["type"])

    # ------------------------------------------------------------------
    def assess(self):
        """Work out how bad the overall situation is."""
        kinds = {a["type"] for a in self.incidents}

        # An attacker who scanned us AND flooded us is running a campaign.
        campaign = "RECONNAISSANCE" in kinds and "QUERY_FLOODING" in kinds

        if "FALSE_DATA" in kinds:
            severity = "CRITICAL"
            summary = ("The vehicle is being fed distance readings that are "
                       "not real. This is the most dangerous of the three, "
                       "because the vehicle will happily drive on bad numbers "
                       "without knowing anything is wrong.")
        elif "QUERY_FLOODING" in kinds:
            severity = "HIGH"
            summary = ("A sensor is being overwhelmed with requests and is "
                       "falling behind. The vehicle is losing data it needs.")
        elif "RECONNAISSANCE" in kinds:
            severity = "MEDIUM"
            summary = ("Someone is mapping our equipment. Nothing is broken "
                       "yet, but this is normally what happens right before "
                       "an attack.")
        else:
            severity = "NONE"
            summary = "Nothing unusual seen."

        return severity, summary, campaign

    # ------------------------------------------------------------------
    def actions_for(self, alert):
        """The specific steps for one kind of alert."""

        if alert["type"] == "RECONNAISSANCE":
            return [
                f"Find out what {alert['ip']} is. Check the DHCP table and "
                f"the switch's MAC address table to see which physical port "
                f"it is plugged into.",
                f"If nobody claims it, disable that switch port. It probed "
                f"{alert['registers_probed']} different registers on the "
                f"LiDAR, which is not something legitimate equipment does.",
                "Add the address to the block list and keep watching. Whoever "
                "this is now knows the layout of our LiDAR.",
                "Nothing is damaged yet, so do not stop the vehicle for this "
                "alone. Treat it as a warning that an attack is likely next.",
            ]

        if alert["type"] == "QUERY_FLOODING":
            return [
                f"The {alert['sensor']} is receiving "
                f"{alert['rate']:.0f} packets per second against a normal of "
                f"{alert['normal_rate']:.0f}. That is "
                f"{alert['times_normal']:.0f} times too many.",
                "Rate-limit that source at the switch or gateway so the "
                "sensor can answer real requests again.",
                "Stop trusting this sensor until the flood ends. It is not "
                "lying to us, but it is too far behind to be useful.",
                "Check whether the same address showed up in an earlier "
                "reconnaissance alert. If it did, this is one planned attack, "
                "not bad luck.",
            ]

        if alert["type"] == "FALSE_DATA":
            steps = [
                "Stop using the LiDAR for driving decisions immediately. The "
                "numbers coming out of it are not measurements of the real "
                "world.",
                "Do not fall back on its last known reading either. A frozen "
                "wrong number is just as dangerous as a moving wrong one.",
                "Drive on the radar alone, and reduce speed, because one "
                "sensor means there is nothing left to cross-check against.",
            ]
            for reason in alert.get("reasons", [])[:2]:
                steps.append(
                    f"Evidence: {reason['feature']} is {reason['value']} "
                    f"when normal is about {reason['normal']} "
                    f"({reason['how_odd']} standard deviations {reason['direction']})."
                )
            steps.append(
                "Once the vehicle is safe, capture the traffic. Whoever is "
                "injecting these values has enough access to write to the "
                "sensor path, which is a bigger problem than the LiDAR."
            )
            return steps

        return []

    # ------------------------------------------------------------------
    def report(self):
        """The final write-up the operator reads."""
        severity, summary, campaign = self.assess()

        lines = []
        lines.append("=" * 70)
        lines.append("AI AGENT REPORT")
        lines.append("=" * 70)
        lines.append(f"SEVERITY: {severity}")
        lines.append("")
        lines.append("WHAT IS HAPPENING")
        lines.append("  " + summary)

        if campaign:
            repeat = [ip for ip, acts in self.suspects.items() if len(set(acts)) > 1]
            who = repeat[0] if repeat else "the same source"
            lines.append("")
            lines.append("  These alerts are not separate problems. The "
                         "reconnaissance and the")
            lines.append(f"  flooding both came from {who}, in that order. "
                         "That is one")
            lines.append("  attacker working through a plan: map the device "
                         "first, then hit it.")

        lines.append("")
        lines.append("WHAT TO DO, MOST URGENT FIRST")
        order = {"FALSE_DATA": 0, "QUERY_FLOODING": 1, "RECONNAISSANCE": 2}
        seen = set()
        step_number = 1

        for alert in sorted(self.incidents, key=lambda a: order.get(a["type"], 9)):
            if alert["type"] in seen:
                continue
            seen.add(alert["type"])
            lines.append("")
            lines.append(f"  [{alert['type']}]  first seen at "
                         f"{alert['time']:.1f} s")
            for step in self.actions_for(alert):
                lines.append(f"    {step_number}. {step}")
                step_number += 1

        lines.append("")
        lines.append("=" * 70)
        return "\n".join(lines)


# ----------------------------------------------------------------------
# OPTIONAL: hook for a real language model.
#
# We are not using this. It is here to show where it WOULD go if we wanted
# nicer wording. Note it only rephrases a report the rules already produced,
# so even if the model said something silly, it could not change what the
# system decided to do. Keeping the language model off the decision path is
# a deliberate safety choice, not a limitation.
#
#   import requests
#   def polish_with_llm(report_text):
#       r = requests.post("http://localhost:11434/api/generate", json={
#           "model": "llama3.1:8b",
#           "prompt": "Rewrite this security report for a driver who is not "
#                     "technical. Do not add any facts:\n\n" + report_text,
#           "stream": False,
#       })
#       return r.json()["response"]
# ----------------------------------------------------------------------
