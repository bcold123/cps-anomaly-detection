# Walkthrough — read this before you present

Goes through the code in the order it runs. If you can follow this page, you
can answer anything the judges ask about the program.

---

## The 30-second version

> An attacker is going after our LiDAR in three stages: first they scan it,
> then they flood it, then they start feeding it fake distance readings that
> are hidden among the real ones. We built one detector for each stage. The
> first two are simple rules, because we can write down exactly what those
> attacks look like. The third one needs machine learning, because a fake
> distance reading looks perfectly normal on its own — the only way to catch
> it is to notice the LiDAR no longer agrees with the radar. Then an AI agent
> ties the alerts together and tells the operator what to do.

---

## File 1 — `sensor_stream.py` (the fake world)

**What it is:** everything the detector sees comes from here. It plays the part
of the vehicle's network *and* the attacker.

**Why it exists:** we cannot bring a real autonomous vehicle and a real
attacker into the room.

**The one thing to understand:** a `Packet` is one message arriving at the
vehicle's server. It carries four things — who sent it, which sensor, which
part of the device was asked for, and what the reading was.

**The clever bit, and worth pointing at:** in Stage 3 the fake readings are
generated with the *same* amount of noise as the real ones and a steady offset.
That is on purpose. If we made the fake data obviously jagged, catching it
would prove nothing. It has to be believable for the demo to mean anything.

---

## File 2 — `rule_detectors.py` (the two simple detectors)

### `ReconDetector` — who is talking to us?

Keeps a list of the computers that belong on this network. Two conditions:

1. Is this address on the list? If not, it is a stranger.
2. Is that stranger touching lots of *different* registers?

**Why condition 2 matters:** a normal computer reads the same one or two
registers forever. A scanner walks through many, because it is trying to find
out what exists. That difference is the fingerprint.

**The line to say:** *"Our scanner runs at 11 packets per second. That is
quieter than normal traffic. No volume alarm on earth would catch it — which is
exactly why we needed a detector that looks at who is talking instead of how
much."*

### `FloodDetector` — how much are they saying?

Learns the normal packet rate during the quiet period, then alarms when the
rate goes 5× above it for three ticks in a row.

**Why three ticks:** one noisy tick is not an attack, and false alarms are
expensive. If we cry wolf, the operator stops listening.

It also records **which IP** sent the most packets. That is what lets the agent
later notice the flood and the scan came from the same computer.

---

## File 3 — `ml_detector.py` (the machine learning)

### Why ML here and not a rule

The other two attacks have obvious fingerprints. False data injection does not.
Every fake reading is smooth, in range, and believable. There is no single
number you can point at. The attack only exists as a *pattern across several
measurements at once* — and finding patterns nobody wrote down is exactly what
machine learning is for.

### What an Isolation Forest is, in plain English

Imagine plotting all your normal data as a cloud of points. To fence off a
point in the middle of the cloud, you need many cuts. To fence off a point
sitting out on its own, you need very few. Isolation Forest measures how few
cuts it takes. **Few cuts = odd point = anomaly.**

Two reasons we chose it:

1. **It trains on normal data only.** We never have to show it an attack, which
   matters because we cannot collect every possible attack in advance.
2. **It is small and fast** enough to run on a Raspberry Pi.

### The three features

| Feature | What it means |
|---|---|
| `lidar_change` | how much the LiDAR reading moved since last tick |
| `radar_change` | how much the radar reading moved since last tick |
| `disagreement` | how far apart the two sensors are right now |

`disagreement` is what catches the attack. `radar_change` is there to *prevent
false alarms*: if both sensors moved, the object really moved and nothing is
wrong. If only the LiDAR moved, something is wrong with the LiDAR.

### The mistake we made, and this is a good story to tell

We first included the raw distance as a feature. It produced false alarms. The
training period covered 40–53 m, so when the car later drove up to something
22 m away, the model called it an attack. Nothing was wrong — the object was
just closer than anything it had been shown.

We removed it, and it gave us a rule we kept:

> **Feed the model things that should always stay the same, not things that are
> allowed to change.** A distance of 22 m is perfectly normal. Two sensors
> disagreeing by 9 m is never normal.

### Not a black box

`explain()` compares each feature against what was seen in training and reports
which ones are furthest out of line, in standard deviations. The model alone
only says "this is odd," which is not something an operator can act on. Every
alert we print names the feature, its value, and what normal looks like.

---

## File 4 — `ai_agent.py` (the agent)

**What makes it an agent and not a print statement** — three things:

1. **It remembers.** It holds the whole incident, not just the latest alert.
2. **It connects events.** Same IP did the recon *and* the flood, in that
   order → one attacker with a plan. That changes what the operator should do.
3. **It decides and prioritises.** Severity, then actions in urgency order.

**Why there is no language model in it:** everything the agent says is built
from numbers the detectors actually measured, so it **cannot make something
up**. There is a commented-out hook at the bottom showing where a language
model would go if we wanted nicer wording — deliberately kept off the decision
path.

If a judge asks "where is the AI?", the honest answer is: the machine learning
is the Isolation Forest in `ml_detector.py`, and the agent is a reasoning layer
on top of it. We chose not to put a language model on the safety path, and
that was a decision, not a shortcut.

---

## File 5 — `detect.py` (the main loop)

Runs ten times a second. Each pass:

```
get this tick's packets
    -> count them per sensor, average the readings
    -> Detector 1: any unknown IPs?          (recon)
    -> Detector 2: is the rate too high?     (flooding)
    -> Detector 3: does the ML flag it?      (false data)
    -> print anything new
```

Two phases:

- **First 20 seconds:** watch quietly, learn the normal packet rate, collect
  training rows. Nothing is flagged. *You cannot spot abnormal until you know
  what normal is.*
- **After that:** train the model, then watch.

At the end, everything goes to the agent for the final report.

---

## Questions you will get

**"Where is the machine learning, exactly?"**
`ml_detector.py`. An Isolation Forest from scikit-learn, trained on 200 samples
of normal driving, scoring three features every tenth of a second. We used a
rule for the other two attacks on purpose, because a rule is clearer, faster,
and easier to defend when you can write down exactly what wrong looks like.

**"How do you know it isn't just flagging noise?"**
Two safeguards. The anomaly has to persist three ticks in a row, and we only
report it if we can name which feature is out of line. We ran five different
noise seeds — all three attacks caught every time, no false alarms.

**"What if the attacker fakes a known IP address?"**
Then the recon detector misses them, and we would say so. But the flooding and
false-data detectors both look at *behaviour* rather than identity, so they
would still fire. That layering is the point: no single detector carries the
whole system.

**"Why does disagreement catch it when the fake readings look normal?"**
Because the radar is watching the same object. The attacker controls the LiDAR
feed, not physics. To hide, they would have to fake every sensor consistently
at the same time, which is a much harder attack.

**"What is next?"**
Preventive measures — right now the system detects and advises but the vehicle
does not act automatically. After that, replaying the real CIC Modbus 2023
capture instead of our simulator.

---

## If the demo breaks on stage

`python3 detect.py` needs only `scikit-learn` and `numpy`. If the laptop cannot
install them, say so and show the saved terminal output instead — take a
screenshot of a good run tonight and put it on a backup slide.
