# LiDAR Intrusion Detection

Panther's Invent 2026 — Sandia Need Statement 2, *AI for Cyber Physical Systems*

Detects the three-stage attack on our autonomous vehicle's LiDAR and tells the
operator what to do about it.

---

## Run it

```bash
pip install scikit-learn numpy
python3 detect.py
```

That's it. No hardware, no network, no dataset download.

```bash
python3 detect.py --realtime   # true speed, for filming the 90-second video
python3 detect.py --seed 3     # different sensor noise, same result
```

---

## The attack we are defending against

An attacker on our network is going after the LiDAR in three stages:

**Stage 1 — Reconnaissance (22–28 s).** An unknown computer at `192.168.1.99`
probes the LiDAR, asking about many different registers to find out what is
there. It is deliberately quiet: about 11 packets per second, which is *less*
than normal traffic.

**Stage 2 — Query flooding (32–42 s).** The same computer blasts the LiDAR with
620 requests per second against a normal of 20. The sensor cannot keep up.

**Stage 3 — False data injection (48–60 s).** The dangerous one. The attacker
starts replacing real LiDAR distances with fake ones that are **disguised among
the real data** — smooth, in range, and completely believable one at a time.
The vehicle would happily drive on them.

---

## The three detectors, and why each one is built the way it is

| Stage | Detector | Question it asks | How it works |
|---|---|---|---|
| Recon | `ReconDetector` | **Who** is talking to us? | Rule: is this IP on our list of known devices, and how many different registers is it touching? |
| Flooding | `FloodDetector` | **How much** are they saying? | Rule: is the packet rate far above what we learned is normal? |
| False data | `MLDetector` | **Is what they say true?** | Machine learning: Isolation Forest on three features |

That split is the design, and it is the thing to explain first:

> **Use a rule when you can write down exactly what "wrong" looks like. Use
> machine learning when you cannot.**

We can write down "a computer we have never heard of is probing us." We cannot
write down "this distance reading is subtly fake" — every fake reading looks
fine on its own. That one needs a model.

---

## How the ML catches the disguised data

The Isolation Forest gets three numbers each tick:

1. `lidar_change` — how much the LiDAR reading moved
2. `radar_change` — how much the radar reading moved
3. `disagreement` — how far apart the two sensors are

Number 3 is what catches the attack, and this is the sentence for the slide:

> The fake readings look perfectly normal on their own. But the radar is
> watching the same object, and it did not move. **You cannot fake one sensor
> without disagreeing with all the others.**

In the run, disagreement goes from about 0.29 m normally to 9.8 m — roughly
**42 standard deviations** outside normal.

---

## Two mistakes we made and fixed (say these; they are good answers)

**We first fed the model the raw distance, and it produced false alarms.** The
training period happened to cover 40–53 m, so when the car later drove up to
something 22 m away, the model called it an attack. Nothing was wrong — the
object was just closer than anything it had seen. We removed the raw distance
and kept only *relative* features. **Feed a model things that should always
stay the same, not things that are allowed to change.**

**A single noisy radar tick triggered an alert at 29 s.** Real sensors produce
the occasional freak reading. We now require an anomaly to persist for three
ticks in a row before alerting. All three detectors use this same idea, because
a false alarm is expensive: cry wolf and the operator stops listening.

---

## The AI agent

The detectors produce facts. Facts are not much use to a person at 2 a.m. The
agent turns them into a decision and a to-do list. Three things make it an
agent rather than a print statement:

1. **It remembers** — it keeps a picture of the whole incident.
2. **It connects events** — it notices the recon and the flood came from the
   *same IP*, in that order, and says so: one attacker running a plan, not two
   unrelated problems.
3. **It decides and prioritises** — it sets a severity and puts the most urgent
   action first.

There is deliberately **no language model on the decision path**. Everything
the agent says is built from numbers the detectors actually measured, so it
cannot invent a reason that did not happen. `ai_agent.py` has a commented-out
hook showing where a language model *would* go if we only wanted nicer wording.

---

## What it prints

```
[ 22.7s] *** RECONNAISSANCE DETECTED ***
          Unknown computer 192.168.1.99 is probing the LiDAR.
          It has asked about 8 different registers, at only 11 packets/sec.
          That is far too quiet to trip a volume alarm, which is exactly the point.

[ 32.2s] *** QUERY FLOODING DETECTED ***
          The lidar is getting 620 packets/sec, mostly from 192.168.1.99.
          Normal is 20/sec, so this is 31 times too many.

[ 48.1s] *** SUSPICIOUS SENSOR DATA (machine learning) ***
          - disagreement: 9.8 (normally about 0.29) -> 42.4 standard deviations higher
          The LiDAR and the radar are looking at the same object and no longer agree.
          Each LiDAR reading looks fine on its own. Together they do not.
```

Followed by the agent's report with severity, the campaign link, and 13
numbered actions in priority order.

Verified on 5 different noise seeds: all three attacks caught every time, no
false alarms.

---

## The files

| File | What it is |
|---|---|
| `detect.py` | **The main program.** Run this. The whole loop is here. |
| `sensor_stream.py` | Pretends to be the vehicle's network and the attacker. Edit this to change the attack. |
| `rule_detectors.py` | The two simple detectors: recon and flooding |
| `ml_detector.py` | The machine learning model |
| `ai_agent.py` | Turns alerts into actionable steps |
| `WALKTHROUGH.md` | Read this before presenting — explains every file in order |

Roughly 600 lines total, over half of which are comments.

---

## Honest limitations

- **The data is simulated.** The attack model reproduces what the detectors
  measure — rate, unknown senders, sensor disagreement — but not real Modbus
  packet framing. Next step is replaying the CIC Modbus 2023 capture through
  the same detectors.
- **The recon detector trusts an allowlist.** If an attacker spoofs a known IP
  address, this detector will not see them. The flooding and false-data
  detectors still would, because they look at behaviour rather than identity.
- **The model is trained on 20 seconds of one situation.** Real deployment
  needs training data covering rain, night, tunnels, and heavy traffic, or
  those will look like attacks.
- **No preventive measures yet.** Right now the system detects and advises. The
  vehicle does not act on it automatically. That is the next piece.
