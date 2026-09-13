"""
detect.py
=========
THE MAIN PROGRAM. Run this one:

    python3 detect.py

WHAT IT DOES, top to bottom:

    1. Spend the first 20 seconds watching quietly and learning what normal
       looks like. Nothing is flagged during this time, on purpose -- you
       cannot spot abnormal until you know what normal is.
    2. Train the machine learning model on what it just saw.
    3. Watch the rest of the run and print an alert whenever one of the three
       detectors fires.
    4. Hand everything to the AI agent, which writes the final report.

THE LOOP RUNS 10 TIMES A SECOND. Each pass through the loop we:
    get this tick's packets  ->  count them  ->  run the three detectors
"""

import argparse
import time

from ai_agent import AIAgent
from ml_detector import MLDetector, make_features
from rule_detectors import FloodDetector, ReconDetector
from sensor_stream import SensorStream

TRAINING_SECONDS = 20.0     # quiet period at the start
TOTAL_SECONDS = 70.0
TICK = 0.1                  # 10 times a second


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--realtime", action="store_true",
                        help="run at true speed, for filming the demo video")
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args()

    stream = SensorStream(seed=args.seed)
    recon_detector = ReconDetector()
    flood_detector = FloodDetector()
    ml = MLDetector()
    agent = AIAgent()

    previous_lidar = None
    previous_radar = None
    ml_alert_cooldown = 0.0     # stops one attack printing 100 identical lines

    print("=" * 70)
    print("LiDAR INTRUSION DETECTION")
    print("=" * 70)
    print(f"Learning what normal looks like for the first "
          f"{TRAINING_SECONDS:.0f} seconds...")
    print()

    t = 0.0
    while t < TOTAL_SECONDS:
        packets = stream.packets_for_tick(t, TICK)

        # ---------------------------------------------------------------
        # Sort this tick's packets into per-sensor buckets so we can count
        # them and average the readings.
        # ---------------------------------------------------------------
        readings = {"lidar": [], "radar": []}
        counts = {"lidar": 0, "radar": 0}

        for p in packets:
            counts[p.sensor] += 1
            if p.distance_m is not None:
                readings[p.sensor].append(p.distance_m)

        rates = {s: counts[s] / TICK for s in counts}       # packets per second

        lidar_avg = (sum(readings["lidar"]) / len(readings["lidar"])
                     if readings["lidar"] else previous_lidar)
        radar_avg = (sum(readings["radar"]) / len(readings["radar"])
                     if readings["radar"] else lidar_avg)

        if lidar_avg is None:
            t += TICK
            continue

        features = make_features(lidar_avg, previous_lidar,
                                 radar_avg, previous_radar)

        # ---------------------------------------------------------------
        # PHASE 1 -- the quiet learning period
        # ---------------------------------------------------------------
        if t < TRAINING_SECONDS:
            ml.collect(features)
            flood_detector.learn_normal("lidar", rates["lidar"])
            flood_detector.learn_normal("radar", rates["radar"])

            if abs(t - TRAINING_SECONDS) < TICK:
                rows = ml.train()
                print(f"[{t:5.1f}s] Learned normal behaviour from {rows} "
                      f"samples. Watching for attacks now.")
                print(f"          Normal LiDAR traffic: "
                      f"{flood_detector.normal_rate['lidar']:.0f} packets/sec")
                print()

            previous_lidar = lidar_avg
            previous_radar = radar_avg
            t += TICK
            continue

        # ---------------------------------------------------------------
        # PHASE 2 -- watching for the three attacks
        # ---------------------------------------------------------------

        # --- Detector 1: unknown computer probing us ---------------------
        for alert in recon_detector.check(packets, t):
            agent.observe(alert)
            print(f"[{alert['time']:5.1f}s] *** RECONNAISSANCE DETECTED ***")
            print(f"          Unknown computer {alert['ip']} is probing the "
                  f"LiDAR.")
            print(f"          It has asked about "
                  f"{alert['registers_probed']} different registers, at only "
                  f"{alert['rate']:.0f} packets/sec.")
            print(f"          That is far too quiet to trip a volume alarm, "
                  f"which is exactly the point.")
            print()

        # --- Detector 2: query flooding ----------------------------------
        for alert in flood_detector.check(rates, t, packets):
            agent.observe(alert)
            print(f"[{alert['time']:5.1f}s] *** QUERY FLOODING DETECTED ***")
            print(f"          The {alert['sensor']} is getting "
                  f"{alert['rate']:.0f} packets/sec, mostly from "
                  f"{alert['ip']}.")
            print(f"          Normal is {alert['normal_rate']:.0f}/sec, so "
                  f"this is {alert['times_normal']:.0f} times too many.")
            print()

        # --- Detector 3: the ML model, looking for fake readings ----------
        confirmed, score = ml.check(features)

        if confirmed and t > ml_alert_cooldown:
            reasons = ml.explain(features)

            # We only shout about it if the model can tell us WHY. An
            # unexplained "the model says so" is not something an operator
            # can act on, and it is not something we would want to defend.
            if reasons:
                ml_alert_cooldown = t + 5.0
                alert = {
                    "type": "FALSE_DATA",
                    "time": t,
                    "score": score,
                    "reasons": reasons,
                }
                agent.observe(alert)
                print(f"[{t:5.1f}s] *** SUSPICIOUS SENSOR DATA "
                      f"(machine learning) ***")
                print(f"          The model has not seen readings like this "
                      f"before (score {score:.2f}).")
                for r in reasons[:3]:
                    print(f"          - {r['feature']}: {r['value']} "
                          f"(normally about {r['normal']}) "
                          f"-> {r['how_odd']} standard deviations "
                          f"{r['direction']} than usual")
                if any(r["feature"] == "disagreement" for r in reasons):
                    print(f"          The LiDAR and the radar are looking at "
                          f"the same object and no longer agree.")
                    print(f"          Each LiDAR reading looks fine on its "
                          f"own. Together they do not.")
                print()

        previous_lidar = lidar_avg
        previous_radar = radar_avg

        if args.realtime:
            time.sleep(TICK)
        t += TICK

    # ------------------------------------------------------------------
    print()
    print(agent.report())


if __name__ == "__main__":
    main()
