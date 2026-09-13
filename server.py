"""
server.py
=========
STEP 3 OF THE PIPELINE: the vehicle system server.

This is the program the attacker is trying to fool. It listens for sensor
packets, and every packet that arrives goes straight through the same three
detectors from the offline demo.

    python3 server.py                    # listen on all interfaces, port 9999
    python3 server.py --train 20         # learn normal for 20s, then watch

Then, from another terminal:

    python3 sensor_node.py --fake --server 127.0.0.1
    python3 sensor_node.py --fake --sensor radar --register 10 --server 127.0.0.1


================================================================
THE MOST IMPORTANT IDEA IN THIS FILE: WHO DECIDES WHAT IS TRUE
================================================================

Every packet claims things. It claims which sensor it came from. It carries a
sequence number and a timestamp saying when it was sent.

The server does not believe any of it for security purposes.

Three facts the server establishes FOR ITSELF, and why each one matters:

  1. WHO SENT IT.
     Taken from the UDP socket (`recvfrom` hands us the real source address),
     never from a field inside the packet. If we let a packet tell us who sent
     it, an attacker would simply write "192.168.1.10" in that field and our
     reconnaissance detector would never see them. The address the operating
     system reports is not something the sender can freely choose.

  2. WHEN IT ARRIVED.
     Measured with the server's own clock at the moment of arrival, not read
     from the `sent_at` field. Our flood detector works by counting packets
     per second. If an attacker sending 600 packets a second stamped them all
     as "one second apart", and we believed it, the flood would be invisible.
     Arrival time is ours to measure and cannot be forged.

  3. WHETHER THE READING IS PLAUSIBLE.
     That is what the machine learning model decides, by comparing the LiDAR
     against the radar. The packet gets no say.

The rule underneath all three:

    TRUST WHAT YOU MEASURED. DO NOT TRUST WHAT YOU WERE TOLD.

`seq` and `sent_at` are still useful -- for spotting dropped packets and
measuring network delay when everything is healthy. We just never let them
drive a security decision.
"""

import argparse
import json
import socket
import time
from collections import defaultdict

from ai_agent import AIAgent
from ml_detector import MLDetector, make_features
from rule_detectors import FloodDetector, ReconDetector
from sensor_stream import Packet

# The devices allowed to send us sensor data. In a real vehicle this comes
# from your network configuration, not a hard-coded list.
KNOWN_DEVICES = {
    "127.0.0.2": "lidar sensor node",
    "127.0.0.3": "radar sensor node",
    "192.168.1.10": "vehicle main computer",
    "192.168.1.11": "sensor gateway",
}

TICK = 0.1          # we make a decision ten times a second


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=9999)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--train", type=float, default=20.0,
                        help="seconds of quiet learning before watching")
    parser.add_argument("--stop-after", type=float, default=0.0,
                        help="exit after this many seconds (0 = run forever)")
    args = parser.parse_args()

    # ------------------------------------------------------------------
    # Open the socket. Non-blocking, so the decision loop keeps ticking
    # even when no packets are arriving -- silence is information too.
    # ------------------------------------------------------------------
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.host, args.port))
    sock.setblocking(False)

    recon_detector = ReconDetector(known_devices=KNOWN_DEVICES)
    flood_detector = FloodDetector()
    ml = MLDetector()
    agent = AIAgent()

    started = time.time()
    previous_lidar = None
    previous_radar = None
    ml_cooldown = 0.0
    trained = False

    print("=" * 70)
    print(f"VEHICLE SERVER listening on {args.host}:{args.port}")
    print("=" * 70)
    print(f"Learning what normal looks like for {args.train:.0f} seconds...")
    print()

    while True:
        tick_ends = time.time() + TICK
        packets = []

        # --------------------------------------------------------------
        # Drain everything that arrived during this tick.
        # --------------------------------------------------------------
        while time.time() < tick_ends:
            try:
                data, address = sock.recvfrom(2048)
            except BlockingIOError:
                time.sleep(0.002)      # nothing waiting; do not spin the CPU
                continue

            source_ip = address[0]         # FACT 1: who, from the socket
            arrived_at = time.time()       # FACT 2: when, by our own clock

            try:
                body = json.loads(data.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                # Malformed packet. Still worth counting: a flood of garbage
                # is still a flood, and we do not want a bad packet to be a
                # way of hiding from us.
                packets.append(Packet(
                    time=arrived_at - started,
                    source_ip=source_ip,
                    sensor="lidar",
                    register=-1,
                    distance_m=None,
                ))
                continue

            packets.append(Packet(
                time=arrived_at - started,
                source_ip=source_ip,
                sensor=body.get("sensor", "unknown"),
                register=int(body.get("register", 0)),
                distance_m=body.get("distance_m"),
            ))

        now = time.time() - started
        if args.stop_after and now > args.stop_after:
            break

        # --------------------------------------------------------------
        # Exactly the same processing as the offline demo from here on.
        # Nothing in the detectors changed to support live data, which is
        # the payoff of keeping hardware separate from detection.
        # --------------------------------------------------------------
        readings = defaultdict(list)
        counts = defaultdict(int)
        for p in packets:
            counts[p.sensor] += 1
            if p.distance_m is not None:
                readings[p.sensor].append(p.distance_m)

        rates = {s: counts[s] / TICK for s in ("lidar", "radar")}

        lidar_avg = (sum(readings["lidar"]) / len(readings["lidar"])
                     if readings["lidar"] else previous_lidar)
        radar_avg = (sum(readings["radar"]) / len(readings["radar"])
                     if readings["radar"] else previous_radar)

        if lidar_avg is None or radar_avg is None:
            continue                    # not enough data yet to say anything

        features = make_features(lidar_avg, previous_lidar,
                                 radar_avg, previous_radar)

        # ---- learning phase -------------------------------------------
        if now < args.train:
            ml.collect(features)
            flood_detector.learn_normal("lidar", rates["lidar"])
            flood_detector.learn_normal("radar", rates["radar"])
            previous_lidar, previous_radar = lidar_avg, radar_avg
            continue

        if not trained:
            rows = ml.train()
            trained = True
            print(f"[{now:5.1f}s] Learned normal from {rows} samples. "
                  f"Watching now.")
            print(f"          Normal LiDAR traffic: "
                  f"{flood_detector.normal_rate.get('lidar', 0):.0f} packets/sec")
            print()

        # ---- detector 1: unknown computers ----------------------------
        for alert in recon_detector.check(packets, now):
            agent.observe(alert)
            print(f"[{now:5.1f}s] *** RECONNAISSANCE DETECTED ***")
            print(f"          Unknown computer {alert['ip']} probed "
                  f"{alert['registers_probed']} different registers "
                  f"at {alert['rate']:.0f} packets/sec.")
            print()

        # ---- detector 2: query flooding -------------------------------
        for alert in flood_detector.check(rates, now, packets):
            agent.observe(alert)
            print(f"[{now:5.1f}s] *** QUERY FLOODING DETECTED ***")
            print(f"          {alert['sensor']} receiving "
                  f"{alert['rate']:.0f} packets/sec from {alert['ip']} "
                  f"({alert['times_normal']:.0f}x normal).")
            print()

        # ---- detector 3: the machine learning model -------------------
        confirmed, score = ml.check(features)
        if confirmed and now > ml_cooldown:
            reasons = ml.explain(features)
            if reasons:
                ml_cooldown = now + 5.0
                agent.observe({"type": "FALSE_DATA", "time": now,
                               "score": score, "reasons": reasons})
                print(f"[{now:5.1f}s] *** SUSPICIOUS SENSOR DATA "
                      f"(machine learning) ***")
                for r in reasons[:2]:
                    print(f"          - {r['feature']}: {r['value']} "
                          f"(normally about {r['normal']}) -> "
                          f"{r['how_odd']} standard deviations "
                          f"{r['direction']}")
                print()

        previous_lidar, previous_radar = lidar_avg, radar_avg

    print()
    print(agent.report())
    sock.close()


if __name__ == "__main__":
    main()