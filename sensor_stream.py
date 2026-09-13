"""
sensor_stream.py
================
This file PRETENDS to be the vehicle's network. It makes up the packets that
would normally arrive from the sensors, and it also plays the part of the
attacker.

We need this because we cannot bring a real autonomous vehicle and a real
attacker into the room. Everything the detector sees comes from here, so if
you want to change the attack, this is the only file you edit.

WHAT A PACKET IS
    One packet = one message arriving at the vehicle's server.
    It says: who sent it, which sensor it is about, what part of the device
    was asked for, and what the reading was.

THE ATTACK, exactly as described in our plan:

    Stage 1  RECONNAISSANCE      (22-28 s)
             An unknown computer at 192.168.1.99 starts poking at the LiDAR.
             It sends very few packets, but it asks for lots of different
             parts of the device, trying to map what is there.

    Stage 2  QUERY FLOODING      (32-42 s)
             The same computer now blasts the LiDAR with requests, far more
             than the vehicle ever sends. The LiDAR cannot keep up.

    Stage 3  FALSE DATA INJECTION (48-60 s)
             The clever part. The attacker starts replacing real LiDAR
             distances with fake ones. Each fake number looks perfectly
             normal on its own -- it is smooth, it is in range, nothing
             about it screams "wrong". That is the whole point: it is
             DISGUISED among the real data.
             The only way to catch it is to notice that the LiDAR no longer
             agrees with the radar, which is looking at the same object.
"""

import math
import random
from dataclasses import dataclass


# The computers that are SUPPOSED to be on this network.
# Anything not on this list is a stranger.
KNOWN_DEVICES = {
    "192.168.1.10": "vehicle main computer",
    "192.168.1.11": "sensor gateway",
}

ATTACKER_IP = "192.168.1.99"


@dataclass
class Packet:
    """One message arriving at the vehicle server."""
    time: float          # seconds since we started
    source_ip: str       # who sent it
    sensor: str          # "lidar" or "radar"
    register: int        # which part of the device was asked for
    distance_m: float    # the reading, in metres (None if it was just a probe)


class SensorStream:
    """Produces the packets the vehicle server receives."""

    def __init__(self, seed=7):
        self.rng = random.Random(seed)
        self.probe_register = 0     # the attacker walks through registers

    # ------------------------------------------------------------------
    def true_distance(self, t):
        """Where the object in front of the car REALLY is.

        A slow wave, so the distance drifts between about 22 m and 58 m.
        Both sensors are trying to measure this same number.
        """
        return 40.0 + 18.0 * math.sin(t / 9.0)

    # ------------------------------------------------------------------
    def stage(self, t):
        """Which part of the attack is happening right now."""
        if 22.0 <= t < 28.0:
            return "recon"
        if 32.0 <= t < 42.0:
            return "flood"
        if 48.0 <= t < 60.0:
            return "injection"
        return "normal"

    # ------------------------------------------------------------------
    def packets_for_tick(self, t, dt):
        """Return every packet that arrived during this slice of time."""
        packets = []
        stage = self.stage(t)
        truth = self.true_distance(t)

        # --- normal traffic: the vehicle polls each sensor 20 times a second
        for sensor, noise, register in (("lidar", 0.20, 0), ("radar", 0.50, 10)):
            for _ in range(int(20 * dt)):
                reading = truth + self.rng.gauss(0, noise)

                # STAGE 3: swap the real LiDAR reading for a fake one.
                # Note we keep the noise small and the offset steady, so the
                # fake readings look just as smooth and believable as real
                # ones. Looked at alone, nothing is suspicious.
                if stage == "injection" and sensor == "lidar":
                    reading = truth + 9.0 + self.rng.gauss(0, 0.20)

                packets.append(Packet(
                    time=t,
                    source_ip="192.168.1.10",
                    sensor=sensor,
                    register=register,
                    distance_m=reading,
                ))

        # --- STAGE 1: reconnaissance. Very few packets, but each one asks
        # about a different part of the device. No readings come back,
        # because the attacker is asking for things that do not exist.
        if stage == "recon":
            for _ in range(max(1, int(15 * dt))):
                packets.append(Packet(
                    time=t,
                    source_ip=ATTACKER_IP,
                    sensor="lidar",
                    register=self.probe_register,
                    distance_m=None,
                ))
                self.probe_register += 1

        # --- STAGE 2: query flooding. Huge numbers of requests, all at the
        # same real register, all from the attacker.
        if stage == "flood":
            for _ in range(int(600 * dt)):
                packets.append(Packet(
                    time=t,
                    source_ip=ATTACKER_IP,
                    sensor="lidar",
                    register=0,
                    distance_m=truth + self.rng.gauss(0, 0.20),
                ))

        return packets
