"""
ml_detector.py
==============
The machine learning part.

WHY WE NEED ML HERE AND NOT FOR THE OTHER TWO ATTACKS
    Reconnaissance and flooding have obvious fingerprints, so we wrote rules.
    False data injection does not. The attacker sends distance readings that
    are smooth, in range, and completely believable one at a time. There is no
    single number you can point at and say "that one is fake." The attack only
    shows up as a PATTERN across several measurements at once, and finding
    patterns nobody wrote down is exactly what machine learning is for.

THE MODEL: ISOLATION FOREST (from scikit-learn)
    In one sentence: it learns what normal data looks like, then flags points
    that are unusually easy to separate from the rest.

    The intuition: imagine plotting all your normal data as a cloud of points.
    To fence off a point in the middle of the cloud you need lots of cuts. To
    fence off a point sitting out on its own you need very few. Isolation
    Forest measures how few cuts it takes. Few cuts = odd point = anomaly.

    Two reasons we picked it:
      1. It trains on NORMAL data only. We never have to show it an attack,
         which matters because we cannot collect every attack in advance.
      2. It is fast and small enough to run on a Raspberry Pi.

THE THREE NUMBERS WE FEED IT (the "features")
    1. lidar_change     how much the LiDAR reading moved since last time
    2. radar_change     how much the RADAR reading moved since last time
    3. disagreement     how far apart the two sensors are right now

    Feature 3 is the one that catches the injection, and it is the sentence
    to say out loud in the presentation: the fake readings look fine on their
    own, but the radar is watching the same object and it did not move. You
    cannot fake one sensor without disagreeing with all the others.

    Feature 2 is there to stop false alarms. If BOTH sensors moved, the
    object really moved and nothing is wrong. If only the LiDAR moved,
    something is wrong with the LiDAR.

WHY EVERY FEATURE IS A *RELATIVE* NUMBER, NOT AN ABSOLUTE ONE
    We tried using the raw distance as a feature first and it did not work.
    The training period happened to cover distances from 40 to 53 metres, so
    later on, when the car legitimately drove up to something 22 metres away,
    the model called it an attack. Nothing was wrong -- the object was just
    closer than anything it had been shown.

    That is a real false alarm and it taught us a rule worth keeping:
        feed the model things that SHOULD always stay the same,
        not things that are allowed to change.
    A distance of 22 m is perfectly normal. Two sensors disagreeing by 9 m is
    never normal. So we dropped the raw distance and kept the comparisons.

    We also left the packet RATE out, even though it is a fine number, because
    the flood detector in rule_detectors.py already handles rate. Each of our
    three detectors asks one question nobody else is asking:
        who is talking to us     -> ReconDetector
        how much are they saying -> FloodDetector
        is what they say true    -> this file
"""

import numpy as np
from sklearn.ensemble import IsolationForest


FEATURE_NAMES = ["lidar_change", "radar_change", "disagreement"]


def make_features(lidar_avg, prev_lidar_avg, radar_avg, prev_radar_avg):
    """Turn one tick's readings into the three numbers the model wants."""
    lidar_change = abs(lidar_avg - prev_lidar_avg) if prev_lidar_avg is not None else 0.0
    radar_change = abs(radar_avg - prev_radar_avg) if prev_radar_avg is not None else 0.0
    disagreement = abs(lidar_avg - radar_avg)
    return [lidar_change, radar_change, disagreement]


class MLDetector:
    """A thin, readable wrapper around scikit-learn's IsolationForest."""

    def __init__(self, contamination=0.02, ticks_to_confirm=3):
        # contamination = roughly what fraction of the TRAINING data we expect
        # to be odd. We train on clean data, so we keep this small.
        self.model = IsolationForest(
            n_estimators=100,       # how many random trees to build
            contamination=contamination,
            random_state=42,        # so the results are the same every run
        )
        self.trained = False
        self.training_rows = []

        # One odd tick is not an attack. Sensor noise produces the occasional
        # freak reading, and on our first run exactly that happened at 29 s:
        # a single large radar jump got reported as an attack when nothing was
        # happening. Requiring the model to say "odd" several ticks in a row
        # removes it. All three of our detectors now use this same idea.
        self.ticks_to_confirm = ticks_to_confirm
        self.consecutive_odd = 0

    # ------------------------------------------------------------------
    def collect(self, features):
        """Save one row of normal data to train on later."""
        self.training_rows.append(features)

    def train(self):
        """Learn what normal looks like. Called once, after the quiet period."""
        X = np.array(self.training_rows)
        self.model.fit(X)
        self.trained = True
        return len(X)

    # ------------------------------------------------------------------
    def check(self, features):
        """Score one tick.

        Returns (confirmed, score). `confirmed` is True only once the model
        has called this data odd for several ticks in a row. The score is
        negative for anomalies and positive for normal points; the further
        from zero, the more confident the model is.
        """
        if not self.trained:
            return False, 0.0

        X = np.array([features])
        is_anomaly = self.model.predict(X)[0] == -1     # -1 means "odd one out"
        score = float(self.model.score_samples(X)[0])

        if is_anomaly:
            self.consecutive_odd += 1
        else:
            self.consecutive_odd = 0

        confirmed = self.consecutive_odd >= self.ticks_to_confirm
        return confirmed, score

    # ------------------------------------------------------------------
    def explain(self, features):
        """Say WHICH feature looks wrong, in plain English.

        The model itself only says "this is odd". That is not good enough for
        an operator, so we compare each feature against what we saw during
        training and report the ones that are furthest out of line. This keeps
        the model from being a black box, which is the usual and fair
        complaint about ML in safety systems.
        """
        X = np.array(self.training_rows)
        means = X.mean(axis=0)
        stds = X.std(axis=0)

        # Guard against a feature that barely moved during training. If we
        # divided by a near-zero spread we would print nonsense like
        # "10,000,000 standard deviations", which we did on our first run.
        stds = np.maximum(stds, 0.05 * np.abs(means) + 1e-3)

        # "how many standard deviations away from normal is each feature?"
        z_scores = (np.array(features) - means) / stds

        reasons = []
        for name, z, value, mean in zip(FEATURE_NAMES, z_scores, features, means):
            if abs(z) > 4:
                direction = "higher" if z > 0 else "lower"
                reasons.append({
                    "feature": name,
                    "value": round(float(value), 2),
                    "normal": round(float(mean), 2),
                    # capped, because past a certain point "very far from
                    # normal" is the whole message and the exact figure is
                    # just noise
                    "how_odd": round(min(float(abs(z)), 99.9), 1),
                    "direction": direction,
                })

        reasons.sort(key=lambda r: r["how_odd"], reverse=True)
        return reasons
