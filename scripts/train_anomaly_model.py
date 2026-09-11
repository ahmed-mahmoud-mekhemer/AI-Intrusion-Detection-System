#!/usr/bin/env python3
# scripts/train_anomaly_model.py
# ─────────────────────────────────────────────────────────────────────────────
# Train the Isolation Forest anomaly model for real-time scoring.
#
# Data sources (in priority order):
#   1. data/models/rt_baseline.csv  (14-feature, from updated collect_baseline.py)
#   2. BENIGN rows from data/real_traffic/training_windows.csv  (14-feature fallback)
#
# Output: data/models/rt_anomaly_model.joblib
#   A sklearn Pipeline: StandardScaler → IsolationForest
#
# Usage:
#   cd ids_project
#   python scripts/train_anomaly_model.py
# ─────────────────────────────────────────────────────────────────────────────
import sys
from pathlib import Path

import numpy as np

ROOT       = Path(__file__).resolve().parent.parent
BASELINE   = ROOT / "data" / "models" / "rt_baseline.csv"
TRAINING   = ROOT / "data" / "real_traffic" / "training_windows.csv"
MODEL_PATH = ROOT / "data" / "models" / "rt_anomaly_model.joblib"

FEATURE_NAMES = [
    "total_rate", "syn_rate", "icmp_rate", "udp_rate",
    "unique_dst_ports", "avg_pkt_size",
    "ack_rate", "rst_rate", "fin_rate", "syn_ack_ratio",
    "pkt_size_std", "unique_src_ips", "dst_port_entropy", "bytes_rate",
]


def _load_baseline_csv():
    """Load rt_baseline.csv if it has all 14 features. Returns array or None."""
    if not BASELINE.exists():
        return None
    try:
        import pandas as pd
        df = pd.read_csv(BASELINE)
        missing = [c for c in FEATURE_NAMES if c not in df.columns]
        if missing:
            print(f"[train] rt_baseline.csv is missing features: {missing}")
            print(f"[train] Falling back to BENIGN rows from training_windows.csv")
            return None
        X = df[FEATURE_NAMES].values.astype(float)
        print(f"[train] Loaded {len(X)} windows from rt_baseline.csv (14-feature)")
        return X
    except Exception as exc:
        print(f"[train] Could not read rt_baseline.csv: {exc}")
        return None


def _load_benign_from_training():
    """Load BENIGN-labeled rows from training_windows.csv. Returns array or None."""
    if not TRAINING.exists():
        return None
    try:
        import pandas as pd
        df = pd.read_csv(TRAINING)
        benign = df[df["label"] == "BENIGN"]
        missing = [c for c in FEATURE_NAMES if c not in benign.columns]
        if missing:
            print(f"[train] training_windows.csv is missing features: {missing}")
            return None
        X = benign[FEATURE_NAMES].values.astype(float)
        print(f"[train] Loaded {len(X)} BENIGN windows from training_windows.csv")
        return X
    except Exception as exc:
        print(f"[train] Could not read training_windows.csv: {exc}")
        return None


def main():
    print(f"[train] Isolation Forest training — 14-feature architecture")

    X = _load_baseline_csv()
    if X is None:
        X = _load_benign_from_training()

    if X is None or len(X) == 0:
        sys.exit(
            "ERROR: No usable normal-traffic data found.\n"
            "Either run scripts/collect_baseline.py (with 14-feature version)\n"
            "or collect BENIGN windows via scripts/collect_traffic_windows.py."
        )

    if len(X) < 10:
        sys.exit(
            f"ERROR: Only {len(X)} windows available — need at least 10.\n"
            "Collect more baseline/BENIGN data first."
        )

    # Drop NaN rows
    mask = ~np.isnan(X).any(axis=1)
    dropped = len(X) - mask.sum()
    if dropped:
        print(f"[train] Dropped {dropped} rows with NaN values.")
    X = X[mask]

    print(f"[train] Training Isolation Forest on {len(X)} windows ({X.shape[1]} features)…")

    from sklearn.ensemble import IsolationForest
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler
    import joblib

    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("iforest", IsolationForest(
            n_estimators=100,
            contamination=0.02,
            random_state=42,
            n_jobs=-1,
        )),
    ])

    pipeline.fit(X)

    raw_scores = pipeline.decision_function(X)
    anomaly_scores = np.clip(0.5 - raw_scores, 0.0, 1.0)
    print(f"[train] Self-test anomaly scores — "
          f"mean={anomaly_scores.mean():.3f}  "
          f"max={anomaly_scores.max():.3f}  "
          f"min={anomaly_scores.min():.3f}")

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, MODEL_PATH)
    print(f"[train] Model saved: {MODEL_PATH}")
    print("\n[train] Done. Restart the IDS backend to load the new model.")


if __name__ == "__main__":
    main()
