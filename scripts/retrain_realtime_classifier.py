#!/usr/bin/env python3
# scripts/retrain_realtime_classifier.py
# ─────────────────────────────────────────────────────────────────────────────
# Retrain the realtime attack classifier using real collected traffic windows.
#
# Workflow:
#   1. Load real-traffic data from data/real_traffic/training_windows.csv
#   2. Optionally mix with synthetic data for classes with few real samples
#   3. Train StandardScaler + RandomForest (same architecture as original)
#   4. Evaluate with 5-fold CV and held-out test set
#   5. Compare against the current deployed model
#   6. Promote the new model (with user confirmation unless --auto-promote)
#
# Usage:
#   python scripts/retrain_realtime_classifier.py
#   python scripts/retrain_realtime_classifier.py --no-synthetic
#   python scripts/retrain_realtime_classifier.py --auto-promote
#   python scripts/retrain_realtime_classifier.py --min-per-class 50
# ─────────────────────────────────────────────────────────────────────────────

import argparse
import csv
import json
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    classification_report, confusion_matrix, f1_score
)

# ── Paths ─────────────────────────────────────────────────────────────────────
ROOT      = Path(__file__).resolve().parent.parent
DATA_DIR  = ROOT / "data" / "real_traffic"
MASTER    = DATA_DIR / "training_windows.csv"
MODELS    = ROOT / "data" / "models"

CURRENT_MODEL  = MODELS / "rt_classifier_model.joblib"
CURRENT_SCALER = MODELS / "rt_classifier_scaler.joblib"
CURRENT_META   = MODELS / "rt_classifier_meta.json"

BACKUP_SUFFIX = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
BACKUP_MODEL  = MODELS / f"rt_classifier_model_backup_{BACKUP_SUFFIX}.joblib"
BACKUP_SCALER = MODELS / f"rt_classifier_scaler_backup_{BACKUP_SUFFIX}.joblib"
BACKUP_META   = MODELS / f"rt_classifier_meta_backup_{BACKUP_SUFFIX}.json"

FEATURE_NAMES = [
    "total_rate", "syn_rate", "icmp_rate", "udp_rate",
    "unique_dst_ports", "avg_pkt_size",
    "ack_rate", "rst_rate", "fin_rate", "syn_ack_ratio",
    "pkt_size_std", "unique_src_ips", "dst_port_entropy", "bytes_rate",
]
VALID_LABELS = [
    "BENIGN", "SYN Flood", "Port Scan",
    "ICMP Flood", "UDP Flood", "Connection Burst",
]

RF_PARAMS = dict(
    n_estimators=300,
    max_depth=12,
    min_samples_leaf=3,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1,
)
CONFIDENCE_THRESHOLD = 0.70
CV_FOLDS = 5
_W = 70


# ── Synthetic fallback profiles (14-feature, CICIDS2017-profiled) ─────────────
# Order: [total, syn, icmp, udp, ports, pkt_sz, ack, rst, fin, sar, pkt_std, srcs, entr, bytes]
_SYNTH_PROFILES = {
    "BENIGN": dict(
        mean=[ 5.0,  0.50, 0.20, 1.00, 3.0,  800.0, 1.80, 0.15, 0.30, 0.20, 350.0,  8.0, 2.8,  4000.0],
        std= [ 2.0,  0.20, 0.08, 0.30, 1.0,  150.0, 0.80, 0.08, 0.12, 0.05,  80.0,  3.0, 0.5,  1500.0],
    ),
    "SYN Flood": dict(
        # Profiled from real TCP-connect-storm capture: high port diversity, moderate syn_rate
        mean=[ 76.0, 32.0,  0.0,  8.0, 625.0, 166.0, 35.0, 32.0, 0.34, 0.42, 260.0,  8.0, 7.9,  9739.0],
        std= [ 20.0, 10.0,  0.0,  3.0, 150.0,  30.0, 10.0, 10.0, 0.15, 0.08,  60.0,  3.0, 0.8,  2500.0],
    ),
    "Port Scan": dict(
        # Profiled from real capture: moderate port spread, lower ack/rst than SYN Flood
        mean=[ 65.0, 25.0,  0.0,  9.0, 324.0, 138.0, 31.0, 25.0, 0.75, 0.45, 246.0,  8.0, 7.5,  9945.0],
        std= [ 15.0,  8.0,  0.0,  3.0,  80.0,  25.0,  8.0,  8.0, 0.20, 0.08,  50.0,  2.0, 0.5,  2000.0],
    ),
    "ICMP Flood": dict(
        mean=[ 80.0,  0.0, 75.0,  0.0,  2.0,  84.0,  0.00,  0.0, 0.0, 0.00,  5.0,  1.0, 0.0,  6720.0],
        std= [ 40.0,  0.0, 38.0,  0.0,  0.5,  10.0,  0.00,  0.0, 0.0, 0.00,  2.0,  0.0, 0.0,  3200.0],
    ),
    "UDP Flood": dict(
        mean=[120.0,  0.0,  0.0,112.0,  4.0, 700.0,  0.00,  0.0, 0.0, 0.00, 40.0,  1.0, 2.0, 84000.0],
        std= [ 50.0,  0.0,  0.0, 45.0,  1.0, 180.0,  0.00,  0.0, 0.0, 0.00, 10.0,  0.0, 0.3, 30000.0],
    ),
    "Connection Burst": dict(
        mean=[100.0,  1.50, 0.40, 2.0,  4.0, 1050.0, 80.0,  1.5, 4.0, 0.02, 400.0, 14.0, 1.7, 105000.0],
        std= [ 50.0,  0.50, 0.20, 0.8,  0.7,  150.0, 40.0,  0.8, 2.0, 0.01,  80.0,  5.0, 0.2,  50000.0],
    ),
}


def _load_real_data() -> tuple[np.ndarray, np.ndarray, dict]:
    """Returns X, y, counts_per_class."""
    if not MASTER.exists():
        return np.array([]).reshape(0, 6), np.array([]), {}

    rows, labels = [], []
    with open(MASTER, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            try:
                feats = [float(row[f]) for f in FEATURE_NAMES]
                lbl   = row["label"]
                if lbl not in VALID_LABELS:
                    continue
                rows.append(feats)
                labels.append(lbl)
            except (ValueError, KeyError):
                continue

    if not rows:
        return np.array([]).reshape(0, 14), np.array([]), {}

    X = np.array(rows)
    y = np.array(labels)
    counts = {lbl: int((y == lbl).sum()) for lbl in VALID_LABELS}
    return X, y, counts


def _synth_for_class(label: str, n: int) -> tuple[np.ndarray, np.ndarray]:
    prof = _SYNTH_PROFILES[label]
    mean = np.array(prof["mean"])
    std  = np.array(prof["std"])
    rng  = np.random.default_rng(42)
    X    = rng.normal(mean, std, (n, len(mean)))
    # Clip negatives
    X    = np.clip(X, 0, None)
    y    = np.array([label] * n)
    return X, y


def build_dataset(real_X, real_y, real_counts, min_per_class: int,
                  use_synthetic: bool) -> tuple[np.ndarray, np.ndarray, dict]:
    """Mix real data with synthetic to reach min_per_class per class."""
    all_X = [real_X] if len(real_X) > 0 else []
    all_y = [real_y] if len(real_y) > 0 else []
    synth_counts = {}

    for lbl in VALID_LABELS:
        real_n = real_counts.get(lbl, 0)
        needed = max(0, min_per_class - real_n)

        if needed > 0 and use_synthetic:
            sX, sy = _synth_for_class(lbl, needed)
            all_X.append(sX)
            all_y.append(sy)
            synth_counts[lbl] = needed
        else:
            synth_counts[lbl] = 0

    X = np.vstack(all_X) if all_X else np.array([]).reshape(0, 14)
    y = np.concatenate(all_y) if all_y else np.array([])
    return X, y, synth_counts


def train(X, y) -> tuple:
    """Train scaler+RF Pipeline, return (pipeline, cv_mean, cv_std)."""
    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("clf",    RandomForestClassifier(**RF_PARAMS)),
    ])

    cv = StratifiedKFold(n_splits=CV_FOLDS, shuffle=True, random_state=42)
    scores = cross_val_score(pipeline, X, y, cv=cv, scoring="f1_macro", n_jobs=-1)

    pipeline.fit(X, y)
    return pipeline, float(scores.mean()), float(scores.std())


def evaluate(pipeline, X_test, y_test) -> dict:
    y_pr  = pipeline.predict(X_test)
    proba = pipeline.predict_proba(X_test)
    conf  = proba.max(axis=1)
    accepted_mask = conf >= CONFIDENCE_THRESHOLD

    report = classification_report(y_test, y_pr, output_dict=True, zero_division=0)
    cm     = confusion_matrix(y_test, y_pr, labels=pipeline.classes_.tolist())
    f1     = f1_score(y_test, y_pr, average="macro", zero_division=0)
    accept_rate = accepted_mask.mean()

    return {
        "f1_macro":    float(f1),
        "accept_rate": float(accept_rate),
        "report":      report,
        "confusion":   cm.tolist(),
        "classes":     pipeline.classes_.tolist(),
    }


def _load_current_meta() -> dict:
    if CURRENT_META.exists():
        try:
            return json.loads(CURRENT_META.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def print_comparison(old_meta: dict, new_f1: float, new_cv_mean: float,
                     new_cv_std: float, new_eval: dict):
    old_f1 = old_meta.get("cv_f1_macro_mean", None)
    print(f"\n  {'─'*(_W-2)}")
    print(f"  MODEL COMPARISON")
    print(f"  {'─'*(_W-2)}")
    print(f"  {'Metric':<28}  {'Current':>10}  {'New':>10}  {'Delta':>10}")
    print(f"  {'─'*28}  {'─'*10}  {'─'*10}  {'─'*10}")

    if old_f1 is not None:
        delta = new_cv_mean - old_f1
        delta_str = f"{delta:+.4f}"
        trend = " ▲" if delta > 0.001 else (" ▼" if delta < -0.001 else "  ~")
        print(f"  {'CV F1-macro (mean)':<28}  {old_f1:>10.4f}  {new_cv_mean:>10.4f}  {delta_str:>10}{trend}")
    else:
        print(f"  {'CV F1-macro (mean)':<28}  {'(none)':>10}  {new_cv_mean:>10.4f}  {'':>10}")

    print(f"  {'CV F1-macro (std)':<28}  {'':>10}  {new_cv_std:>10.4f}")
    print(f"  {'Test F1-macro':<28}  {'':>10}  {new_eval['f1_macro']:>10.4f}")
    print(f"  {'Acceptance rate':<28}  {'':>10}  {new_eval['accept_rate']:>10.1%}")
    print(f"  {'─'*(_W-2)}")


def promote(pipeline, new_meta: dict):
    """Backup current model and write new Pipeline."""
    if CURRENT_MODEL.exists():
        shutil.copy2(CURRENT_MODEL, BACKUP_MODEL)
    if CURRENT_META.exists():
        shutil.copy2(CURRENT_META, BACKUP_META)

    joblib.dump(pipeline, CURRENT_MODEL)
    CURRENT_META.write_text(json.dumps(new_meta, indent=2), encoding="utf-8")

    print(f"\n  Promoted new model:")
    print(f"    {CURRENT_MODEL}")
    print(f"    {CURRENT_META}")
    if BACKUP_MODEL.exists():
        print(f"\n  Backup saved:")
        print(f"    {BACKUP_MODEL}")


def main():
    parser = argparse.ArgumentParser(
        description="Retrain realtime classifier from real traffic data."
    )
    parser.add_argument("--no-synthetic",   action="store_true",
                        help="Do not augment with synthetic data")
    parser.add_argument("--min-per-class",  type=int, default=100,
                        help="Minimum windows per class (augment with synthetic if needed)")
    parser.add_argument("--auto-promote",   action="store_true",
                        help="Promote without confirmation prompt")
    parser.add_argument("--test-size",      type=float, default=0.15,
                        help="Fraction of data held out for final evaluation")
    args = parser.parse_args()

    print()
    print("=" * _W)
    print("  REALTIME CLASSIFIER RETRAINING")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * _W)

    # ── 1. Load real data ─────────────────────────────────────────────────────
    print(f"\n  [1/5] Loading real traffic data from:")
    print(f"        {MASTER}")
    real_X, real_y, real_counts = _load_real_data()
    print(f"        {len(real_X)} windows loaded")

    if len(real_X) == 0:
        print("\n  ERROR: No real data found. Run collect_traffic_windows.py first.")
        print("  Hint:  python scripts/show_dataset_status.py")
        sys.exit(1)

    print(f"\n  Real data per class:")
    for lbl in VALID_LABELS:
        n   = real_counts.get(lbl, 0)
        bar = "█" * min(n // 5, 30)
        print(f"    {lbl:<22} {n:>5}  {bar}")

    missing = [l for l in VALID_LABELS if real_counts.get(l, 0) == 0]
    if missing and not args.no_synthetic:
        print(f"\n  Classes with no real data (will use synthetic): {missing}")

    # ── 2. Build dataset ──────────────────────────────────────────────────────
    print(f"\n  [2/5] Building dataset (min {args.min_per_class}/class, "
          f"synthetic={'yes' if not args.no_synthetic else 'no'})")

    X, y, synth_counts = build_dataset(
        real_X, real_y, real_counts,
        min_per_class=args.min_per_class,
        use_synthetic=not args.no_synthetic,
    )

    print(f"        Total: {len(X)} windows")
    for lbl in VALID_LABELS:
        r = real_counts.get(lbl, 0)
        s = synth_counts.get(lbl, 0)
        print(f"    {lbl:<22}  real={r:>5}  synth={s:>5}  total={r+s:>5}")

    if len(X) < 60:
        print("\n  ERROR: Not enough data to train (< 60 total windows). Aborting.")
        sys.exit(1)

    # ── 3. Split and train ────────────────────────────────────────────────────
    print(f"\n  [3/5] Splitting {args.test_size:.0%} test / "
          f"{1-args.test_size:.0%} train+CV ...")

    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=args.test_size, stratify=y, random_state=42
    )

    print(f"        Train: {len(X_tr)}  Test: {len(X_te)}")
    print(f"\n  [4/5] Training RandomForest Pipeline (5-fold CV) ...")
    t0 = time.time()
    pipeline, cv_mean, cv_std = train(X_tr, y_tr)
    elapsed = time.time() - t0
    print(f"        Done in {elapsed:.1f}s")
    print(f"        CV F1-macro: {cv_mean:.4f} +/- {cv_std:.4f}")

    # ── 4. Evaluate ───────────────────────────────────────────────────────────
    print(f"\n  [5/5] Evaluating on held-out test set ...")
    new_eval = evaluate(pipeline, X_te, y_te)
    print(f"        Test F1-macro:    {new_eval['f1_macro']:.4f}")
    print(f"        Acceptance rate:  {new_eval['accept_rate']:.1%} "
          f"(conf >= {CONFIDENCE_THRESHOLD:.0%})")

    print(f"\n  Per-class test results:")
    print(f"  {'Class':<22}  {'Precision':>9}  {'Recall':>9}  {'F1':>9}  {'Support':>7}")
    print(f"  {'─'*22}  {'─'*9}  {'─'*9}  {'─'*9}  {'─'*7}")
    rep = new_eval["report"]
    for lbl in VALID_LABELS:
        if lbl in rep:
            r = rep[lbl]
            print(f"  {lbl:<22}  {r['precision']:>9.3f}  {r['recall']:>9.3f}  "
                  f"{r['f1-score']:>9.3f}  {int(r['support']):>7}")

    # ── 5. Compare and promote ────────────────────────────────────────────────
    old_meta = _load_current_meta()
    print_comparison(old_meta, new_eval["f1_macro"], cv_mean, cv_std, new_eval)

    new_meta = {
        "classes":              VALID_LABELS,
        "feature_names":        FEATURE_NAMES,
        "confidence_threshold": CONFIDENCE_THRESHOLD,
        "cv_f1_macro_mean":     cv_mean,
        "cv_f1_macro_std":      cv_std,
        "test_f1_macro":        new_eval["f1_macro"],
        "accept_rate":          new_eval["accept_rate"],
        "training_samples":     int(len(X_tr)),
        "real_samples":         int(len(real_X)),
        "synthetic_augmented":  not args.no_synthetic,
        "trained_at":           datetime.now(timezone.utc).isoformat(),
        "rf_params":            RF_PARAMS,
    }

    # Check if new model is better or if there's no current model
    old_f1 = old_meta.get("cv_f1_macro_mean", 0.0)
    is_better = cv_mean >= old_f1 - 0.005  # allow 0.5% tolerance

    if args.auto_promote:
        promote(pipeline, new_meta)
        print("\n  Auto-promoted (--auto-promote flag set).")
    else:
        print()
        if not is_better:
            print(f"  WARNING: New model CV F1 ({cv_mean:.4f}) is lower than current "
                  f"({old_f1:.4f}) by > 0.5%.")
            print("  This may indicate insufficient real data or distribution shift.")

        ans = input("  Promote new model? [y/N] ").strip().lower()
        if ans == "y":
            promote(pipeline, new_meta)
        else:
            print("\n  Not promoted. Model saved to memory only.")
            print("  Re-run with --auto-promote to skip this prompt.")

    print()
    print("  Next steps:")
    print("  • Restart the backend to load the new model:")
    print("    python backend/main.py")
    print("  • Re-run evaluation:")
    print("    python scripts/evaluate_realtime_ai.py")
    print()


if __name__ == "__main__":
    main()
