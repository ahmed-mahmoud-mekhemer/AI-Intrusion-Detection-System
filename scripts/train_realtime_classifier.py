#!/usr/bin/env python3
# scripts/train_realtime_classifier.py
# ─────────────────────────────────────────────────────────────────────────────
# Train a supervised Random Forest attack classifier for the realtime IDS layer.
#
# Feature space (6-dimensional) — matches anomaly_service.py exactly:
#   [total_rate, syn_rate, icmp_rate, udp_rate, unique_dst_ports, avg_pkt_size]
#
# Classes (6):
#   BENIGN, SYN Flood, Port Scan, ICMP Flood, UDP Flood, Connection Burst
#
# Design principles:
#   1. BENIGN class included — RF can say "this anomaly looks like normal
#      traffic" rather than forcing an attack label. Prevents false positives.
#   2. Open-set rejection — confidence < CONFIDENCE_THRESHOLD falls through to
#      the EMA-ratio classifier and eventually AI-UNKNOWN.
#   3. Multiple intensity levels — model generalises across mild to extreme
#      attacks, not just one point estimate.
#   4. Synthetic data with CICIDS2017-validated profiles — since raw PCAPs are
#      unavailable, feature profiles are derived from CICIDS2017 statistics:
#        SYN Flood    → Flow Packets/s, SYN Flag Count (CIC DDoS/DoS-SYN files)
#        Port Scan    → unique destination port spread (CIC PortScan file)
#        ICMP Flood   → ICMP Echo rate (CIC Wednesday file)
#        UDP Flood    → UDP Flow Packets/s, packet size (CIC Wednesday file)
#        Connection Burst → high Flow Packets/s, mixed protocol, low SYN ratio
#      See: https://www.unb.ca/cic/datasets/ids-2017.html
#
# Output:
#   data/models/rt_classifier_model.joblib   sklearn Pipeline (scaler + RF)
#   data/models/rt_classifier_meta.json      class list + threshold constant
#
# Usage:
#   python scripts/train_realtime_classifier.py [--samples N] [--seed S]
#   python scripts/train_realtime_classifier.py --help
# ─────────────────────────────────────────────────────────────────────────────

import argparse
import json
import sys
from pathlib import Path

import numpy as np

# ── Path bootstrap ─────────────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

try:
    import joblib
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import (classification_report, confusion_matrix,
                                 roc_auc_score)
    from sklearn.model_selection import StratifiedKFold, train_test_split
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler
    HAS_SKL = True
except ImportError:
    HAS_SKL = False

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    HAS_MPL = True
except ImportError:
    HAS_MPL = False

# ── Paths ─────────────────────────────────────────────────────────────────────

MODEL_PATH = ROOT / "data" / "models" / "rt_classifier_model.joblib"
META_PATH  = ROOT / "data" / "models" / "rt_classifier_meta.json"
EVAL_DIR   = ROOT / "evaluation_output"

# ── Hyper-parameters ──────────────────────────────────────────────────────────

CONFIDENCE_THRESHOLD = 0.70   # below this → open-set rejection → AI-UNKNOWN
RANDOM_SEED          = 42
N_PER_INTENSITY      = 500    # samples per (class × intensity) combination
NOISE_FRAC           = 0.15   # relative Gaussian noise fraction

# RF hyper-parameters
RF_N_ESTIMATORS  = 300
RF_MAX_DEPTH     = 12
RF_MIN_SAMPLES_L = 4

# ── Feature definitions ────────────────────────────────────────────────────────

FEATURE_NAMES = [
    "total_rate",        # 0  packets/s across all protocols in 10-s window
    "syn_rate",          # 1  pure-SYN packets/s (SYN=1, ACK=0)
    "icmp_rate",         # 2  ICMP packets/s
    "udp_rate",          # 3  UDP packets/s
    "unique_dst_ports",  # 4  distinct destination ports observed in window
    "avg_pkt_size",      # 5  mean frame length (bytes)
    "ack_rate",          # 6  ACK packets/s (TCP ACK bit)
    "rst_rate",          # 7  RST packets/s (TCP RST bit)
    "fin_rate",          # 8  FIN packets/s (TCP FIN bit)
    "syn_ack_ratio",     # 9  SYN/(SYN+ACK) ∈ [0,1]; ~1.0 = real SYN flood
    "pkt_size_std",      # 10 std dev of frame lengths (low = uniform flood)
    "unique_src_ips",    # 11 distinct source IPs
    "dst_port_entropy",  # 12 Shannon entropy of dst port distribution
    "bytes_rate",        # 13 total bytes/s
]

N_FEATURES = len(FEATURE_NAMES)

# ── CICIDS2017-profiled attack feature distributions ──────────────────────────
# Feature order (14):
#   [total_rate, syn_rate, icmp_rate, udp_rate, unique_dst_ports, avg_pkt_size,
#    ack_rate, rst_rate, fin_rate, syn_ack_ratio, pkt_size_std,
#    unique_src_ips, dst_port_entropy, bytes_rate]
#
# Each class has 5 intensity levels from mild to extreme.
# EMA normal baseline ≈ [5.0, 0.5, 0.2, 1.0, 3.0, 800.0, 1.8, 0.15, 0.3, 0.20, 350.0, 8.0, 2.8, 4000.0]
#
# Design invariants:
#   SYN Flood:        syn_ack_ratio ≥ 0.88 (spoofed SYNs, no ACKs back);
#                     rst_rate ≈ 0; ack_rate ≈ 0; pkt_size_std very low
#   Port Scan:        unique_dst_ports HIGH; rst_rate HIGH (refused ports);
#                     dst_port_entropy HIGH; syn_ack_ratio 0.50-0.65
#   ICMP Flood:       icmp_rate dominates; ack/rst/fin = 0; syn_ack_ratio = 0
#   UDP Flood:        udp_rate dominates; bytes_rate very high; ack/rst/fin = 0
#   Connection Burst: ack_rate very high; syn_ack_ratio < 0.05; total_rate high;
#                     few dst_ports; bytes_rate very high
#   BENIGN:           all moderate; mixed ACK/SYN; varied pkt sizes

PROFILES: dict = {

    # ── BENIGN ────────────────────────────────────────────────────────────────
    # Normal traffic: mixed protocols, moderate ACKs, varied sizes, few sources
    "BENIGN": [
        # idle / minimal traffic
        [ 1.0,  0.08, 0.04, 0.18,  1.2,  670.0,  0.30, 0.05, 0.10, 0.15, 280.0,  3.0, 1.5,    700.0],
        # light browsing
        [ 3.5,  0.25, 0.10, 0.45,  2.5,  740.0,  1.00, 0.10, 0.20, 0.18, 320.0,  6.0, 2.2,   2600.0],
        # normal mixed workstation
        [ 5.0,  0.50, 0.20, 1.00,  3.0,  800.0,  1.80, 0.15, 0.30, 0.20, 350.0,  8.0, 2.8,   4000.0],
        # moderate (video, updates)
        [ 8.5,  0.80, 0.30, 1.60,  4.2,  850.0,  3.00, 0.20, 0.50, 0.20, 380.0, 10.0, 3.0,   7200.0],
        # busy (file transfer, VoIP)
        [13.0,  1.20, 0.50, 2.80,  5.8,  880.0,  5.00, 0.30, 0.80, 0.18, 400.0, 12.0, 3.2,  11400.0],
    ],

    # ── SYN FLOOD ─────────────────────────────────────────────────────────────
    # Real flood: spoofed source IPs → SYNs go out, no ACKs come back.
    # syn_ack_ratio ≈ 0.90-0.97; ack_rate ≈ 0; rst_rate ≈ 0; pkt_size_std very low.
    "SYN Flood": [
        [ 12.0,  10.0, 0.0, 0.0,  1.5, 62.0,  0.30, 0.10, 0.0, 0.92,  8.0,  5.0, 0.5,    750.0],
        [ 35.0,  30.0, 0.0, 0.0,  2.0, 60.0,  0.50, 0.10, 0.0, 0.94,  6.0,  8.0, 0.6,   2100.0],
        [ 85.0,  75.0, 0.0, 0.0,  2.0, 58.0,  0.80, 0.20, 0.0, 0.95,  5.0, 12.0, 0.7,   4930.0],
        [160.0, 140.0, 0.0, 0.0,  1.8, 56.0,  1.00, 0.20, 0.0, 0.96,  4.0, 15.0, 0.6,   8960.0],
        [250.0, 225.0, 0.0, 0.0,  2.0, 54.0,  1.50, 0.30, 0.0, 0.97,  4.0, 20.0, 0.7,  13500.0],
    ],

    # ── PORT SCAN ─────────────────────────────────────────────────────────────
    # Many unique dst ports; refused ports → high rst_rate; high dst_port_entropy.
    # syn_ack_ratio 0.50-0.65 (SYNs out, RSTs/SYN-ACKs back mixed in).
    "Port Scan": [
        [  8.0,  4.0, 0.0, 0.0,  15.0, 62.0,  2.00,  3.50, 0.10, 0.55,  8.0, 1.0, 3.5,    500.0],
        [ 16.0, 11.0, 0.0, 0.0,  28.0, 62.0,  3.50,  6.00, 0.20, 0.58,  7.0, 1.0, 4.0,    992.0],
        [ 28.0, 20.0, 0.0, 0.0,  50.0, 60.0,  5.00, 10.00, 0.30, 0.60,  6.0, 1.0, 4.5,   1680.0],
        [ 45.0, 32.0, 0.0, 0.0,  85.0, 58.0,  8.00, 16.00, 0.50, 0.62,  5.0, 1.0, 4.8,   2610.0],
        [ 70.0, 52.0, 0.0, 0.0, 140.0, 56.0, 12.00, 25.00, 0.80, 0.65,  5.0, 1.0, 5.0,   3920.0],
    ],

    # ── ICMP FLOOD ────────────────────────────────────────────────────────────
    # No TCP flags at all; icmp_rate dominates; pkt_size_std very low.
    # dst_port_entropy = 0 (ICMP has no ports); bytes_rate = rate × avg_size.
    "ICMP Flood": [
        [  8.0, 0.0,   7.0, 0.0, 2.0,  64.0,  0.0, 0.0, 0.0, 0.0,  5.0, 1.0, 0.0,    512.0],
        [ 22.0, 0.0,  20.0, 0.0, 2.0,  64.0,  0.0, 0.0, 0.0, 0.0,  5.0, 1.0, 0.0,   1408.0],
        [ 55.0, 0.0,  51.0, 0.0, 2.0,  64.0,  0.0, 0.0, 0.0, 0.0,  5.0, 1.0, 0.0,   3520.0],
        [110.0, 0.0, 102.0, 0.0, 2.0,  64.0,  0.0, 0.0, 0.0, 0.0,  5.0, 1.0, 0.0,   7040.0],
        [220.0, 0.0, 205.0, 0.0, 2.0, 128.0,  0.0, 0.0, 0.0, 0.0,  5.0, 1.0, 0.0,  28160.0],
    ],

    # ── UDP FLOOD ─────────────────────────────────────────────────────────────
    # No TCP; udp_rate dominates; bytes_rate very high (large payloads).
    # dst_port_entropy moderate (few target ports).
    "UDP Flood": [
        [  9.0, 0.0, 0.0,   7.5, 3.0,  420.0,  0.0, 0.0, 0.0, 0.0, 30.0, 1.0, 1.5,   3780.0],
        [ 22.0, 0.0, 0.0,  20.0, 3.5,  650.0,  0.0, 0.0, 0.0, 0.0, 35.0, 1.0, 1.8,  14300.0],
        [ 55.0, 0.0, 0.0,  51.0, 4.0,  820.0,  0.0, 0.0, 0.0, 0.0, 40.0, 1.0, 2.0,  45100.0],
        [110.0, 0.0, 0.0, 102.0, 4.5,  960.0,  0.0, 0.0, 0.0, 0.0, 45.0, 1.0, 2.0, 105600.0],
        [210.0, 0.0, 0.0, 198.0, 5.0, 1000.0,  0.0, 0.0, 0.0, 0.0, 50.0, 1.0, 2.2, 210000.0],
    ],

    # ── CONNECTION BURST ──────────────────────────────────────────────────────
    # Established-TCP DDoS: many ACKs, very few SYNs, large packets, few dst ports.
    # syn_ack_ratio < 0.05; ack_rate very high; bytes_rate very high.
    "Connection Burst": [
        [ 26.0,  0.65, 0.25, 1.0, 3.2,  960.0,  20.0, 0.50, 1.50, 0.03, 350.0,  8.0, 1.5,  24960.0],
        [ 48.0,  1.00, 0.35, 1.5, 3.8, 1000.0,  38.0, 0.80, 2.50, 0.02, 380.0, 12.0, 1.6,  48000.0],
        [ 85.0,  1.40, 0.45, 2.0, 4.2, 1100.0,  68.0, 1.20, 4.00, 0.02, 400.0, 15.0, 1.7,  93500.0],
        [140.0,  1.80, 0.55, 2.6, 4.7, 1150.0, 112.0, 1.80, 6.00, 0.01, 420.0, 18.0, 1.8, 161000.0],
        [210.0,  2.20, 0.70, 3.3, 5.0, 1200.0, 168.0, 2.50, 8.00, 0.01, 450.0, 22.0, 1.9, 252000.0],
    ],
}

CLASS_ORDER = [
    "BENIGN",
    "SYN Flood",
    "Port Scan",
    "ICMP Flood",
    "UDP Flood",
    "Connection Burst",
]

# ── OOD (out-of-distribution) scenarios for open-set validation ───────────────
# These should NOT be confidently classified — they represent novel traffic.

OOD_SCENARIOS = [
    # name,                   expected,  [total, syn, icmp, udp, ports, pkt_sz,
    #                                      ack, rst, fin, sar, pkt_std, srcs, entr, bytes]
    ("Sub-threshold SYN",  "reject",  [ 6.0, 1.5, 0.0, 0.0,  2.0, 700.0,  3.0, 0.5, 0.3, 0.30, 200.0,  5.0, 1.0,  4200.0]),
    ("Sub-threshold Scan", "reject",  [ 7.0, 1.0, 0.0, 0.0,  8.0, 700.0,  2.5, 1.5, 0.2, 0.25, 150.0,  2.0, 2.5,  4900.0]),
    ("Slow scan",          "reject",  [ 3.0, 1.0, 0.0, 0.0, 12.0, 620.0,  1.0, 1.0, 0.1, 0.40, 120.0,  1.0, 3.0,  1860.0]),
    ("DNS tunneling",      "reject",  [ 4.0, 0.0, 0.0, 3.5,  4.0,  80.0,  0.5, 0.2, 0.1, 0.00,  40.0,  2.0, 1.8,   320.0]),
    ("Legitimate spike",   "benign",  [11.0, 0.9, 0.3, 2.0,  5.0, 850.0,  4.0, 0.2, 0.5, 0.18, 380.0,  9.0, 2.8,  9350.0]),
    ("Mixed proto burst",  "reject",  [ 9.0, 1.5, 0.8, 2.5,  4.5, 650.0,  3.0, 0.3, 0.5, 0.30, 280.0,  5.0, 2.5,  5850.0]),
    ("Low-noise ICMP",     "reject",  [ 3.5, 0.0, 0.8, 0.0,  2.0, 640.0,  0.0, 0.0, 0.0, 0.00,  20.0,  1.0, 0.0,  2240.0]),
    ("ARP storm",          "reject",  [ 2.5, 0.0, 0.0, 0.5,  1.5, 280.0,  0.0, 0.0, 0.0, 0.00,  60.0,  3.0, 0.8,   700.0]),
]

# ── Dark theme for plots ───────────────────────────────────────────────────────

_DARK_BG  = "#0A0E1A"
_PANEL_BG = "#0F1729"
_CYAN     = "#22D3EE"
_AMBER    = "#F59E0B"
_GREEN    = "#10B981"
_RED      = "#EF4444"
_PURPLE   = "#A855F7"
_TEXT     = "#E2E8F0"
_SUBTLE   = "#94A3B8"
_DIVIDER  = "#1E2A3F"

_CLASS_COLORS = {
    "BENIGN":           _GREEN,
    "SYN Flood":        _RED,
    "Port Scan":        _PURPLE,
    "ICMP Flood":       _AMBER,
    "UDP Flood":        _CYAN,
    "Connection Burst": "#F97316",
}


# ═══════════════════════════════════════════════════════════════════════════════
# Data generation
# ═══════════════════════════════════════════════════════════════════════════════

def _add_noise(vec: list, frac: float, rng: np.random.Generator) -> list:
    """Add relative Gaussian noise; each feature floored at 0."""
    out = []
    for v in vec:
        if v == 0.0:
            # Zero features: add tiny positive noise so model sees slight variation
            out.append(max(0.0, rng.exponential(0.05)))
        else:
            out.append(max(0.0, v + rng.normal(0, abs(v) * frac)))
    return out


def generate_dataset(n_per_intensity: int = N_PER_INTENSITY,
                     noise_frac: float = NOISE_FRAC,
                     seed: int = RANDOM_SEED) -> tuple:
    """
    Generate synthetic labelled dataset.
    Returns: (X: ndarray [n_samples, 6], y: ndarray [n_samples] str labels)
    """
    rng = np.random.default_rng(seed)
    X_parts, y_parts = [], []

    for cls_idx, cls_name in enumerate(CLASS_ORDER):
        intensities = PROFILES[cls_name]
        for int_idx, base_vec in enumerate(intensities):
            # Use per-(class,intensity) seed offset for reproducibility
            sub_seed = seed + cls_idx * 100 + int_idx * 7
            sub_rng  = np.random.default_rng(sub_seed)
            rows = [
                _add_noise(base_vec, noise_frac, sub_rng)
                for _ in range(n_per_intensity)
            ]
            X_parts.append(np.array(rows, dtype=float))
            y_parts.extend([cls_name] * n_per_intensity)

    X = np.vstack(X_parts)
    y = np.array(y_parts)
    # Shuffle
    idx = rng.permutation(len(X))
    return X[idx], y[idx]


# ═══════════════════════════════════════════════════════════════════════════════
# Training
# ═══════════════════════════════════════════════════════════════════════════════

def build_pipeline() -> Pipeline:
    return Pipeline([
        ("scaler", StandardScaler()),
        ("clf", RandomForestClassifier(
            n_estimators  = RF_N_ESTIMATORS,
            max_depth     = RF_MAX_DEPTH,
            min_samples_leaf = RF_MIN_SAMPLES_L,
            n_jobs        = -1,
            random_state  = RANDOM_SEED,
            class_weight  = "balanced",
        )),
    ])


def train(n_per_intensity: int = N_PER_INTENSITY, seed: int = RANDOM_SEED):
    if not HAS_SKL:
        print("[ERROR] scikit-learn / joblib not installed. "
              "Run: pip install scikit-learn joblib")
        sys.exit(1)

    EVAL_DIR.mkdir(parents=True, exist_ok=True)
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)

    print()
    print("=" * 72)
    print("  Realtime Attack Classifier — Training Pipeline")
    print("  Hybrid AI-Based NIDS — Graduation Project")
    print("=" * 72)

    # ── 1. Data generation ────────────────────────────────────────────────────
    print("\n[1/6] Generating synthetic training data...")
    X, y = generate_dataset(n_per_intensity=n_per_intensity, seed=seed)
    n_total = len(X)
    classes, counts = np.unique(y, return_counts=True)
    print(f"  Total samples : {n_total}")
    print(f"  Classes       : {len(classes)}")
    print(f"  Per class     : {dict(zip(classes, counts))}")
    print(f"  Features      : {N_FEATURES}  {FEATURE_NAMES}")

    # ── 2. Train / val / test split ───────────────────────────────────────────
    print("\n[2/6] Stratified train/val/test split (70/15/15)...")
    X_tv, X_test, y_tv, y_test = train_test_split(
        X, y, test_size=0.15, stratify=y, random_state=seed
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_tv, y_tv, test_size=0.1765, stratify=y_tv, random_state=seed
        # 0.1765 of 85% ≈ 15% of total
    )
    print(f"  Train : {len(X_train)}")
    print(f"  Val   : {len(X_val)}")
    print(f"  Test  : {len(X_test)}")

    # ── 3. 5-fold cross-validation on train set ───────────────────────────────
    print("\n[3/6] 5-fold stratified cross-validation (train set)...")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=seed)
    from sklearn.model_selection import cross_val_score
    pipe_cv = build_pipeline()
    cv_scores = cross_val_score(pipe_cv, X_train, y_train,
                                cv=cv, scoring="f1_macro", n_jobs=-1)
    print(f"  CV F1-macro: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")
    print(f"  Per fold   : {[f'{s:.4f}' for s in cv_scores]}")

    # ── 4. Final training on full train set ───────────────────────────────────
    print("\n[4/6] Training final model on train set...")
    pipeline = build_pipeline()
    pipeline.fit(X_train, y_train)
    print("  Done.")

    # ── 5. Validation set metrics ─────────────────────────────────────────────
    print("\n[5/6] Evaluation...")

    for split_name, Xs, ys in [("Validation", X_val, y_val),
                                ("Test", X_test, y_test)]:
        y_pred  = pipeline.predict(Xs)
        y_proba = pipeline.predict_proba(Xs)
        max_prob = y_proba.max(axis=1)

        print(f"\n  {split_name.upper()} SET — classification report")
        print("  " + "-" * 60)
        report = classification_report(
            ys, y_pred, target_names=CLASS_ORDER, digits=4
        )
        for line in report.splitlines():
            print(f"  {line}")

        # Confidence calibration
        for thresh in (0.60, 0.70, 0.80, 0.90):
            mask = max_prob >= thresh
            if mask.sum() == 0:
                continue
            acc  = (pipeline.predict(Xs[mask]) == ys[mask]).mean()
            rej  = (~mask).mean()
            print(f"  Threshold {thresh:.0%}: accepted {mask.sum()}/{len(Xs)} "
                  f"({1-rej:.1%}), accuracy={acc:.4f}, rejected={rej:.1%}")

        if split_name == "Test":
            _print_confusion_matrix(ys, y_pred, "Test")
            _evaluate_ood(pipeline)
            if HAS_MPL:
                _plot_confusion_matrix(ys, y_pred, pipeline.classes_,
                                       EVAL_DIR / "rf_confusion_matrix.png")
                _plot_confidence_histogram(max_prob, ys, y_pred,
                                           EVAL_DIR / "rf_confidence_hist.png")
                _plot_feature_importance(pipeline, EVAL_DIR / "rf_feature_importance.png")
                _plot_f1_bars(ys, y_pred, pipeline.classes_,
                              EVAL_DIR / "rf_f1_bars.png")

    # ── 6. Save model ─────────────────────────────────────────────────────────
    print("\n[6/6] Saving model and metadata...")
    joblib.dump(pipeline, MODEL_PATH)
    meta = {
        "classes":              pipeline.classes_.tolist(),
        "confidence_threshold": CONFIDENCE_THRESHOLD,
        "feature_names":        FEATURE_NAMES,
        "n_estimators":         RF_N_ESTIMATORS,
        "max_depth":            RF_MAX_DEPTH,
        "training_samples":     len(X_train),
        "cv_f1_macro_mean":     float(cv_scores.mean()),
        "cv_f1_macro_std":      float(cv_scores.std()),
    }
    META_PATH.write_text(json.dumps(meta, indent=2))
    print(f"  Model : {MODEL_PATH}")
    print(f"  Meta  : {META_PATH}")
    if HAS_MPL:
        print(f"  Plots : {EVAL_DIR}/rf_*.png")

    print()
    print("=" * 72)
    print("  TRAINING COMPLETE")
    print(f"  CV F1-macro (train): {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")
    print(f"  Confidence threshold: {CONFIDENCE_THRESHOLD:.0%}")
    print("=" * 72)
    print()

    return pipeline


# ═══════════════════════════════════════════════════════════════════════════════
# OOD evaluation
# ═══════════════════════════════════════════════════════════════════════════════

def _evaluate_ood(pipeline: Pipeline) -> None:
    """Evaluate open-set rejection on OOD scenarios."""
    print("\n  OOD (OUT-OF-DISTRIBUTION) REJECTION EVALUATION")
    print(f"  {'Scenario':<28} {'Top class':<20} {'MaxProb':>8} {'Outcome':>12}")
    print("  " + "-" * 72)

    n_rejected = 0
    for name, expected, feat in OOD_SCENARIOS:
        X = np.array(feat, dtype=float).reshape(1, -1)
        proba     = pipeline.predict_proba(X)[0]
        max_prob  = proba.max()
        top_cls   = pipeline.classes_[proba.argmax()]
        rejected  = max_prob < CONFIDENCE_THRESHOLD

        if expected == "reject":
            correct = "CORRECT" if rejected else "MISSED"
            if rejected:
                n_rejected += 1
        else:  # expected == "benign"
            correct = "CORRECT" if top_cls == "BENIGN" else "MISSED"
            if not rejected or top_cls == "BENIGN":
                n_rejected += 1

        print(f"  {name:<28} {top_cls:<20} {max_prob:>8.3f} {correct:>12}")

    total_ood = len(OOD_SCENARIOS)
    print(f"\n  OOD rejection/correct: {n_rejected}/{total_ood} "
          f"({n_rejected/total_ood:.0%})")


# ═══════════════════════════════════════════════════════════════════════════════
# Reporting helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _print_confusion_matrix(y_true, y_pred, split_name: str) -> None:
    cm = confusion_matrix(y_true, y_pred, labels=CLASS_ORDER)
    print(f"\n  CONFUSION MATRIX — {split_name}")
    header = "  " + " " * 20 + "".join(f"{c[:8]:>10}" for c in CLASS_ORDER)
    print(header)
    for i, row_cls in enumerate(CLASS_ORDER):
        row = "  " + f"{row_cls:<20}" + "".join(f"{v:>10}" for v in cm[i])
        print(row)


def _mpl_dark_style(fig, axes) -> None:
    fig.patch.set_facecolor(_DARK_BG)
    if not hasattr(axes, "__iter__"):
        axes = [axes]
    for ax in axes:
        ax.set_facecolor(_PANEL_BG)
        ax.tick_params(colors=_SUBTLE)
        ax.xaxis.label.set_color(_TEXT)
        ax.yaxis.label.set_color(_TEXT)
        ax.title.set_color(_CYAN)
        for spine in ax.spines.values():
            spine.set_edgecolor(_DIVIDER)


def _plot_confusion_matrix(y_true, y_pred, classes, path: Path) -> None:
    cm = confusion_matrix(y_true, y_pred, labels=list(classes))
    cm_norm = cm.astype(float) / cm.sum(axis=1, keepdims=True)

    fig, ax = plt.subplots(figsize=(9, 7))
    _mpl_dark_style(fig, ax)

    im = ax.imshow(cm_norm, cmap="Blues", vmin=0, vmax=1)
    cbar = fig.colorbar(im, ax=ax)
    cbar.ax.tick_params(colors=_SUBTLE)
    cbar.set_label("Normalised count", color=_SUBTLE)

    ax.set_xticks(range(len(classes)))
    ax.set_yticks(range(len(classes)))
    short = [c.replace(" Flood", " Fl.").replace("Connection Burst", "Conn.Burst")
             for c in classes]
    ax.set_xticklabels(short, rotation=30, ha="right", color=_SUBTLE, fontsize=9)
    ax.set_yticklabels(short, color=_SUBTLE, fontsize=9)

    for i in range(len(classes)):
        for j in range(len(classes)):
            val  = cm[i, j]
            norm = cm_norm[i, j]
            color = _DARK_BG if norm > 0.5 else _TEXT
            ax.text(j, i, f"{val}\n{norm:.0%}", ha="center", va="center",
                    color=color, fontsize=8)

    ax.set_xlabel("Predicted label", color=_SUBTLE)
    ax.set_ylabel("True label", color=_SUBTLE)
    ax.set_title("RF Classifier — Confusion Matrix (test set)", color=_CYAN, pad=12)
    fig.tight_layout()
    fig.savefig(path, dpi=150, facecolor=_DARK_BG)
    plt.close(fig)
    print(f"  Plot saved: {path}")


def _plot_confidence_histogram(max_prob, y_true, y_pred, path: Path) -> None:
    correct_mask   = y_true == y_pred
    incorrect_mask = ~correct_mask

    fig, ax = plt.subplots(figsize=(9, 5))
    _mpl_dark_style(fig, ax)

    bins = np.linspace(0, 1, 25)
    ax.hist(max_prob[correct_mask],   bins=bins, alpha=0.75,
            color=_GREEN,  label=f"Correct  (n={correct_mask.sum()})")
    ax.hist(max_prob[incorrect_mask], bins=bins, alpha=0.75,
            color=_RED,    label=f"Incorrect (n={incorrect_mask.sum()})")
    ax.axvline(CONFIDENCE_THRESHOLD, color=_AMBER, linewidth=2,
               linestyle="--", label=f"Threshold {CONFIDENCE_THRESHOLD:.0%}")

    ax.set_xlabel("Max class probability (confidence)", color=_SUBTLE)
    ax.set_ylabel("Sample count", color=_SUBTLE)
    ax.set_title("RF Classifier — Confidence Distribution (test set)",
                 color=_CYAN, pad=12)
    legend = ax.legend(facecolor=_PANEL_BG, edgecolor=_DIVIDER, labelcolor=_TEXT)
    fig.tight_layout()
    fig.savefig(path, dpi=150, facecolor=_DARK_BG)
    plt.close(fig)
    print(f"  Plot saved: {path}")


def _plot_feature_importance(pipeline: Pipeline, path: Path) -> None:
    rf   = pipeline.named_steps["clf"]
    imp  = rf.feature_importances_
    std  = np.std([t.feature_importances_ for t in rf.estimators_], axis=0)
    idx  = np.argsort(imp)[::-1]

    fig, ax = plt.subplots(figsize=(9, 5))
    _mpl_dark_style(fig, ax)

    colors = [_CLASS_COLORS.get(n, _CYAN) for n in FEATURE_NAMES]
    bars = ax.bar(range(N_FEATURES), imp[idx], yerr=std[idx], capsize=4,
                  color=[colors[i] for i in idx],
                  error_kw={"ecolor": _SUBTLE, "linewidth": 1.2})
    ax.set_xticks(range(N_FEATURES))
    ax.set_xticklabels([FEATURE_NAMES[i] for i in idx],
                       rotation=25, ha="right", color=_SUBTLE, fontsize=9)
    ax.set_ylabel("Mean decrease in impurity", color=_SUBTLE)
    ax.set_title("RF Classifier — Feature Importance (MDI ± std)",
                 color=_CYAN, pad=12)
    fig.tight_layout()
    fig.savefig(path, dpi=150, facecolor=_DARK_BG)
    plt.close(fig)
    print(f"  Plot saved: {path}")


def _plot_f1_bars(y_true, y_pred, classes, path: Path) -> None:
    from sklearn.metrics import precision_recall_fscore_support
    prec, rec, f1, _ = precision_recall_fscore_support(
        y_true, y_pred, labels=list(classes), zero_division=0
    )

    x = np.arange(len(classes))
    w = 0.25

    fig, ax = plt.subplots(figsize=(10, 5))
    _mpl_dark_style(fig, ax)

    ax.bar(x - w, prec, w, label="Precision", color=_CYAN,   alpha=0.85)
    ax.bar(x,     rec,  w, label="Recall",    color=_GREEN,  alpha=0.85)
    ax.bar(x + w, f1,   w, label="F1-score",  color=_PURPLE, alpha=0.85)

    short = [c.replace(" Flood", " Fl.").replace("Connection Burst", "Conn.Burst")
             for c in classes]
    ax.set_xticks(x)
    ax.set_xticklabels(short, rotation=20, ha="right", color=_SUBTLE, fontsize=9)
    ax.set_ylim(0, 1.10)
    ax.set_ylabel("Score", color=_SUBTLE)
    ax.set_title("RF Classifier — Per-class Precision / Recall / F1 (test set)",
                 color=_CYAN, pad=12)
    legend = ax.legend(facecolor=_PANEL_BG, edgecolor=_DIVIDER, labelcolor=_TEXT)
    fig.tight_layout()
    fig.savefig(path, dpi=150, facecolor=_DARK_BG)
    plt.close(fig)
    print(f"  Plot saved: {path}")


# ═══════════════════════════════════════════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Train the realtime IDS attack classifier."
    )
    parser.add_argument("--samples", type=int, default=N_PER_INTENSITY,
                        help=f"Samples per (class × intensity) (default {N_PER_INTENSITY})")
    parser.add_argument("--seed",    type=int, default=RANDOM_SEED,
                        help=f"Random seed (default {RANDOM_SEED})")
    args = parser.parse_args()

    train(n_per_intensity=args.samples, seed=args.seed)


if __name__ == "__main__":
    main()
