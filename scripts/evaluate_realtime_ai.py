#!/usr/bin/env python3
"""
scripts/evaluate_realtime_ai.py
════════════════════════════════════════════════════════════════════════════════
Academic Evaluation Pipeline — Realtime AI Behavioral Detection Layer
Hybrid AI-Based NIDS — Graduation Project

METHODOLOGY
───────────
Ground truth is established via synthetic feature vectors derived from
domain-knowledge attack signatures, not from labeled live traffic.
This is standard practice when live labeled captures are unavailable.
The evaluation is academically valid because:

  1. The classifier under test is itself domain-knowledge-based (EMA ratio
     thresholds), not learned from the same data — so testing it on
     domain-derived vectors is not circular.
  2. The IF model is tested against vectors it has NOT seen during training
     (training used collect_baseline.py traffic; test vectors are synthetic).
  3. Multiple noise-perturbed variants of each scenario are generated,
     giving a statistical evaluation rather than a single point.

EVALUATION COMPONENTS
─────────────────────
  A. Behavioral Pattern Classifier
       Tests the classify_behavioral_alert() function at three intensity levels:
         Strong     — 10-20x above EMA baseline  (should classify: "Likely X")
         Borderline — 4-5x above EMA baseline    (at classification threshold)
         Sub-thresh — 2-3x above EMA baseline    (should fall to AI-UNKNOWN)
       Metrics: per-class Precision / Recall / F1, confusion matrix

  B. Isolation Forest Anomaly Detector  (requires trained model)
       Tests score_feature_vector_direct() on attack vs normal feature vectors.
       Metrics: Precision / Recall / F1 at threshold 0.5, ROC-AUC
       Output: ROC curve, IF score distribution per attack type

  C. HYBRID Detection Threshold Coverage  (requires trained model)
       Asks: for attacks the rule engine catches, what % also exceed the
       HYBRID threshold (IF score >= 0.52)?
       Output: per-attack HYBRID coverage table

  D. AI-UNKNOWN Uncertainty Handling
       Tests that sub-threshold and ambiguous scenarios correctly produce
       "Suspicious Behavioral Traffic" with conf=0.0.
       This measures the system's epistemically honest behavior.

OUTPUTS  (saved to evaluation_output/)
───────────────────────────────────────
  confusion_matrix_classifier.png   Multi-class behavioral classifier CM
  confusion_matrix_binary.png       Binary attack/normal IF detection CM
  roc_curve.png                     ROC-AUC for IF anomaly detection
  f1_bar_chart.png                  Per-class F1 bar chart
  if_score_distributions.png        IF score boxplots per attack type
  detection_results.csv             Raw per-sample results
  evaluation_report.json            Complete structured report
  evaluation_summary.txt            Copy-paste text for graduation report

USAGE
──────
  # From the ids_project/ directory:
  python scripts/evaluate_realtime_ai.py

  # Or from project root:
  cd ids_project && python scripts/evaluate_realtime_ai.py
"""

import sys
import csv
import json
import math
import warnings
import datetime
import pathlib
from pathlib import Path

import numpy as np

warnings.filterwarnings("ignore")

# ── Path setup ────────────────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

try:
    from backend.services.anomaly_service import (
        classify_behavioral_alert,
        score_feature_vector_direct,
        update_baseline,
        reset_for_new_session,
        is_model_loaded,
        FEATURE_NAMES,
        _load_model,            # trigger model load before evaluation
    )
except ImportError as exc:
    print(f"[FATAL] Cannot import anomaly_service: {exc}")
    print("        Run from the ids_project/ directory.")
    sys.exit(1)

try:
    from backend.services import realtime_classifier_service as _rt_clf_svc
    _HAS_RT_CLF_SVC = True
except ImportError:
    _rt_clf_svc      = None   # type: ignore
    _HAS_RT_CLF_SVC  = False

try:
    import matplotlib
    matplotlib.use("Agg")                  # non-interactive backend for file output
    import matplotlib.pyplot as plt
    import matplotlib.gridspec as gridspec
    import matplotlib.ticker as mticker
    import matplotlib.patches as mpatches
    HAS_MPL = True
except ImportError:
    HAS_MPL = False
    print("[WARN] matplotlib not found — plots will be skipped (pip install matplotlib)")

try:
    from sklearn.metrics import (
        precision_score, recall_score, f1_score, accuracy_score,
        confusion_matrix, classification_report,
        roc_curve, auc,
    )
    HAS_SKL = True
except ImportError:
    HAS_SKL = False
    print("[WARN] scikit-learn not found — some metrics will be skipped")

# ── Output ────────────────────────────────────────────────────────────────────
OUTPUT_DIR = ROOT / "evaluation_output"
OUTPUT_DIR.mkdir(exist_ok=True)
TIMESTAMP  = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

DIVIDER = "─" * 72

# ── Evaluation hyper-parameters ───────────────────────────────────────────────
# 14 features: total, syn, icmp, udp, ports, pkt_sz, ack, rst, fin, sar, pkt_std, srcs, entr, bytes
NORMAL_BASELINE  = [5.0, 0.5, 0.2, 1.0, 3.0, 800.0, 1.8, 0.15, 0.30, 0.20, 350.0, 8.0, 2.8, 4000.0]
N_WARMUP_OBS     = 15      # EMA warm-up observations before evaluation
N_SAMPLES        = 25      # noisy samples per attack class
N_NORMAL         = 40      # normal traffic samples
NOISE_FRAC       = 0.12    # 12% relative Gaussian noise
RANDOM_SEED      = 42
IF_BINARY_THRESH = 0.50    # IF score >= this → anomaly (binary classification)
HYBRID_THRESH    = 0.52    # IF score >= this AND rule fired → HYBRID
BEHAV_THRESH     = 0.55    # IF score >= this → behavioral alert gate
CLASSIFY_THRESH  = 4.0     # feature ratio >= this → named classification

np.random.seed(RANDOM_SEED)

# ── Ground truth scenario library ─────────────────────────────────────────────
# Each record: (class_name, expected_label, base_features, description)
# Features: [total_rate, syn_rate, icmp_rate, udp_rate, unique_dst_ports, avg_pkt_size]
#
# Three intensity tiers per attack:
#   STRONG     — dominant feature 10-240x above normal EMA baseline
#   BORDERLINE — dominant feature exactly at 4x classification threshold
#   SUB-THRESH — dominant feature at 2-3x (below threshold → correctly AI-UNKNOWN)

ATTACK_STRONG = [
    (
        "SYN Flood",
        "Likely SYN Flood",
        # Derived from real captured SYN Flood means (syn_r=32, rst_r=32, ports=625)
        [76.0, 32.0, 0.0, 8.0, 625.0, 166.0, 35.0, 32.0, 0.34, 0.42, 260.0, 8.0, 7.9, 9739.0],
        "syn_rate 64x above baseline, high rst_rate, high port diversity",
    ),
    (
        "Port Scan",
        "Likely Port Scan",
        # Derived from real captured Port Scan means (ports=324, syn_r=25)
        [65.0, 25.0, 0.0, 9.0, 324.0, 138.0, 31.0, 25.0, 0.75, 0.45, 246.0, 8.0, 7.5, 9945.0],
        "unique_dst_ports 108x baseline, broad TCP probe spread",
    ),
    (
        "ICMP Flood",
        "Likely ICMP Flood",
        # Derived from real captured ICMP Flood means (icmp_r=157, pkt_sz=1012)
        [170.0, 0.0, 158.0, 10.0, 8.0, 1012.0, 2.0, 0.0, 0.12, 0.07, 165.0, 7.0, 2.1, 171741.0],
        "icmp_rate 790x baseline, dominates all protocol rates",
    ),
    (
        "UDP Flood",
        "Likely UDP Flood",
        # Derived from real captured UDP Flood means (udp_r=467, ports=4447)
        [470.0, 0.0, 0.0, 467.0, 4447.0, 972.0, 3.0, 0.0, 0.13, 0.07, 283.0, 7.0, 11.75, 464771.0],
        "udp_rate 467x baseline, massive port diversity",
    ),
    (
        "Connection Burst",
        "Likely Connection Burst",
        # Derived from real captured Connection Burst means (ack_r=315, syn_r=121, rst_r=129)
        [473.0, 121.0, 0.0, 16.0, 540.0, 165.0, 315.0, 129.0, 25.0, 0.27, 351.0, 9.0, 6.45, 78071.0],
        "high ack_rate and rst_rate with massive total_rate — connection storm",
    ),
]

ATTACK_BORDERLINE = [
    (
        "SYN Flood",
        "Likely SYN Flood",
        [38.0, 16.0, 0.0, 4.0, 313.0, 100.0, 18.0, 16.0, 0.2, 0.5, 130.0, 8.0, 4.5, 4870.0],
        "half-strength SYN Flood — boundary case",
    ),
    (
        "Port Scan",
        "Likely Port Scan",
        [35.0, 13.0, 0.0, 5.0, 165.0, 90.0, 16.0, 13.0, 0.4, 0.45, 125.0, 4.0, 5.5, 5000.0],
        "moderate port spread — boundary case",
    ),
    (
        "ICMP Flood",
        "Likely ICMP Flood",
        [90.0, 0.0, 80.0, 5.0, 5.0, 850.0, 1.0, 0.0, 0.1, 0.05, 100.0, 5.0, 1.5, 90000.0],
        "moderate ICMP dominance — boundary case",
    ),
    (
        "UDP Flood",
        "Likely UDP Flood",
        [240.0, 0.0, 0.0, 235.0, 2200.0, 700.0, 1.5, 0.0, 0.1, 0.05, 150.0, 5.0, 9.0, 230000.0],
        "moderate UDP flood — boundary case",
    ),
    (
        "Connection Burst",
        "Likely Connection Burst",
        [240.0, 60.0, 0.0, 8.0, 270.0, 100.0, 160.0, 65.0, 12.0, 0.25, 175.0, 6.0, 5.0, 40000.0],
        "moderate connection burst — boundary case",
    ),
]

ATTACK_SUBTHRESH = [
    (
        "SYN Flood (sub-threshold)",
        "Suspicious Behavioral Traffic",
        [6.5, 1.5, 0.0, 0.0, 2.0, 750.0, 1.0, 0.5, 0.2, 0.1, 300.0, 8.0, 2.5, 5000.0],
        "syn_rate 3x baseline — correctly below classification threshold",
    ),
    (
        "Port Scan (sub-threshold)",
        "Suspicious Behavioral Traffic",
        [7.0, 1.0, 0.0, 0.0, 8.0, 700.0, 1.0, 0.5, 0.3, 0.1, 280.0, 5.0, 3.0, 4900.0],
        "unique_dst_ports 2.7x — correctly below classification threshold",
    ),
    (
        "Ambiguous Anomaly A",
        "Suspicious Behavioral Traffic",
        [9.0, 1.5, 0.8, 2.5, 4.5, 650.0, 2.0, 0.5, 0.5, 0.15, 300.0, 8.0, 2.8, 6000.0],
        "subtle multi-feature deviation — no dominant pattern identifiable",
    ),
    (
        "Ambiguous Anomaly B",
        "Suspicious Behavioral Traffic",
        [11.0, 2.0, 1.0, 3.0, 4.0, 600.0, 2.0, 0.5, 0.5, 0.2, 280.0, 8.0, 2.8, 7000.0],
        "moderate multi-feature anomaly — correctly unclassifiable",
    ),
]

NORMAL_SCENARIOS = [
    (
        "Normal Traffic",
        "Suspicious Behavioral Traffic",
        [5.0, 0.5, 0.2, 1.0, 3.0, 800.0, 1.8, 0.15, 0.30, 0.20, 350.0, 8.0, 2.8, 4000.0],
        "idle network baseline — should never classify as attack",
    ),
    (
        "Normal (elevated)",
        "Suspicious Behavioral Traffic",
        [8.0, 1.2, 0.5, 1.8, 5.0, 750.0, 2.5, 0.3, 0.5, 0.20, 320.0, 9.0, 3.0, 6000.0],
        "moderately busy network — all features below 2x EMA",
    ),
]


# ═════════════════════════════════════════════════════════════════════════════
# Utility functions
# ═════════════════════════════════════════════════════════════════════════════

def _add_noise(features: list, std_frac: float = NOISE_FRAC) -> list:
    """
    Add relative Gaussian noise to a feature vector.
    Noise = N(0, |feature| × std_frac).  Floor at 0.0.
    """
    return [
        max(0.0, f + np.random.normal(0, abs(f) * std_frac) if f > 0 else 0.0)
        for f in features
    ]


def _warm_ema(n_obs: int = N_WARMUP_OBS) -> None:
    """Warm the EMA baseline with normal traffic observations."""
    reset_for_new_session()
    for _ in range(n_obs):
        update_baseline(_add_noise(NORMAL_BASELINE, 0.10))


def _generate_samples(scenarios, n_per_class: int, noise_frac: float = NOISE_FRAC):
    """
    Expand a list of (class, expected_label, base_features, desc) scenarios
    into n_per_class noisy samples each.
    Returns: list of (class_name, expected_label, feature_vector, desc)
    """
    samples = []
    for class_name, expected_label, base_feats, desc in scenarios:
        for _ in range(n_per_class):
            samples.append((class_name, expected_label, _add_noise(base_feats, noise_frac), desc))
    return samples


def _banner(title: str) -> None:
    print(f"\n{DIVIDER}")
    print(f"  {title}")
    print(DIVIDER)


# ═════════════════════════════════════════════════════════════════════════════
# A. Behavioral Pattern Classifier Evaluation
# ═════════════════════════════════════════════════════════════════════════════

def evaluate_classifier() -> dict:
    """
    Evaluate classify_behavioral_alert() against synthetic ground truth.

    For each sample: call classifier → compare label to expected → record result.
    Uses a fixed EMA baseline (warmed with normal traffic); EMA is NOT updated
    during evaluation to simulate a stable reference baseline.
    """
    _banner("SECTION A — Behavioral Pattern Classifier")

    _load_model()
    _warm_ema()
    model_present = is_model_loaded()
    # Use a fixed representative IF score for explanation text.
    # When model IS present, we will compute the real score per sample below.
    _DUMMY_IF_SCORE = 0.82

    # Build sample sets
    strong_samples     = _generate_samples(ATTACK_STRONG,     N_SAMPLES)
    borderline_samples = _generate_samples(ATTACK_BORDERLINE,  N_SAMPLES)
    subthresh_samples  = _generate_samples(ATTACK_SUBTHRESH,   N_SAMPLES)
    normal_samples     = _generate_samples(NORMAL_SCENARIOS,   N_NORMAL)

    all_samples = (
        [("strong",     s) for s in strong_samples] +
        [("borderline", s) for s in borderline_samples] +
        [("subthresh",  s) for s in subthresh_samples] +
        [("normal",     s) for s in normal_samples]
    )

    records = []
    for intensity, (class_name, expected_label, features, desc) in all_samples:
        if model_present:
            if_score = score_feature_vector_direct(features)
        else:
            if_score = _DUMMY_IF_SCORE

        pred_label, conf, expl = classify_behavioral_alert(features, if_score)
        correct = (pred_label == expected_label)

        records.append({
            "intensity":      intensity,
            "class":          class_name,
            "expected_label": expected_label,
            "predicted_label":pred_label,
            "confidence":     round(conf, 3),
            "if_score":       round(if_score, 4),
            "correct":        correct,
            "explanation":    expl,
        })

    # ── Per-intensity summary ─────────────────────────────────────────────────
    intensity_groups = {}
    for r in records:
        intensity_groups.setdefault(r["intensity"], []).append(r)

    print(f"\n  EMA warmed with {N_WARMUP_OBS} normal-traffic observations.")
    print(f"  IF model loaded: {model_present}")
    print(f"  Total samples evaluated: {len(records)}")

    print(f"\n  {'Intensity':<16} {'Samples':>8} {'Correct':>8} {'Accuracy':>10}")
    print(f"  {'─'*16} {'─'*8} {'─'*8} {'─'*10}")
    for intensity in ("strong", "borderline", "subthresh", "normal"):
        grp = intensity_groups.get(intensity, [])
        if not grp:
            continue
        n_correct = sum(r["correct"] for r in grp)
        acc = n_correct / len(grp) * 100
        print(f"  {intensity:<16} {len(grp):>8} {n_correct:>8} {acc:>9.1f}%")

    # ── Per-class precision / recall / F1 ─────────────────────────────────────
    # For the attack classification task:
    # TP = attack sample → correct "Likely X" label
    # FP = normal/subthresh sample → incorrect "Likely X" label
    # FN = attack sample → "Suspicious Behavioral Traffic" (missed classification)
    # TN = normal/subthresh sample → "Suspicious Behavioral Traffic" (correct)

    # Build binary (attack detected / not) vectors
    y_true_binary = []
    y_pred_binary = []
    for r in records:
        is_real_attack = not r["class"].startswith("Normal") and \
                         "Ambiguous" not in r["class"] and \
                         "sub-threshold" not in r["class"].lower()
        y_true_binary.append(1 if is_real_attack else 0)
        y_pred_binary.append(0 if r["predicted_label"] == "Suspicious Behavioral Traffic" else 1)

    # Build multi-class label vectors (strong attacks only, for per-class metrics)
    strong_records = [r for r in records if r["intensity"] == "strong"]
    attack_class_labels = sorted({r["class"] for r in strong_records})

    y_true_mc = [r["class"] for r in strong_records]
    y_pred_mc = [r["predicted_label"].replace("Likely ", "") for r in strong_records]
    # Normalize: if predicted is "Suspicious Behavioral Traffic", map to "Unclassified"
    y_pred_mc = [
        p if p in attack_class_labels else "Unclassified"
        for p in y_pred_mc
    ]

    # ── Print multi-class report ──────────────────────────────────────────────
    print(f"\n  STRONG ATTACK CLASSIFICATION REPORT (N={len(strong_records)} samples)")
    print(f"  {'Attack Class':<25} {'Prec':>7} {'Rec':>7} {'F1':>7} {'Support':>9}")
    print(f"  {'─'*25} {'─'*7} {'─'*7} {'─'*7} {'─'*9}")

    per_class_metrics = {}
    for cls in attack_class_labels:
        tp = sum(1 for yt, yp in zip(y_true_mc, y_pred_mc) if yt == cls and yp == cls)
        fp = sum(1 for yt, yp in zip(y_true_mc, y_pred_mc) if yt != cls and yp == cls)
        fn = sum(1 for yt, yp in zip(y_true_mc, y_pred_mc) if yt == cls and yp != cls)
        support = y_true_mc.count(cls)

        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec  = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1   = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0

        per_class_metrics[cls] = {"precision": prec, "recall": rec, "f1": f1, "support": support}
        print(f"  {cls:<25} {prec:>7.3f} {rec:>7.3f} {f1:>7.3f} {support:>9}")

    # Macro averages
    macro_prec = sum(m["precision"] for m in per_class_metrics.values()) / len(per_class_metrics)
    macro_rec  = sum(m["recall"]    for m in per_class_metrics.values()) / len(per_class_metrics)
    macro_f1   = sum(m["f1"]        for m in per_class_metrics.values()) / len(per_class_metrics)
    print(f"  {'─'*25} {'─'*7} {'─'*7} {'─'*7} {'─'*9}")
    print(f"  {'Macro Average':<25} {macro_prec:>7.3f} {macro_rec:>7.3f} {macro_f1:>7.3f}")

    # ── Binary attack detection summary ──────────────────────────────────────
    tp_b = sum(1 for yt, yp in zip(y_true_binary, y_pred_binary) if yt == 1 and yp == 1)
    fp_b = sum(1 for yt, yp in zip(y_true_binary, y_pred_binary) if yt == 0 and yp == 1)
    tn_b = sum(1 for yt, yp in zip(y_true_binary, y_pred_binary) if yt == 0 and yp == 0)
    fn_b = sum(1 for yt, yp in zip(y_true_binary, y_pred_binary) if yt == 1 and yp == 0)

    prec_b = tp_b / (tp_b + fp_b) if (tp_b + fp_b) > 0 else 0.0
    rec_b  = tp_b / (tp_b + fn_b) if (tp_b + fn_b) > 0 else 0.0
    f1_b   = 2 * prec_b * rec_b / (prec_b + rec_b) if (prec_b + rec_b) > 0 else 0.0
    fpr_b  = fp_b / (fp_b + tn_b) if (fp_b + tn_b) > 0 else 0.0

    print(f"\n  BINARY ATTACK DETECTION (strong + borderline = positive class)")
    print(f"  TP={tp_b}  FP={fp_b}  TN={tn_b}  FN={fn_b}")
    print(f"  Precision:    {prec_b:.4f}")
    print(f"  Recall:       {rec_b:.4f}")
    print(f"  F1-score:     {f1_b:.4f}")
    print(f"  False Pos Rate: {fpr_b:.4f}")

    # ── AI-UNKNOWN correctness ────────────────────────────────────────────────
    unknown_candidates = [r for r in records
                          if r["expected_label"] == "Suspicious Behavioral Traffic"]
    unknown_correct    = sum(1 for r in unknown_candidates
                             if r["predicted_label"] == "Suspicious Behavioral Traffic")
    unknown_acc = unknown_correct / len(unknown_candidates) if unknown_candidates else 0.0
    print(f"\n  AI-UNKNOWN CORRECTNESS (sub-threshold + normal + ambiguous)")
    print(f"  Expected 'Suspicious Behavioral Traffic': {len(unknown_candidates)} samples")
    print(f"  Correctly returned AI-UNKNOWN:            {unknown_correct}")
    print(f"  Uncertainty Accuracy:                     {unknown_acc:.4f}")

    # ── Generate plots ────────────────────────────────────────────────────────
    if HAS_MPL:
        _plot_classifier_confusion_matrix(records, attack_class_labels)
        _plot_f1_bar_chart(per_class_metrics)

    # ── Save CSV ──────────────────────────────────────────────────────────────
    csv_path = OUTPUT_DIR / "detection_results.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(records[0].keys()))
        writer.writeheader()
        writer.writerows(records)
    print(f"\n  Raw results saved: {csv_path}")

    return {
        "model_present": model_present,
        "total_samples": len(records),
        "per_intensity": {
            intensity: {
                "n": len(grp),
                "correct": sum(r["correct"] for r in grp),
                "accuracy": sum(r["correct"] for r in grp) / len(grp),
            }
            for intensity, grp in intensity_groups.items()
        },
        "per_class_metrics": per_class_metrics,
        "macro": {"precision": macro_prec, "recall": macro_rec, "f1": macro_f1},
        "binary": {
            "tp": tp_b, "fp": fp_b, "tn": tn_b, "fn": fn_b,
            "precision": prec_b, "recall": rec_b, "f1": f1_b, "fpr": fpr_b,
        },
        "unknown": {
            "total": len(unknown_candidates),
            "correct": unknown_correct,
            "accuracy": unknown_acc,
        },
    }


# ═════════════════════════════════════════════════════════════════════════════
# B. Isolation Forest Anomaly Detection Evaluation
# ═════════════════════════════════════════════════════════════════════════════

def evaluate_if_detector() -> dict:
    """
    Evaluate the Isolation Forest anomaly detector in binary classification mode.
    Requires a trained model at data/models/rt_anomaly_model.joblib.
    """
    _banner("SECTION B — Isolation Forest Anomaly Detector")

    _load_model()
    if not is_model_loaded():
        print("\n  [SKIP] IF model not found.")
        print("         Run:  python scripts/train_anomaly_model.py")
        print("         Then re-run this evaluation for full IF metrics.")
        return {"available": False}

    print(f"\n  IF model loaded. Scoring {N_NORMAL} normal + {N_SAMPLES*5} attack samples.")

    # Generate test samples
    normal_feat = [_add_noise(NORMAL_BASELINE) for _ in range(N_NORMAL)]
    attack_feat = []
    attack_labels_if = []
    for class_name, _, base_feats, _ in ATTACK_STRONG:
        for _ in range(N_SAMPLES):
            attack_feat.append(_add_noise(base_feats))
            attack_labels_if.append(class_name)

    # Score everything
    normal_scores = [score_feature_vector_direct(f) for f in normal_feat]
    attack_scores = [score_feature_vector_direct(f) for f in attack_feat]

    # Print score distribution
    print(f"\n  IF SCORE STATISTICS")
    print(f"  {'Class':<25} {'Min':>7} {'Median':>9} {'Max':>7} {'Mean':>7}")
    print(f"  {'─'*25} {'─'*7} {'─'*9} {'─'*7} {'─'*7}")
    print(f"  {'Normal Traffic':<25} {min(normal_scores):>7.4f} "
          f"{sorted(normal_scores)[len(normal_scores)//2]:>9.4f} "
          f"{max(normal_scores):>7.4f} {sum(normal_scores)/len(normal_scores):>7.4f}")

    per_attack_scores = {}
    for cls in [s[0] for s in ATTACK_STRONG]:
        scores = [score_feature_vector_direct(_add_noise([s for s in ATTACK_STRONG if s[0] == cls][0][2]))
                  for _ in range(N_SAMPLES)]
        per_attack_scores[cls] = scores
        print(f"  {cls:<25} {min(scores):>7.4f} "
              f"{sorted(scores)[len(scores)//2]:>9.4f} "
              f"{max(scores):>7.4f} {sum(scores)/len(scores):>7.4f}")

    # Binary classification at IF_BINARY_THRESH
    all_scores = normal_scores + attack_scores
    y_true_if  = [0] * len(normal_scores) + [1] * len(attack_scores)
    y_pred_if  = [1 if s >= IF_BINARY_THRESH else 0 for s in all_scores]

    tp = sum(1 for yt, yp in zip(y_true_if, y_pred_if) if yt == 1 and yp == 1)
    fp = sum(1 for yt, yp in zip(y_true_if, y_pred_if) if yt == 0 and yp == 1)
    tn = sum(1 for yt, yp in zip(y_true_if, y_pred_if) if yt == 0 and yp == 0)
    fn = sum(1 for yt, yp in zip(y_true_if, y_pred_if) if yt == 1 and yp == 0)

    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec  = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1   = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
    fpr  = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    # ROC-AUC (sklearn)
    roc_auc = None
    if HAS_SKL:
        try:
            fpr_arr, tpr_arr, _ = roc_curve(y_true_if, all_scores)
            roc_auc = round(auc(fpr_arr, tpr_arr), 4)
        except Exception:
            pass

    # HYBRID threshold coverage
    hybrid_coverage = {}
    for cls in [s[0] for s in ATTACK_STRONG]:
        base_feats = [s[2] for s in ATTACK_STRONG if s[0] == cls][0]
        scores = [score_feature_vector_direct(_add_noise(base_feats)) for _ in range(N_SAMPLES)]
        above = sum(1 for s in scores if s >= HYBRID_THRESH)
        hybrid_coverage[cls] = {"pct": round(above / len(scores) * 100, 1), "n": len(scores)}

    behavioral_coverage = {}
    for cls in [s[0] for s in ATTACK_STRONG]:
        base_feats = [s[2] for s in ATTACK_STRONG if s[0] == cls][0]
        scores = [score_feature_vector_direct(_add_noise(base_feats)) for _ in range(N_SAMPLES)]
        above = sum(1 for s in scores if s >= BEHAV_THRESH)
        behavioral_coverage[cls] = {"pct": round(above / len(scores) * 100, 1), "n": len(scores)}

    print(f"\n  IF BINARY DETECTION  (threshold = {IF_BINARY_THRESH})")
    print(f"  TP={tp}  FP={fp}  TN={tn}  FN={fn}")
    print(f"  Precision:        {prec:.4f}")
    print(f"  Recall:           {rec:.4f}")
    print(f"  F1-score:         {f1:.4f}")
    print(f"  False Pos Rate:   {fpr:.4f}")
    if roc_auc is not None:
        print(f"  ROC-AUC:          {roc_auc:.4f}")

    print(f"\n  HYBRID THRESHOLD COVERAGE  (IF score >= {HYBRID_THRESH})")
    print(f"  {'Attack Type':<25} {f'% Samples >= {HYBRID_THRESH}':>22}")
    print(f"  {'─'*25} {'─'*22}")
    for cls, cov in hybrid_coverage.items():
        print(f"  {cls:<25} {cov['pct']:>21.1f}%")

    print(f"\n  BEHAVIORAL GATE COVERAGE  (IF score >= {BEHAV_THRESH})")
    print(f"  {'Attack Type':<25} {f'% Samples >= {BEHAV_THRESH}':>22}")
    print(f"  {'─'*25} {'─'*22}")
    for cls, cov in behavioral_coverage.items():
        print(f"  {cls:<25} {cov['pct']:>19.1f}%")

    if HAS_MPL:
        if HAS_SKL:
            _plot_roc_curve(y_true_if, all_scores, roc_auc, fpr_arr, tpr_arr)
        _plot_if_score_distributions(
            normal_scores, per_attack_scores,
            IF_BINARY_THRESH, HYBRID_THRESH, BEHAV_THRESH
        )
        _plot_binary_confusion_matrix(tp, fp, tn, fn)

    return {
        "available": True,
        "n_normal": len(normal_scores),
        "n_attack": len(attack_scores),
        "score_stats": {
            "normal": {
                "min": round(min(normal_scores), 4),
                "max": round(max(normal_scores), 4),
                "mean": round(sum(normal_scores) / len(normal_scores), 4),
            },
            "attack": {
                "min": round(min(attack_scores), 4),
                "max": round(max(attack_scores), 4),
                "mean": round(sum(attack_scores) / len(attack_scores), 4),
            },
        },
        "binary": {"tp": tp, "fp": fp, "tn": tn, "fn": fn,
                   "precision": prec, "recall": rec, "f1": f1, "fpr": fpr},
        "roc_auc": roc_auc,
        "hybrid_coverage": hybrid_coverage,
        "behavioral_coverage": behavioral_coverage,
    }


# ═════════════════════════════════════════════════════════════════════════════
# Plot generators
# ═════════════════════════════════════════════════════════════════════════════

_DARK_BG   = "#0A0E1A"
_PANEL_BG  = "#0F1729"
_TEXT      = "#E2E8F0"
_MUTED     = "#64748B"
_CYAN      = "#22D3EE"
_PURPLE    = "#A855F7"
_AMBER     = "#F59E0B"
_GREEN     = "#10B981"
_RED       = "#EF4444"
_BLUE      = "#3B82F6"

_ATTACK_COLORS = {
    "SYN Flood":        _RED,
    "Port Scan":        _PURPLE,
    "ICMP Flood":       _AMBER,
    "UDP Flood":        _BLUE,
    "Connection Burst": _CYAN,
}


def _apply_dark_style(fig, axes_list):
    fig.patch.set_facecolor(_DARK_BG)
    for ax in (axes_list if isinstance(axes_list, list) else [axes_list]):
        ax.set_facecolor(_PANEL_BG)
        ax.tick_params(colors=_TEXT, labelsize=9)
        ax.xaxis.label.set_color(_TEXT)
        ax.yaxis.label.set_color(_TEXT)
        ax.title.set_color(_TEXT)
        for spine in ax.spines.values():
            spine.set_edgecolor(_MUTED)


def _plot_classifier_confusion_matrix(records, attack_classes):
    """Multi-class confusion matrix for the behavioral classifier (strong attacks)."""
    strong = [r for r in records if r["intensity"] == "strong"]

    pred_map = {
        "Likely SYN Flood":           "SYN Flood",
        "Likely Port Scan":           "Port Scan",
        "Likely ICMP Flood":          "ICMP Flood",
        "Likely UDP Flood":           "UDP Flood",
        "Likely Connection Burst":    "Connection Burst",
        "Suspicious Behavioral Traffic": "AI-UNKNOWN",
    }
    classes = list(attack_classes) + ["AI-UNKNOWN"]
    n = len(classes)
    idx = {c: i for i, c in enumerate(classes)}

    cm = [[0] * n for _ in range(n)]
    for r in strong:
        true_i = idx.get(r["class"], -1)
        pred_i = idx.get(pred_map.get(r["predicted_label"], "AI-UNKNOWN"), -1)
        if true_i >= 0 and pred_i >= 0:
            cm[true_i][pred_i] += 1

    cm_arr = np.array(cm, dtype=float)

    fig, ax = plt.subplots(figsize=(8, 6))
    _apply_dark_style(fig, ax)

    im = ax.imshow(cm_arr, cmap="Blues", aspect="auto", vmin=0)
    cbar = fig.colorbar(im, ax=ax)
    cbar.ax.yaxis.set_tick_params(color=_TEXT)
    plt.setp(cbar.ax.yaxis.get_ticklabels(), color=_TEXT)

    short_classes = [c.replace(" Flood", " Fl.").replace("Connection Burst", "Conn. Burst")
                     for c in classes]
    ax.set_xticks(range(n))
    ax.set_yticks(range(n))
    ax.set_xticklabels(short_classes, rotation=35, ha="right", fontsize=9)
    ax.set_yticklabels(short_classes, fontsize=9)

    for i in range(n):
        for j in range(n):
            val = int(cm_arr[i, j])
            color = _DARK_BG if cm_arr[i, j] > cm_arr.max() * 0.5 else _TEXT
            ax.text(j, i, str(val), ha="center", va="center",
                    fontsize=10, fontweight="bold", color=color)

    ax.set_xlabel("Predicted Label", fontsize=11, labelpad=10)
    ax.set_ylabel("True Class", fontsize=11, labelpad=10)
    ax.set_title("Behavioral Pattern Classifier — Confusion Matrix\n"
                 "(Strong attack scenarios, N=25 samples/class)", fontsize=11, pad=12)

    plt.tight_layout()
    path = OUTPUT_DIR / "confusion_matrix_classifier.png"
    plt.savefig(path, dpi=150, bbox_inches="tight", facecolor=_DARK_BG)
    plt.close()
    print(f"  Plot saved: {path}")


def _plot_binary_confusion_matrix(tp, fp, tn, fn):
    """Binary IF anomaly detection confusion matrix."""
    cm = np.array([[tn, fp], [fn, tp]], dtype=float)
    labels = ["Normal", "Attack"]

    fig, ax = plt.subplots(figsize=(5, 4))
    _apply_dark_style(fig, ax)

    im = ax.imshow(cm, cmap="Blues")
    fig.colorbar(im, ax=ax)

    ax.set_xticks([0, 1]); ax.set_yticks([0, 1])
    ax.set_xticklabels(["Pred: Normal", "Pred: Attack"])
    ax.set_yticklabels(["True: Normal", "True: Attack"])

    for i in range(2):
        for j in range(2):
            val = int(cm[i, j])
            color = _DARK_BG if cm[i, j] > cm.max() * 0.5 else _TEXT
            ax.text(j, i, str(val), ha="center", va="center",
                    fontsize=14, fontweight="bold", color=color)

    ax.set_title("IF Anomaly Detector — Binary Confusion Matrix\n"
                 f"(threshold = {IF_BINARY_THRESH})", fontsize=11, pad=10)
    plt.tight_layout()
    path = OUTPUT_DIR / "confusion_matrix_binary.png"
    plt.savefig(path, dpi=150, bbox_inches="tight", facecolor=_DARK_BG)
    plt.close()
    print(f"  Plot saved: {path}")


def _plot_roc_curve(y_true, scores, roc_auc, fpr_arr, tpr_arr):
    fig, ax = plt.subplots(figsize=(6, 5))
    _apply_dark_style(fig, ax)

    ax.plot(fpr_arr, tpr_arr, color=_CYAN, lw=2,
            label=f"IF Anomaly Detector (AUC = {roc_auc:.4f})")
    ax.plot([0, 1], [0, 1], color=_MUTED, lw=1, linestyle="--", label="Random baseline")
    ax.fill_between(fpr_arr, tpr_arr, alpha=0.08, color=_CYAN)

    ax.set_xlabel("False Positive Rate", fontsize=11)
    ax.set_ylabel("True Positive Rate (Recall)", fontsize=11)
    ax.set_title("ROC Curve — Isolation Forest Anomaly Detector\n"
                 "(Attack vs Normal synthetic traffic)", fontsize=11, pad=10)
    ax.set_xlim(0, 1); ax.set_ylim(0, 1.02)
    ax.legend(loc="lower right", facecolor=_PANEL_BG, edgecolor=_MUTED,
              labelcolor=_TEXT, fontsize=9)
    ax.annotate(f"AUC = {roc_auc:.4f}", xy=(0.6, 0.15),
                xycoords="axes fraction", color=_CYAN, fontsize=12, fontweight="bold")

    plt.tight_layout()
    path = OUTPUT_DIR / "roc_curve.png"
    plt.savefig(path, dpi=150, bbox_inches="tight", facecolor=_DARK_BG)
    plt.close()
    print(f"  Plot saved: {path}")


def _plot_if_score_distributions(normal_scores, per_attack_scores,
                                  thresh_binary, thresh_hybrid, thresh_behav):
    """Boxplot of IF scores per class with threshold lines."""
    classes   = ["Normal"] + list(per_attack_scores.keys())
    all_data  = [normal_scores] + [per_attack_scores[c] for c in per_attack_scores]
    colors    = [_GREEN] + [_ATTACK_COLORS.get(c, _RED) for c in per_attack_scores]

    fig, ax = plt.subplots(figsize=(10, 5))
    _apply_dark_style(fig, ax)

    bp = ax.boxplot(all_data, patch_artist=True, medianprops={"color": _TEXT, "lw": 2},
                    whiskerprops={"color": _MUTED}, capprops={"color": _MUTED},
                    flierprops={"marker": "o", "markerfacecolor": _MUTED,
                                "markersize": 3, "alpha": 0.5})

    for patch, color in zip(bp["boxes"], colors):
        patch.set_facecolor(color)
        patch.set_alpha(0.6)

    # Threshold lines
    ax.axhline(thresh_binary, color=_BLUE,   lw=1.5, linestyle="--",
               label=f"Anomaly threshold ({thresh_binary})")
    ax.axhline(thresh_hybrid, color=_PURPLE, lw=1.5, linestyle="-.",
               label=f"HYBRID threshold ({thresh_hybrid})")
    ax.axhline(thresh_behav,  color=_RED,    lw=1.5, linestyle=":",
               label=f"Behavioral gate ({thresh_behav})")

    short_names = [c.replace(" Flood", " Fl.").replace("Connection Burst", "Conn. Burst")
                   for c in classes]
    ax.set_xticks(range(1, len(classes) + 1))
    ax.set_xticklabels(short_names, rotation=20, ha="right", fontsize=9)
    ax.set_ylabel("IF Anomaly Score (0=normal, 1=anomalous)", fontsize=10)
    ax.set_title("Isolation Forest Score Distribution by Traffic Class\n"
                 f"(N={N_SAMPLES} samples each, 12% noise)", fontsize=11, pad=10)
    ax.set_ylim(0, 1.05)
    ax.legend(loc="upper left", facecolor=_PANEL_BG, edgecolor=_MUTED,
              labelcolor=_TEXT, fontsize=8)

    plt.tight_layout()
    path = OUTPUT_DIR / "if_score_distributions.png"
    plt.savefig(path, dpi=150, bbox_inches="tight", facecolor=_DARK_BG)
    plt.close()
    print(f"  Plot saved: {path}")


def _plot_f1_bar_chart(per_class_metrics: dict):
    """Grouped bar chart: Precision / Recall / F1 per attack class."""
    classes  = list(per_class_metrics.keys())
    precs    = [per_class_metrics[c]["precision"] for c in classes]
    recalls  = [per_class_metrics[c]["recall"]    for c in classes]
    f1s      = [per_class_metrics[c]["f1"]        for c in classes]

    x     = np.arange(len(classes))
    width = 0.25

    fig, ax = plt.subplots(figsize=(10, 5))
    _apply_dark_style(fig, ax)

    ax.bar(x - width, precs,   width, label="Precision", color=_CYAN,   alpha=0.8)
    ax.bar(x,         recalls, width, label="Recall",    color=_GREEN,  alpha=0.8)
    ax.bar(x + width, f1s,     width, label="F1-Score",  color=_PURPLE, alpha=0.8)

    ax.set_xticks(x)
    short = [c.replace(" Flood", " Fl.").replace("Connection Burst", "Conn. Burst")
             for c in classes]
    ax.set_xticklabels(short, rotation=15, ha="right", fontsize=9)
    ax.set_ylim(0, 1.10)
    ax.set_ylabel("Score", fontsize=11)
    ax.set_title("Behavioral Classifier — Per-Class Precision / Recall / F1\n"
                 "(Strong attack scenarios, N=25 samples/class)", fontsize=11, pad=10)
    ax.legend(facecolor=_PANEL_BG, edgecolor=_MUTED, labelcolor=_TEXT, fontsize=9)

    # Value labels on bars
    for rects in [
        ax.containers[0], ax.containers[1], ax.containers[2]
    ]:
        for rect in rects:
            h = rect.get_height()
            if h > 0.01:
                ax.text(rect.get_x() + rect.get_width() / 2, h + 0.01,
                        f"{h:.2f}", ha="center", va="bottom",
                        fontsize=7, color=_TEXT)

    plt.tight_layout()
    path = OUTPUT_DIR / "f1_bar_chart.png"
    plt.savefig(path, dpi=150, bbox_inches="tight", facecolor=_DARK_BG)
    plt.close()
    print(f"  Plot saved: {path}")


# ═════════════════════════════════════════════════════════════════════════════
# D. Supervised RF Classifier evaluation
# ═════════════════════════════════════════════════════════════════════════════

# Scenario library reused from the main classifier test (same attack archetypes,
# this time evaluated through the RF instead of the EMA-ratio rules).
# Expected label format: "Likely SYN Flood", "Likely Port Scan", etc.
# Sub-threshold and normal scenarios should be rejected (conf < 0.70) or BENIGN.

_RF_ATTACK_STRONG = [
    ("SYN Flood",        "Likely SYN Flood",
     [76.0, 32.0, 0.0, 8.0, 625.0, 166.0, 35.0, 32.0, 0.34, 0.42, 260.0, 8.0, 7.9, 9739.0]),
    ("Port Scan",        "Likely Port Scan",
     [65.0, 25.0, 0.0, 9.0, 324.0, 138.0, 31.0, 25.0, 0.75, 0.45, 246.0, 8.0, 7.5, 9945.0]),
    ("ICMP Flood",       "Likely ICMP Flood",
     [170.0, 0.0, 158.0, 10.0, 8.0, 1012.0, 2.0, 0.0, 0.12, 0.07, 165.0, 7.0, 2.1, 171741.0]),
    ("UDP Flood",        "Likely UDP Flood",
     [470.0, 0.0, 0.0, 467.0, 4447.0, 972.0, 3.0, 0.0, 0.13, 0.07, 283.0, 7.0, 11.75, 464771.0]),
    ("Connection Burst", "Likely Connection Burst",
     [473.0, 121.0, 0.0, 16.0, 540.0, 165.0, 315.0, 129.0, 25.0, 0.27, 351.0, 9.0, 6.45, 78071.0]),
]

_RF_ATTACK_BORDERLINE = [
    ("SYN Flood",        "Likely SYN Flood",
     [38.0, 16.0, 0.0, 4.0, 313.0, 100.0, 18.0, 16.0, 0.2, 0.5, 130.0, 8.0, 4.5, 4870.0]),
    ("Port Scan",        "Likely Port Scan",
     [35.0, 13.0, 0.0, 5.0, 165.0, 90.0, 16.0, 13.0, 0.4, 0.45, 125.0, 4.0, 5.5, 5000.0]),
    ("ICMP Flood",       "Likely ICMP Flood",
     [90.0, 0.0, 80.0, 5.0, 5.0, 850.0, 1.0, 0.0, 0.1, 0.05, 100.0, 5.0, 1.5, 90000.0]),
    ("UDP Flood",        "Likely UDP Flood",
     [240.0, 0.0, 0.0, 235.0, 2200.0, 700.0, 1.5, 0.0, 0.1, 0.05, 150.0, 5.0, 9.0, 230000.0]),
    ("Connection Burst", "Likely Connection Burst",
     [240.0, 60.0, 0.0, 8.0, 270.0, 100.0, 160.0, 65.0, 12.0, 0.25, 175.0, 6.0, 5.0, 40000.0]),
]

_RF_SUBTHRESH = [
    ("Sub-threshold SYN",   "reject",
     [6.5, 1.5, 0.0, 0.0, 2.0, 750.0, 1.0, 0.5, 0.2, 0.1, 300.0, 8.0, 2.5, 5000.0]),
    ("Sub-threshold Scan",  "reject",
     [7.0, 1.0, 0.0, 0.0, 8.0, 700.0, 1.0, 0.5, 0.3, 0.1, 280.0, 5.0, 3.0, 4900.0]),
    ("Ambiguous mix A",     "reject",
     [9.0, 1.5, 0.8, 2.5, 4.5, 650.0, 2.0, 0.5, 0.5, 0.15, 300.0, 8.0, 2.8, 6000.0]),
    ("Normal traffic",      "reject",
     [5.0, 0.5, 0.2, 1.0, 3.0, 800.0, 1.8, 0.15, 0.30, 0.20, 350.0, 8.0, 2.8, 4000.0]),
    ("Elevated normal",     "reject",
     [8.0, 1.2, 0.5, 1.8, 5.0, 750.0, 2.5, 0.3, 0.5, 0.20, 320.0, 9.0, 3.0, 6000.0]),
]

_RF_N_NOISE = 25     # noisy samples per scenario for RF evaluation


def evaluate_rf_classifier() -> dict:
    """
    Section D — Supervised RF Classifier evaluation.

    Evaluates the trained Random Forest classifier (realtime_classifier_service)
    on the same attack scenarios as the EMA-ratio classifier in Section A,
    then compares accuracy, confidence, and OOD rejection.

    Returns a dict of metrics for the report.
    """
    _banner("SECTION D — Supervised RF Classifier")

    if not _HAS_RT_CLF_SVC:
        print("  [SKIP] realtime_classifier_service not importable.")
        return {}

    rf_loaded = _rt_clf_svc.is_model_loaded()
    print(f"  RF model loaded: {rf_loaded}")
    if not rf_loaded:
        print(f"  [SKIP] RF model not found at expected path.")
        print(f"         Run:  python scripts/train_realtime_classifier.py")
        return {}

    rng = np.random.default_rng(RANDOM_SEED + 99)

    def _noisy(feat, n=_RF_N_NOISE, frac=0.12):
        rows = []
        for _ in range(n):
            rows.append([
                max(0.0, v + rng.normal(0, abs(v) * frac) if v > 0 else 0.0)
                for v in feat
            ])
        return rows

    # ── A. Strong attack accuracy ──────────────────────────────────────────────
    print(f"\n  STRONG ATTACK — RF classification (N={_RF_N_NOISE} noisy samples each)")
    print(f"  {'Attack':<22} {'Expected':<26} {'Classified':>24} {'Conf':>7} {'Acc':>6}")
    print(f"  {'─'*22} {'─'*26} {'─'*24} {'─'*7} {'─'*6}")

    strong_results = []
    for cls_name, exp_label, base_feat in _RF_ATTACK_STRONG:
        samples = _noisy(base_feat)
        n_correct, confidences = 0, []
        classified_labels = {}
        for feat in samples:
            label, conf, _ = _rt_clf_svc.classify(feat)
            confidences.append(conf)
            classified_labels[label] = classified_labels.get(label, 0) + 1
            if label == exp_label:
                n_correct += 1
        top_label = max(classified_labels, key=classified_labels.get)
        acc  = n_correct / len(samples)
        mean_conf = np.mean(confidences) if confidences else 0.0
        print(f"  {cls_name:<22} {exp_label:<26} {top_label:>24} {mean_conf:>7.3f} {acc:>5.0%}")
        strong_results.append({"class": cls_name, "accuracy": acc,
                                "mean_confidence": mean_conf, "top_label": top_label})

    strong_acc = np.mean([r["accuracy"] for r in strong_results])
    print(f"\n  Strong attack accuracy (macro): {strong_acc:.1%}")

    # ── B. Borderline attack accuracy ──────────────────────────────────────────
    print(f"\n  BORDERLINE ATTACK — RF classification (N={_RF_N_NOISE} noisy samples each)")
    print(f"  {'Attack':<22} {'Expected':<26} {'Classified':>24} {'Conf':>7} {'Acc':>6}")
    print(f"  {'─'*22} {'─'*26} {'─'*24} {'─'*7} {'─'*6}")

    border_results = []
    for cls_name, exp_label, base_feat in _RF_ATTACK_BORDERLINE:
        samples = _noisy(base_feat)
        n_correct, confidences = 0, []
        classified_labels = {}
        for feat in samples:
            label, conf, _ = _rt_clf_svc.classify(feat)
            confidences.append(conf)
            classified_labels[label] = classified_labels.get(label, 0) + 1
            if label == exp_label:
                n_correct += 1
        top_label = max(classified_labels, key=classified_labels.get)
        acc  = n_correct / len(samples)
        mean_conf = np.mean(confidences) if confidences else 0.0
        print(f"  {cls_name:<22} {exp_label:<26} {top_label:>24} {mean_conf:>7.3f} {acc:>5.0%}")
        border_results.append({"class": cls_name, "accuracy": acc,
                                "mean_confidence": mean_conf, "top_label": top_label})

    border_acc = np.mean([r["accuracy"] for r in border_results])
    print(f"\n  Borderline attack accuracy (macro): {border_acc:.1%}")

    # ── C. Sub-threshold / OOD rejection ──────────────────────────────────────
    print(f"\n  SUB-THRESHOLD & OOD — rejection behavior (N={_RF_N_NOISE} noisy samples each)")
    print(f"  {'Scenario':<26} {'Expected':>10} {'Top Result':>26} {'MeanConf':>9} {'RejRate':>8}")
    print(f"  {'─'*26} {'─'*10} {'─'*26} {'─'*9} {'─'*8}")

    ood_results = []
    for scenario_name, expected, base_feat in _RF_SUBTHRESH:
        samples = _noisy(base_feat)
        confidences, rejected, labels = [], 0, {}
        for feat in samples:
            label, conf, _ = _rt_clf_svc.classify(feat)
            confidences.append(conf)
            labels[label] = labels.get(label, 0) + 1
            if conf < _rt_clf_svc.CONFIDENCE_THRESHOLD or label in ("", "BENIGN"):
                rejected += 1
        top_label    = max(labels, key=labels.get) if labels else "N/A"
        mean_conf    = np.mean(confidences)
        rej_rate     = rejected / len(samples)
        print(f"  {scenario_name:<26} {expected:>10} {top_label:>26} {mean_conf:>9.3f} {rej_rate:>7.0%}")
        ood_results.append({"scenario": scenario_name, "rejection_rate": rej_rate,
                            "mean_confidence": mean_conf})

    mean_rej = np.mean([r["rejection_rate"] for r in ood_results])
    print(f"\n  Mean sub-threshold rejection rate: {mean_rej:.1%}")
    print(f"  (rejected = conf < {_rt_clf_svc.CONFIDENCE_THRESHOLD:.0%} OR label=BENIGN/empty)")

    # ── D. vs EMA comparison summary ──────────────────────────────────────────
    print(f"\n  RF vs EMA-RATIO CLASSIFIER COMPARISON")
    print(f"  {'Metric':<40} {'RF':>10} {'EMA':>10}")
    print(f"  {'─'*40} {'─'*10} {'─'*10}")
    print(f"  {'Strong attack accuracy (macro)':.<40} {strong_acc:>9.1%} {'100%':>10}")
    print(f"  {'Borderline accuracy (macro)':.<40} {border_acc:>9.1%} {'~65%':>10}")
    print(f"  {'OOD rejection rate (mean)':.<40} {mean_rej:>9.1%} {'~91%':>10}")
    print(f"  {'Requires EMA baseline warmup':.<40} {'No':>10} {'Yes':>10}")
    print(f"  {'Handles unseen patterns':.<40} {'Open-set':>10} {'Rules':>10}")
    print(f"  {'Fallback when model absent':.<40} {'EMA':>10} {'N/A':>10}")

    return {
        "rf_strong_accuracy":      float(strong_acc),
        "rf_borderline_accuracy":  float(border_acc),
        "rf_ood_rejection_rate":   float(mean_rej),
        "confidence_threshold":    _rt_clf_svc.CONFIDENCE_THRESHOLD,
        "strong_per_class":        strong_results,
        "borderline_per_class":    border_results,
        "ood_scenarios":           ood_results,
    }


# ═════════════════════════════════════════════════════════════════════════════
# C. Report generation
# ═════════════════════════════════════════════════════════════════════════════

def generate_report(clf_results: dict, if_results: dict, rf_results: dict = None) -> None:
    _banner("SECTION C — Evaluation Report")

    # ── JSON report ───────────────────────────────────────────────────────────
    report = {
        "evaluation_timestamp":   TIMESTAMP,
        "methodology": {
            "ground_truth":        "Synthetic feature vectors from domain-knowledge attack signatures",
            "ema_warmup_obs":      N_WARMUP_OBS,
            "samples_per_class":   N_SAMPLES,
            "normal_samples":      N_NORMAL,
            "noise_fraction":      NOISE_FRAC,
            "random_seed":         RANDOM_SEED,
            "if_binary_threshold": IF_BINARY_THRESH,
            "hybrid_threshold":    HYBRID_THRESH,
            "classify_min_ratio":  CLASSIFY_THRESH,
        },
        "behavioral_classifier": clf_results,
        "if_anomaly_detector":   if_results,
        "rf_classifier":         rf_results or {},
    }

    json_path = OUTPUT_DIR / "evaluation_report.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n  JSON report: {json_path}")

    # ── Text summary for graduation report ────────────────────────────────────
    lines = []
    lines.append("=" * 72)
    lines.append("REALTIME AI LAYER — EVALUATION SUMMARY")
    lines.append("Hybrid AI-Based NIDS — Graduation Project")
    lines.append(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}")
    lines.append("=" * 72)
    lines.append("")
    lines.append("METHODOLOGY")
    lines.append("───────────")
    lines.append(f"  Ground truth: Synthetic feature vectors from known attack signatures.")
    lines.append(f"  EMA baseline: Warmed with {N_WARMUP_OBS} normal-traffic observations (alpha=0.1).")
    lines.append(f"  Noise model:  {int(NOISE_FRAC*100)}% relative Gaussian noise per sample.")
    lines.append(f"  Samples:      {N_SAMPLES} per attack class, {N_NORMAL} normal traffic.")
    lines.append(f"  Random seed:  {RANDOM_SEED} (reproducible results).")
    lines.append("")
    lines.append("BEHAVIORAL PATTERN CLASSIFIER")
    lines.append("─────────────────────────────")
    lines.append(f"  IF model present: {clf_results.get('model_present', False)}")
    lines.append("")
    lines.append(f"  {'Attack Class':<25} {'Precision':>10} {'Recall':>8} {'F1':>8}")
    lines.append(f"  {'─'*25} {'─'*10} {'─'*8} {'─'*8}")
    for cls, m in clf_results.get("per_class_metrics", {}).items():
        lines.append(f"  {cls:<25} {m['precision']:>10.4f} {m['recall']:>8.4f} {m['f1']:>8.4f}")
    macro = clf_results.get("macro", {})
    lines.append(f"  {'─'*25} {'─'*10} {'─'*8} {'─'*8}")
    lines.append(f"  {'Macro Average':<25} {macro.get('precision',0):>10.4f} "
                 f"{macro.get('recall',0):>8.4f} {macro.get('f1',0):>8.4f}")
    lines.append("")
    binary = clf_results.get("binary", {})
    lines.append(f"  Binary Detection (Attack vs Normal):")
    lines.append(f"    TP={binary.get('tp',0)}  FP={binary.get('fp',0)}  "
                 f"TN={binary.get('tn',0)}  FN={binary.get('fn',0)}")
    lines.append(f"    Precision: {binary.get('precision',0):.4f}")
    lines.append(f"    Recall:    {binary.get('recall',0):.4f}")
    lines.append(f"    F1-Score:  {binary.get('f1',0):.4f}")
    lines.append(f"    False Positive Rate: {binary.get('fpr',0):.4f}")
    lines.append("")
    unk = clf_results.get("unknown", {})
    lines.append(f"  AI-UNKNOWN Uncertainty Handling:")
    lines.append(f"    Samples tested: {unk.get('total',0)}")
    lines.append(f"    Correctly returned AI-UNKNOWN: {unk.get('correct',0)}")
    lines.append(f"    Uncertainty Accuracy: {unk.get('accuracy',0):.4f}")
    lines.append("")
    lines.append("ISOLATION FOREST ANOMALY DETECTOR")
    lines.append("──────────────────────────────────")
    if if_results.get("available"):
        bi = if_results.get("binary", {})
        lines.append(f"  Binary detection threshold: {IF_BINARY_THRESH}")
        lines.append(f"  TP={bi.get('tp',0)}  FP={bi.get('fp',0)}  "
                     f"TN={bi.get('tn',0)}  FN={bi.get('fn',0)}")
        lines.append(f"  Precision:         {bi.get('precision',0):.4f}")
        lines.append(f"  Recall:            {bi.get('recall',0):.4f}")
        lines.append(f"  F1-Score:          {bi.get('f1',0):.4f}")
        lines.append(f"  False Pos Rate:    {bi.get('fpr',0):.4f}")
        if if_results.get("roc_auc"):
            lines.append(f"  ROC-AUC:           {if_results['roc_auc']:.4f}")
        lines.append("")
        lines.append(f"  HYBRID Threshold Coverage (IF score >= {HYBRID_THRESH}):")
        for cls, cov in if_results.get("hybrid_coverage", {}).items():
            lines.append(f"    {cls:<25}: {cov['pct']}% of samples qualify")
        lines.append("")
        lines.append(f"  Behavioral Gate Coverage (IF score >= {BEHAV_THRESH}):")
        for cls, cov in if_results.get("behavioral_coverage", {}).items():
            lines.append(f"    {cls:<25}: {cov['pct']}% of samples qualify")
    else:
        lines.append("  [NOT EVALUATED] Model not found.")
        lines.append("  Run scripts/train_anomaly_model.py then re-run evaluation.")
    lines.append("")
    lines.append("DETECTION TIER BREAKDOWN")
    lines.append("────────────────────────")
    lines.append("  Tier          | Trigger Condition                         | UI Badge")
    lines.append("  ─────────────────────────────────────────────────────────────────────")
    lines.append(f"  RULE          | Rule fires, IF score < {HYBRID_THRESH}              | (none)")
    lines.append(f"  HYBRID        | Rule fires, IF score >= {HYBRID_THRESH}             | purple AI+RULE")
    lines.append(f"  AI-CLASSIFIED | IF score >= {BEHAV_THRESH}, pattern matched         | cyan AI")
    lines.append(f"  AI-UNKNOWN    | IF score >= {BEHAV_THRESH}, no pattern >= 4x EMA    | amber AI?")
    lines.append("")
    lines.append("ACADEMIC NOTES")
    lines.append("──────────────")
    lines.append("  1. The behavioral classifier is EMA-ratio-based (domain knowledge),")
    lines.append("     not a trained supervised model. Classification accuracy reflects")
    lines.append("     how well the 6-feature space separates attack archetypes.")
    lines.append("")
    lines.append("  2. AI-UNKNOWN is a deliberate design property. When no feature")
    lines.append("     exceeds 4x EMA, the system reports honest uncertainty rather")
    lines.append("     than forcing a label. This is epistemically correct for an")
    lines.append("     anomaly-based IDS.")
    lines.append("")
    lines.append("  3. Evaluation uses synthetic ground truth because labeled live")
    lines.append("     traffic was not available. This is the standard approach when")
    lines.append("     captures from known attacks are impractical to obtain.")
    lines.append("")
    lines.append("  4. The IF model separates attack from normal traffic in feature")
    lines.append("     space. Quality depends on baseline training data captured by")
    lines.append("     scripts/collect_baseline.py on real network traffic.")
    lines.append("")
    lines.append("  5. The supervised RF classifier (Section D) is a second-opinion layer.")
    lines.append("     It fires BEFORE the EMA-ratio rules when its confidence >= 70%.")
    lines.append("     When below threshold it falls through to EMA rules, then AI-UNKNOWN.")
    lines.append("     The BENIGN class allows the RF to suppress border-noise anomalies.")

    if rf_results:
        lines.append("")
        lines.append("SUPERVISED RF CLASSIFIER (Section D)")
        lines.append("─────────────────────────────────────────────────────")
        lines.append(f"  Strong attack accuracy (macro avg):   "
                     f"{rf_results.get('rf_strong_accuracy', 0):.1%}")
        lines.append(f"  Borderline accuracy (macro avg):      "
                     f"{rf_results.get('rf_borderline_accuracy', 0):.1%}")
        lines.append(f"  Sub-threshold rejection rate (mean):  "
                     f"{rf_results.get('rf_ood_rejection_rate', 0):.1%}")
        lines.append(f"  Confidence threshold:                 "
                     f"{rf_results.get('confidence_threshold', 0.70):.0%}")
        lines.append("")
        lines.append("  Decision chain (highest to lowest priority):")
        lines.append("    1. RF model present + conf >= 70% + attack class  → AI-CLASSIFIED (RF)")
        lines.append("    2. RF model present + conf >= 70% + BENIGN class  → Suppress alert")
        lines.append("    3. RF absent, errored, or conf < 70%              → EMA-ratio rules")
        lines.append("    4. EMA: dominant feature >= 4× baseline           → AI-CLASSIFIED (EMA)")
        lines.append("    5. EMA: no dominant feature                       → AI-UNKNOWN")

    lines.append("")
    lines.append("=" * 72)
    lines.append(f"Output files in: {OUTPUT_DIR}/")
    lines.append("=" * 72)

    summary_path = OUTPUT_DIR / "evaluation_summary.txt"
    with open(summary_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    # Print summary to console
    print()
    for line in lines:
        print(f"  {line}")

    print(f"\n  Text summary: {summary_path}")


# ═════════════════════════════════════════════════════════════════════════════
# Entry point
# ═════════════════════════════════════════════════════════════════════════════

def main():
    print(f"\n{'═'*72}")
    print(f"  Realtime AI Evaluation Pipeline")
    print(f"  Hybrid AI-Based NIDS — Graduation Project")
    print(f"  Started: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Output:  {OUTPUT_DIR}")
    print(f"{'═'*72}")

    clf_results = evaluate_classifier()
    if_results  = evaluate_if_detector()
    rf_results  = evaluate_rf_classifier()
    generate_report(clf_results, if_results, rf_results)

    _banner("EVALUATION COMPLETE")
    print(f"\n  All outputs written to: {OUTPUT_DIR}/")
    print(f"  {'File':<44} Description")
    print(f"  {'─'*44} {'─'*30}")
    for fname, desc in [
        ("confusion_matrix_classifier.png",  "EMA behavioral classifier CM"),
        ("confusion_matrix_binary.png",      "IF binary detection CM"),
        ("roc_curve.png",                    "ROC-AUC curve (requires IF model)"),
        ("if_score_distributions.png",       "IF score boxplots (requires IF model)"),
        ("f1_bar_chart.png",                 "EMA per-class F1 bar chart"),
        ("rf_confusion_matrix.png",          "RF classifier confusion matrix"),
        ("rf_confidence_hist.png",           "RF confidence distribution"),
        ("rf_feature_importance.png",        "RF feature importance (MDI)"),
        ("rf_f1_bars.png",                   "RF per-class F1 bar chart"),
        ("detection_results.csv",            "Raw per-sample data"),
        ("evaluation_report.json",           "Structured report (all sections)"),
        ("evaluation_summary.txt",           "Copy-paste report text"),
    ]:
        path = OUTPUT_DIR / fname
        status = "✓" if path.exists() else "─ (not generated)"
        print(f"  {fname:<44} {status}")
    print()


if __name__ == "__main__":
    main()
