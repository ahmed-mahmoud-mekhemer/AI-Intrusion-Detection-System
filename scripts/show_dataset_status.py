#!/usr/bin/env python3
# scripts/show_dataset_status.py
# ─────────────────────────────────────────────────────────────────────────────
# Inspect the real-traffic training dataset and determine readiness for
# retraining the realtime attack classifier.
#
# Usage:
#   python scripts/show_dataset_status.py
#   python scripts/show_dataset_status.py --detail
# ─────────────────────────────────────────────────────────────────────────────

import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

# ── Paths ─────────────────────────────────────────────────────────────────────
ROOT       = Path(__file__).resolve().parent.parent
DATA_DIR   = ROOT / "data" / "real_traffic"
MASTER_CSV = DATA_DIR / "training_windows.csv"
LOG_FILE   = DATA_DIR / "collection_log.json"
SYNTH_META = ROOT / "data" / "models" / "rt_classifier_meta.json"

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

# Minimum recommended windows per class for a reliable model
MIN_WINDOWS_WARN  = 50    # below this → warn
MIN_WINDOWS_TRAIN = 100   # below this → not ready for retraining

# ── Display constants ─────────────────────────────────────────────────────────
_W = 70
_SEP = "─" * _W


def _read_dataset():
    """Load master CSV. Returns list of row dicts."""
    if not MASTER_CSV.exists():
        return []
    rows = []
    with open(MASTER_CSV, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            rows.append(row)
    return rows


def _read_log():
    if not LOG_FILE.exists():
        return []
    try:
        return json.loads(LOG_FILE.read_text(encoding="utf-8"))
    except Exception:
        return []


def _bar(n, max_n, width=28):
    if max_n == 0:
        return " " * width
    filled = int(n / max_n * width)
    return "█" * filled + "░" * (width - filled)


def show_status(detail: bool = False):
    rows = _read_dataset()
    log  = _read_log()

    print()
    print("=" * _W)
    print("  REAL-TRAFFIC DATASET STATUS")
    print(f"  Master file: {MASTER_CSV}")
    print("=" * _W)

    # ── 1. Class distribution ─────────────────────────────────────────────────
    counts  = defaultdict(int)
    feat_sums = defaultdict(lambda: defaultdict(float))

    for row in rows:
        lbl = row.get("label", "?")
        counts[lbl] += 1
        for f in FEATURE_NAMES:
            try:
                feat_sums[lbl][f] += float(row.get(f, 0))
            except ValueError:
                pass

    total = len(rows)
    max_count = max(counts.values()) if counts else 1

    print(f"\n  CLASS DISTRIBUTION  ({total} total windows)")
    print(f"  {'Label':<22} {'Windows':>8}  {'Bar':<30}  {'Status'}")
    print(f"  {'─'*22} {'─'*8}  {'─'*30}  {'─'*12}")

    all_ready = True
    missing   = []
    for lbl in VALID_LABELS:
        n    = counts.get(lbl, 0)
        bar  = _bar(n, max_count)
        if n == 0:
            status = "MISSING"
            all_ready = False
            missing.append(lbl)
        elif n < MIN_WINDOWS_WARN:
            status = f"LOW ({n}<{MIN_WINDOWS_WARN})"
            all_ready = False
        elif n < MIN_WINDOWS_TRAIN:
            status = f"WARN ({n}<{MIN_WINDOWS_TRAIN})"
        else:
            status = "READY"
        print(f"  {lbl:<22} {n:>8}  {bar}  {status}")

    # Extra labels not in VALID_LABELS (custom)
    for lbl, n in counts.items():
        if lbl not in VALID_LABELS:
            bar = _bar(n, max_count)
            print(f"  {lbl:<22} {n:>8}  {bar}  CUSTOM")

    print(f"  {'─'*22} {'─'*8}")
    print(f"  {'TOTAL':<22} {total:>8}")

    # ── 2. Readiness summary ──────────────────────────────────────────────────
    print(f"\n  READINESS ASSESSMENT")
    print(f"  {_SEP[:_W-2]}")

    min_class_count = min((counts.get(l, 0) for l in VALID_LABELS), default=0)

    if total == 0:
        print(f"  [NOT STARTED] No data collected yet.")
        print(f"  Run: python scripts/collect_traffic_windows.py --interface <iface> --label BENIGN --duration 600")
    elif missing:
        print(f"  [INCOMPLETE] Missing classes: {', '.join(missing)}")
        print(f"  Collect data for each missing class before retraining.")
    elif min_class_count < MIN_WINDOWS_TRAIN:
        under = [l for l in VALID_LABELS if counts.get(l, 0) < MIN_WINDOWS_TRAIN]
        print(f"  [NOT READY] Classes below {MIN_WINDOWS_TRAIN} windows: {', '.join(under)}")
        print(f"  Collect more data for these classes (aim for {MIN_WINDOWS_TRAIN}+ each).")
    else:
        imbalance = max(counts.get(l, 0) for l in VALID_LABELS) / max(min_class_count, 1)
        if imbalance > 5.0:
            print(f"  [UNBALANCED] Max/min ratio = {imbalance:.1f}x. Consider collecting")
            print(f"  more data for under-represented classes.")
        else:
            print(f"  [READY] All classes have >= {min_class_count} windows.")
            print(f"  Run: python scripts/retrain_realtime_classifier.py")

    # ── 3. Collection sessions ────────────────────────────────────────────────
    print(f"\n  COLLECTION SESSIONS ({len(log)} total)")
    if log:
        print(f"  {'Session':>10}  {'Label':<22}  {'Windows':>8}  {'Started'}")
        print(f"  {'─'*10}  {'─'*22}  {'─'*8}  {'─'*20}")
        for entry in log[-15:]:   # show last 15
            started = entry.get("started_at", "")[:16].replace("T", " ")
            print(f"  {entry.get('session_id','?')[:8]:>10}  "
                  f"{entry.get('label','?'):<22}  "
                  f"{entry.get('windows',0):>8}  "
                  f"{started}")
        if len(log) > 15:
            print(f"  ... ({len(log)-15} earlier sessions not shown)")

    # ── 4. Feature statistics per class ───────────────────────────────────────
    if detail and counts:
        print(f"\n  FEATURE MEANS PER CLASS")
        print(f"  {'Label':<22} " + "  ".join(f"{f[:8]:>8}" for f in FEATURE_NAMES))
        print(f"  {'─'*22} " + "  ".join("─" * 8 for _ in FEATURE_NAMES))
        for lbl in VALID_LABELS:
            n = counts.get(lbl, 0)
            if n == 0:
                continue
            means = [feat_sums[lbl][f] / n for f in FEATURE_NAMES]
            row_str = "  ".join(f"{m:>8.2f}" for m in means)
            print(f"  {lbl:<22} {row_str}")

    # ── 5. Synthetic model info ───────────────────────────────────────────────
    if SYNTH_META.exists():
        try:
            meta = json.loads(SYNTH_META.read_text(encoding="utf-8"))
            print(f"\n  CURRENT SYNTHETIC MODEL")
            print(f"  Classes  : {meta.get('classes', [])}")
            print(f"  CV F1    : {meta.get('cv_f1_macro_mean', 0):.4f} "
                  f"± {meta.get('cv_f1_macro_std', 0):.4f}")
            print(f"  Threshold: {meta.get('confidence_threshold', 0.70):.0%}")
            print(f"  Trained on: {meta.get('training_samples', '?')} synthetic samples")
        except Exception:
            pass

    # ── 6. Recommended next steps ─────────────────────────────────────────────
    print(f"\n  RECOMMENDED NEXT STEPS")
    print(f"  {_SEP[:_W-2]}")

    if total == 0:
        _print_collection_plan()
    elif missing:
        for lbl in missing:
            print(f"  • Collect: python scripts/collect_traffic_windows.py "
                  f"--interface <iface> --label \"{lbl}\" --duration 600")
    elif min_class_count < MIN_WINDOWS_TRAIN:
        under = sorted([(counts.get(l, 0), l) for l in VALID_LABELS])
        for cnt, lbl in under[:3]:
            if cnt < MIN_WINDOWS_TRAIN:
                needed = MIN_WINDOWS_TRAIN - cnt
                extra_secs = needed * 10
                print(f"  • {lbl}: collect {needed} more windows "
                      f"({extra_secs}s / {extra_secs//60}m)")
    else:
        print(f"  • Dataset is ready. Run the retraining script:")
        print(f"    python scripts/retrain_realtime_classifier.py")
        print(f"  • Or collect more data for higher confidence:")
        print(f"    Target: 200+ windows per class (33+ minutes each)")

    print()


def _print_collection_plan():
    print("  Collection plan (minimum viable dataset):")
    print()
    plan = [
        ("BENIGN",           "Browse normally (web, YouTube, Discord)",         600),
        ("SYN Flood",        "Run tools/attack_simulators/syn_flood.py",         300),
        ("Port Scan",        "Run tools/attack_simulators/port_scan_sim.py",     300),
        ("ICMP Flood",       "Run tools/attack_simulators/icmp_flood.py",        300),
        ("UDP Flood",        "Run tools/attack_simulators/udp_flood.py",         300),
        ("Connection Burst", "Run tools/attack_simulators/connection_burst.py",  300),
    ]
    total_min = 0
    for label, action, secs in plan:
        mins = secs // 60
        total_min += mins
        print(f"  {label:<22} {secs:>5}s  {action}")
    print(f"\n  Total collection time: ~{total_min} minutes")
    print()
    print("  For each, run simultaneously:")
    print("  1. This collector:  python scripts/collect_traffic_windows.py \\")
    print("                        --interface \"Wi-Fi\" --label \"<LABEL>\" \\")
    print("                        --duration <SECONDS>")
    print("  2. Attack script:   python tools/attack_simulators/<script>.py")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Show real-traffic dataset status and retraining readiness."
    )
    parser.add_argument(
        "--detail", "-d",
        action="store_true",
        help="Show per-class feature means",
    )
    args = parser.parse_args()
    show_status(detail=args.detail)
