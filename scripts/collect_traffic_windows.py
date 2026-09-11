#!/usr/bin/env python3
# scripts/collect_traffic_windows.py
# ─────────────────────────────────────────────────────────────────────────────
# Live traffic window collector for realtime classifier retraining.
#
# This script captures live packets via tshark and extracts the IDENTICAL
# 6-feature vectors used by anomaly_service.py at runtime — guaranteeing
# zero feature-drift between training data and inference.
#
# Each 10-second window produces one row written to:
#   data/real_traffic/training_windows.csv    (master dataset, appended)
#   data/real_traffic/sessions/<timestamp>_<label>.csv  (session trace)
#
# Usage:
#   python scripts/collect_traffic_windows.py --interface "Wi-Fi" --label BENIGN --duration 300
#   python scripts/collect_traffic_windows.py --interface "Wi-Fi" --label "SYN Flood" --duration 120
#   python scripts/collect_traffic_windows.py --list-interfaces
#
# Valid labels: BENIGN, SYN Flood, Port Scan, ICMP Flood, UDP Flood, Connection Burst
#
# Run rules:
#   BENIGN      → browse normally. At least 300 s (30 windows) per session.
#   Attack labels → run the matching attack simulator while this script runs.
#
# Feature parity guarantee:
#   This file and anomaly_service.py share:
#     _WINDOW_SECONDS = 10
#     _FLAG_SYN = 0x002, _FLAG_ACK = 0x010
#     FEATURE_NAMES = [total_rate, syn_rate, icmp_rate, udp_rate,
#                      unique_dst_ports, avg_pkt_size]
#   Any change to anomaly_service feature extraction MUST be mirrored here.
# ─────────────────────────────────────────────────────────────────────────────

import argparse
import csv
import json
import math
import os
import queue
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid
from collections import Counter, deque
from datetime import datetime, timezone
from pathlib import Path

# ── Path bootstrap ─────────────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# ── Paths ─────────────────────────────────────────────────────────────────────
DATA_DIR     = ROOT / "data" / "real_traffic"
MASTER_CSV   = DATA_DIR / "training_windows.csv"
SESSIONS_DIR = DATA_DIR / "sessions"
LOG_FILE     = DATA_DIR / "collection_log.json"

DATA_DIR.mkdir(parents=True, exist_ok=True)
SESSIONS_DIR.mkdir(parents=True, exist_ok=True)

# ── Valid labels ───────────────────────────────────────────────────────────────
VALID_LABELS = [
    "BENIGN",
    "SYN Flood",
    "Port Scan",
    "ICMP Flood",
    "UDP Flood",
    "Connection Burst",
]

# ── Feature extraction constants — MUST match anomaly_service.py exactly ──────
_WINDOW_SECONDS = 10
_FLAG_SYN       = 0x002
_FLAG_ACK       = 0x010
_FLAG_RST       = 0x004
_FLAG_FIN       = 0x001

FEATURE_NAMES = [
    "total_rate",
    "syn_rate",
    "icmp_rate",
    "udp_rate",
    "unique_dst_ports",
    "avg_pkt_size",
    "ack_rate",
    "rst_rate",
    "fin_rate",
    "syn_ack_ratio",
    "pkt_size_std",
    "unique_src_ips",
    "dst_port_entropy",
    "bytes_rate",
]

CSV_HEADER = (
    ["session_id", "window_start", "window_index"]
    + FEATURE_NAMES
    + ["label"]
)

# ── tshark ────────────────────────────────────────────────────────────────────
_TSHARK_CANDIDATES = [
    "tshark",
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
]

_FIELDS = [
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "ip.proto",
    "tcp.flags",
    "frame.len",
]
_FIELD_IDX  = {name: i for i, name in enumerate(_FIELDS)}
_FIELD_ARGS = []
for f in _FIELDS:
    _FIELD_ARGS += ["-e", f]


def _find_tshark() -> str:
    for c in _TSHARK_CANDIDATES:
        if shutil.which(c) or Path(c).exists():
            return c
    raise RuntimeError(
        "tshark not found. Install Wireshark and ensure tshark.exe is on PATH."
    )


def _list_interfaces():
    tshark = _find_tshark()
    print("\nAvailable capture interfaces:")
    print("-" * 50)
    result = subprocess.run(
        [tshark, "-D"], capture_output=True, text=True
    )
    print(result.stdout or result.stderr)
    sys.exit(0)


def _parse_line(line: str):
    """Parse one tshark tab-separated line. Returns dict or None."""
    parts = line.strip().split("\t")
    if len(parts) < len(_FIELDS):
        parts += [""] * (len(_FIELDS) - len(parts))

    def get(name):
        return parts[_FIELD_IDX[name]]

    src_ip = get("ip.src")
    dst_ip = get("ip.dst")
    if not src_ip or not dst_ip:
        return None

    tcp_src = get("tcp.srcport")
    tcp_dst = get("tcp.dstport")
    udp_src = get("udp.srcport")
    udp_dst = get("udp.dstport")

    src_port = int(tcp_src) if tcp_src else (int(udp_src) if udp_src else 0)
    dst_port = int(tcp_dst) if tcp_dst else (int(udp_dst) if udp_dst else 0)

    proto_map = {"6": "TCP", "17": "UDP", "1": "ICMP"}
    protocol  = proto_map.get(get("ip.proto"), "OTHER")

    flags_raw = get("tcp.flags")
    tcp_flags = 0
    if flags_raw:
        try:
            tcp_flags = int(flags_raw, 16)
        except ValueError:
            pass

    frame_len_raw = get("frame.len")
    frame_len = int(frame_len_raw) if frame_len_raw else 0

    epoch_raw = get("frame.time_epoch")
    try:
        epoch = float(epoch_raw)
    except (ValueError, TypeError):
        epoch = time.time()

    return {
        "epoch":     epoch,
        "src_ip":    src_ip,
        "dst_ip":    dst_ip,
        "src_port":  src_port,
        "dst_port":  dst_port,
        "protocol":  protocol,
        "tcp_flags": tcp_flags,
        "frame_len": frame_len,
    }


# ── Window feature extractor ──────────────────────────────────────────────────
# This logic is a direct copy of anomaly_service._compute_features() logic.
# DO NOT change without also changing anomaly_service.py.

def _compute_features(window_pkts: list) -> list:
    """
    Compute the 14-feature vector from a list of packet dicts.
    Matches anomaly_service.compute_and_score() exactly.
    """
    if not window_pkts:
        return [0.0] * 14

    n = len(window_pkts)
    syn_count = ack_count = rst_count = fin_count = 0
    icmp_count = udp_count = 0
    total_bytes = 0
    dst_ports: list = []
    src_ips: list = []
    sizes: list = []

    for pkt in window_pkts:
        flags     = pkt.get("tcp_flags", 0)
        protocol  = pkt.get("protocol", "")
        dst_port  = pkt.get("dst_port", 0)
        src_ip    = pkt.get("src_ip", "")
        frame_len = pkt.get("frame_len", 0)

        is_syn = bool(flags & _FLAG_SYN) and not bool(flags & _FLAG_ACK)
        if protocol == "TCP":
            if is_syn:
                syn_count += 1
            if flags & _FLAG_ACK:
                ack_count += 1
            if flags & _FLAG_RST:
                rst_count += 1
            if flags & _FLAG_FIN:
                fin_count += 1
        elif protocol == "ICMP":
            icmp_count += 1
        elif protocol == "UDP":
            udp_count += 1

        if dst_port > 0:
            dst_ports.append(dst_port)
        if src_ip:
            src_ips.append(src_ip)
        sizes.append(frame_len)
        total_bytes += frame_len

    avg_pkt_size = total_bytes / n
    size_std = math.sqrt(sum((s - avg_pkt_size) ** 2 for s in sizes) / n) if n > 1 else 0.0
    sa_denom = syn_count + ack_count
    syn_ack_ratio = syn_count / sa_denom if sa_denom > 0 else 0.0

    def _entropy(vals: list) -> float:
        if not vals:
            return 0.0
        c = Counter(vals)
        tot = len(vals)
        return -sum((v / tot) * math.log2(v / tot) for v in c.values())

    return [
        round(n           / _WINDOW_SECONDS, 4),   # 0  total_rate
        round(syn_count   / _WINDOW_SECONDS, 4),   # 1  syn_rate
        round(icmp_count  / _WINDOW_SECONDS, 4),   # 2  icmp_rate
        round(udp_count   / _WINDOW_SECONDS, 4),   # 3  udp_rate
        float(len(set(dst_ports))),                 # 4  unique_dst_ports
        round(avg_pkt_size, 4),                     # 5  avg_pkt_size
        round(ack_count   / _WINDOW_SECONDS, 4),   # 6  ack_rate
        round(rst_count   / _WINDOW_SECONDS, 4),   # 7  rst_rate
        round(fin_count   / _WINDOW_SECONDS, 4),   # 8  fin_rate
        round(syn_ack_ratio, 4),                    # 9  syn_ack_ratio
        round(size_std, 4),                         # 10 pkt_size_std
        float(len(set(src_ips))),                   # 11 unique_src_ips
        round(_entropy(dst_ports), 4),              # 12 dst_port_entropy
        round(total_bytes / _WINDOW_SECONDS, 4),   # 13 bytes_rate
    ]


# ── Collection engine ─────────────────────────────────────────────────────────

_stop_event = threading.Event()


def _producer(tshark_path: str, interface: str, pkt_queue: queue.Queue):
    cmd = [
        tshark_path,
        "-i", interface,
        "-T", "fields",
        "-l",
        "-E", "header=n",
        "-E", "separator=\t",
        "-E", "quote=n",
    ] + _FIELD_ARGS

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
    except FileNotFoundError:
        print(f"\n[ERROR] tshark not found: {tshark_path}")
        pkt_queue.put(None)
        return

    try:
        for raw_line in proc.stdout:
            if _stop_event.is_set():
                break
            pkt = _parse_line(raw_line)
            if pkt:
                try:
                    pkt_queue.put_nowait(pkt)
                except queue.Full:
                    pass
    finally:
        proc.terminate()
        pkt_queue.put(None)


def collect(interface: str, label: str, duration: int, min_windows: int = 5):
    """
    Main collection loop.

    Parameters
    ----------
    interface   : tshark interface name (e.g. "Wi-Fi")
    label       : attack/benign class label
    duration    : maximum collection time in seconds (0 = unlimited)
    min_windows : warn if fewer than this many windows collected
    """
    tshark = _find_tshark()

    # Session metadata
    session_id   = uuid.uuid4().hex[:8]
    started_at   = datetime.now(timezone.utc)
    ts_str       = started_at.strftime("%Y%m%d_%H%M%S")
    safe_label   = label.replace(" ", "_")
    session_path = SESSIONS_DIR / f"{ts_str}_{safe_label}_{session_id}.csv"

    print()
    print("=" * 68)
    print(f"  TRAFFIC WINDOW COLLECTOR")
    print(f"  Label     : {label}")
    print(f"  Interface : {interface}")
    print(f"  Duration  : {'unlimited' if duration == 0 else f'{duration}s'}")
    print(f"  Window    : {_WINDOW_SECONDS}s each")
    print(f"  Session   : {session_id}")
    print(f"  Session file: {session_path.name}")
    print("=" * 68)

    if label not in VALID_LABELS:
        print(f"\n[WARN] '{label}' is not a standard label.")
        print(f"       Valid labels: {', '.join(VALID_LABELS)}")
        resp = input("       Continue anyway? [y/N] ").strip().lower()
        if resp != "y":
            sys.exit(0)

    if label != "BENIGN":
        print(f"\n[ACTION REQUIRED] Start the '{label}' attack simulator NOW.")
        print(f"  tools/attack_simulators/  ← run the matching script")
        print(f"  Press ENTER when the attack is running...")
        input()

    print(f"\n[INFO] Starting tshark on interface '{interface}'...")
    print(f"       Press Ctrl+C to stop collection early.\n")

    pkt_queue  = queue.Queue(maxsize=50000)
    window_buf = []   # packets in current window
    window_start = time.time()
    window_index = 0
    windows_this_session = []

    producer_thread = threading.Thread(
        target=_producer,
        args=(tshark, interface, pkt_queue),
        daemon=True,
        name="collector-producer",
    )
    producer_thread.start()

    # Allow tshark to start up
    time.sleep(1.5)
    print(f"  {'Win#':>5}  {'total_r':>8}  {'syn_r':>7}  {'ack_r':>7}  "
          f"{'rst_r':>6}  {'sar':>5}  {'ports':>5}  {'entr':>5}  {'pkt_sz':>7}  {'pkts':>6}")
    print(f"  {'-'*5}  {'-'*8}  {'-'*7}  {'-'*7}  "
          f"{'-'*6}  {'-'*5}  {'-'*5}  {'-'*5}  {'-'*7}  {'-'*6}")

    collect_start = time.time()

    try:
        while not _stop_event.is_set():
            # Check duration
            elapsed = time.time() - collect_start
            if duration > 0 and elapsed >= duration:
                break

            # Drain packet queue into window buffer
            deadline = time.time()
            while time.time() - window_start < _WINDOW_SECONDS:
                try:
                    pkt = pkt_queue.get(timeout=0.1)
                    if pkt is None:
                        # tshark died
                        _stop_event.set()
                        break
                    window_buf.append(pkt)
                except queue.Empty:
                    pass

            if _stop_event.is_set():
                break

            # Window is complete — compute features
            features = _compute_features(window_buf)
            n_pkts   = len(window_buf)

            # Print live display (key features: total, syn, ack, rst, sar, ports, entropy, pkt_size)
            print(f"  {window_index+1:>5}  "
                  f"{features[0]:>8.2f}  "   # total_rate
                  f"{features[1]:>7.2f}  "   # syn_rate
                  f"{features[6]:>7.2f}  "   # ack_rate
                  f"{features[7]:>6.2f}  "   # rst_rate
                  f"{features[9]:>5.2f}  "   # syn_ack_ratio
                  f"{features[4]:>5.0f}  "   # unique_dst_ports
                  f"{features[12]:>5.2f}  "  # dst_port_entropy
                  f"{features[5]:>7.1f}  "   # avg_pkt_size
                  f"{n_pkts:>6}")

            # Record row
            row = {
                "session_id":   session_id,
                "window_start": datetime.fromtimestamp(window_start,
                                                       tz=timezone.utc).isoformat(),
                "window_index": window_index,
            }
            for fname, fval in zip(FEATURE_NAMES, features):
                row[fname] = fval
            row["label"] = label
            windows_this_session.append(row)

            # Advance window
            window_buf  = []
            window_start = time.time()
            window_index += 1

    except KeyboardInterrupt:
        print("\n\n  [Ctrl+C] Stopping collection...")

    finally:
        _stop_event.set()

    # ── Save results ──────────────────────────────────────────────────────────
    n_windows = len(windows_this_session)
    print(f"\n  Collected: {n_windows} windows")

    if n_windows == 0:
        print("  [WARN] No windows collected — nothing saved.")
        print("         Check the interface name with --list-interfaces")
        return 0

    # Write session file
    with open(session_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_HEADER)
        writer.writeheader()
        writer.writerows(windows_this_session)
    print(f"  Session file: {session_path}")

    # Append to master CSV
    master_exists = MASTER_CSV.exists()
    with open(MASTER_CSV, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_HEADER)
        if not master_exists:
            writer.writeheader()
        writer.writerows(windows_this_session)

    # Show updated dataset totals
    _show_label_counts()

    # Update collection log
    _append_log({
        "session_id":    session_id,
        "label":         label,
        "interface":     interface,
        "windows":       n_windows,
        "started_at":    started_at.isoformat(),
        "ended_at":      datetime.now(timezone.utc).isoformat(),
        "session_file":  str(session_path),
    })

    if n_windows < min_windows:
        print(f"\n  [WARN] Only {n_windows} windows collected.")
        print(f"         Aim for at least 100 windows per label (= 1000 s ≈ 17 min).")
    else:
        print(f"\n  [OK] Session saved. Run show_dataset_status.py to check balance.")

    return n_windows


def _show_label_counts():
    if not MASTER_CSV.exists():
        return
    counts: dict = {}
    try:
        with open(MASTER_CSV, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                lbl = row.get("label", "?")
                counts[lbl] = counts.get(lbl, 0) + 1
    except Exception:
        return
    total = sum(counts.values())
    print(f"\n  Master dataset ({MASTER_CSV.name}):")
    for lbl in VALID_LABELS + [k for k in counts if k not in VALID_LABELS]:
        n = counts.get(lbl, 0)
        bar = "█" * min(n // 5, 30)
        print(f"    {lbl:<20} {n:>5} windows  {bar}")
    print(f"    {'TOTAL':<20} {total:>5} windows")


def _append_log(entry: dict):
    existing = []
    if LOG_FILE.exists():
        try:
            existing = json.loads(LOG_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    existing.append(entry)
    LOG_FILE.write_text(json.dumps(existing, indent=2), encoding="utf-8")


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Collect labeled traffic windows for realtime IDS retraining.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # 10 minutes of normal browsing
  python scripts/collect_traffic_windows.py --interface "Wi-Fi" --label BENIGN --duration 600

  # 5 minutes of SYN flood traffic
  python scripts/collect_traffic_windows.py --interface "Wi-Fi" --label "SYN Flood" --duration 300

  # List available interfaces
  python scripts/collect_traffic_windows.py --list-interfaces

Valid labels:
  BENIGN, SYN Flood, Port Scan, ICMP Flood, UDP Flood, Connection Burst
        """,
    )
    parser.add_argument(
        "--interface", "-i",
        help="tshark interface name (e.g. 'Wi-Fi', 'Ethernet', '\\Device\\NPF_{GUID}')",
    )
    parser.add_argument(
        "--label", "-l",
        help=f"Traffic class label. One of: {', '.join(VALID_LABELS)}",
    )
    parser.add_argument(
        "--duration", "-d",
        type=int, default=0,
        help="Collection duration in seconds (0 = run until Ctrl+C)",
    )
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List available tshark interfaces and exit",
    )

    args = parser.parse_args()

    if args.list_interfaces:
        _list_interfaces()

    if not args.interface:
        parser.error("--interface is required. Use --list-interfaces to see options.")
    if not args.label:
        parser.error("--label is required.")

    signal.signal(signal.SIGINT, lambda s, f: _stop_event.set())

    collect(
        interface=args.interface,
        label=args.label,
        duration=args.duration,
    )


if __name__ == "__main__":
    main()
