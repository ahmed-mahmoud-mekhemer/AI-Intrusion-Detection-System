#!/usr/bin/env python3
# scripts/collect_baseline.py
# ─────────────────────────────────────────────────────────────────────────────
# Collect baseline (normal) traffic feature windows for Isolation Forest training.
#
# Run this script for several minutes during normal network activity
# (web browsing, background updates, etc.) — NOT during an attack.
# The captured feature windows become the training data for the anomaly model.
#
# Output: data/models/rt_baseline.csv
#         Columns: total_rate, syn_rate, icmp_rate, udp_rate,
#                  unique_dst_ports, avg_pkt_size
#
# Usage:
#   cd ids_project
#   python scripts/collect_baseline.py --interface "Wi-Fi" --minutes 10
# ─────────────────────────────────────────────────────────────────────────────
import argparse
import csv
import shutil
import subprocess
import sys
import time
from collections import deque
from pathlib import Path

# ── tshark setup (mirrors live_monitor_service.py) ────────────────────────────

_TSHARK_CANDIDATES = [
    "tshark",
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
]

_FIELDS = [
    "frame.time_epoch",
    "ip.src", "ip.dst",
    "tcp.srcport", "tcp.dstport",
    "udp.srcport", "udp.dstport",
    "ip.proto",
    "tcp.flags",
    "frame.len",
]

_FIELD_IDX = {name: i for i, name in enumerate(_FIELDS)}

_FIELD_ARGS = []
for f in _FIELDS:
    _FIELD_ARGS += ["-e", f]

_FLAG_SYN = 0x002
_FLAG_ACK = 0x010
_WINDOW_SECONDS = 10

OUTPUT_PATH = Path(__file__).resolve().parent.parent / "data" / "models" / "rt_baseline.csv"
FEATURE_NAMES = [
    "total_rate", "syn_rate", "icmp_rate", "udp_rate",
    "unique_dst_ports", "avg_pkt_size",
]


def _find_tshark() -> str:
    for c in _TSHARK_CANDIDATES:
        if shutil.which(c) or Path(c).exists():
            return c
    sys.exit("ERROR: tshark not found. Install Wireshark and add it to PATH.")


def _parse_line(line: str):
    parts = line.strip().split("\t")
    if len(parts) < len(_FIELDS):
        parts += [""] * (len(_FIELDS) - len(parts))

    def get(name):
        return parts[_FIELD_IDX[name]]

    if not get("ip.src") or not get("ip.dst"):
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

    return (epoch, protocol, tcp_flags, dst_port, frame_len)


def _compute_features(pkts: list) -> list:
    n = len(pkts)
    if n == 0:
        return [0.0] * len(FEATURE_NAMES)

    syn_count  = sum(
        1 for _, proto, flags, _, _ in pkts
        if proto == "TCP" and (flags & _FLAG_SYN) and not (flags & _FLAG_ACK)
    )
    icmp_count = sum(1 for _, proto, _, _, _ in pkts if proto == "ICMP")
    udp_count  = sum(1 for _, proto, _, _, _ in pkts if proto == "UDP")
    ports      = {d for _, _, _, d, _ in pkts if d > 0}
    avg_size   = sum(s for _, _, _, _, s in pkts) / n

    return [
        round(n          / _WINDOW_SECONDS, 4),
        round(syn_count  / _WINDOW_SECONDS, 4),
        round(icmp_count / _WINDOW_SECONDS, 4),
        round(udp_count  / _WINDOW_SECONDS, 4),
        float(len(ports)),
        round(avg_size, 2),
    ]


def collect(interface: str, minutes: int):
    tshark = _find_tshark()
    duration_s = minutes * 60
    end_time   = time.time() + duration_s

    cmd = [
        tshark, "-i", interface,
        "-T", "fields", "-l",
        "-E", "separator=\t",
        "-E", "header=n",
        "-E", "quote=n",
    ] + _FIELD_ARGS

    print(f"[collect] Starting capture on '{interface}' for {minutes} minute(s).")
    print(f"[collect] Output → {OUTPUT_PATH}")
    print("[collect] Use Ctrl+C to stop early.\n")

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    window: deque = deque()
    rows_written = 0
    last_flush   = time.time()

    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        text=True, bufsize=1,
    )

    write_header = not OUTPUT_PATH.exists()
    out_file = open(OUTPUT_PATH, "a", newline="")
    writer = csv.writer(out_file)
    if write_header:
        writer.writerow(FEATURE_NAMES)

    try:
        for line in proc.stdout:
            if time.time() > end_time:
                break

            pkt = _parse_line(line.rstrip("\n"))
            if pkt:
                window.append(pkt)

            now = time.time()
            cutoff = now - _WINDOW_SECONDS

            # Evict old packets
            while window and window[0][0] < cutoff:
                window.popleft()

            # Emit a feature row every 10 seconds
            if now - last_flush >= _WINDOW_SECONDS:
                feats = _compute_features(list(window))
                writer.writerow(feats)
                out_file.flush()
                rows_written += 1
                last_flush = now
                print(f"  [{rows_written:4d} windows] pkts={len(window):5d}  "
                      f"syn_rate={feats[1]:.2f}  icmp_rate={feats[2]:.2f}  "
                      f"udp_rate={feats[3]:.2f}  ports={int(feats[4])}")

    except KeyboardInterrupt:
        print("\n[collect] Interrupted by user.")
    finally:
        proc.terminate()
        out_file.close()

    print(f"\n[collect] Done. {rows_written} feature windows written to {OUTPUT_PATH}")
    if rows_written < 30:
        print("[collect] WARNING: fewer than 30 windows collected. "
              "Run for longer to get a reliable baseline (recommend ≥ 100 windows).")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Collect normal traffic baseline for Isolation Forest training."
    )
    parser.add_argument("--interface", default="Wi-Fi",
                        help="Network interface name (default: Wi-Fi)")
    parser.add_argument("--minutes", type=int, default=10,
                        help="Duration in minutes (default: 10)")
    args = parser.parse_args()
    collect(args.interface, args.minutes)
