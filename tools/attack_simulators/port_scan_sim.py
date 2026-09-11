#!/usr/bin/env python3
# tools/attack_simulators/port_scan_sim.py
# ─────────────────────────────────────────────────────────────────────────────
# Port Scan simulator for IDS training data collection.
#
# Performs rapid TCP connect() attempts across many destination ports on one
# or more targets. This is the traffic pattern a Port Scan alert should fire on:
# many unique destination ports, moderate total rate, low SYN/ACK ratio.
#
# No admin required.
#
# Usage:
#   python tools/attack_simulators/port_scan_sim.py
#   python tools/attack_simulators/port_scan_sim.py --target 192.168.1.0/24
#   python tools/attack_simulators/port_scan_sim.py --rate 100 --duration 300
# ─────────────────────────────────────────────────────────────────────────────

import argparse
import ipaddress
import random
import socket
import threading
import time
from datetime import datetime

DEFAULT_TARGET   = "127.0.0.1"
DEFAULT_RATE     = 80       # ports scanned per second
DEFAULT_DURATION = 300

COMMON_PORTS = [
    20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    465, 587, 631, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432,
    5900, 6379, 8080, 8443, 8888, 9200, 27017,
]
EXTENDED_PORTS = COMMON_PORTS + list(range(1024, 10000, 37))


def _expand_targets(target_str: str) -> list:
    try:
        net  = ipaddress.ip_network(target_str, strict=False)
        hosts = list(net.hosts())
        if not hosts:
            hosts = [net.network_address]
        return [str(h) for h in hosts[:64]]
    except ValueError:
        return [target_str]


def _scan_worker(targets: list, ports: list, rate: int,
                 stop_event: threading.Event, counters: dict):
    interval = 1.0 / max(rate, 1)
    port_idx = 0

    while not stop_event.is_set():
        host = random.choice(targets)
        port = ports[port_idx % len(ports)]
        port_idx += 1

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.1)
        try:
            s.connect((host, port))
            counters["open"] += 1
        except ConnectionRefusedError:
            counters["closed"] += 1
        except (socket.timeout, OSError):
            counters["filtered"] += 1
        except Exception:
            counters["errors"] += 1
        finally:
            try:
                s.close()
            except Exception:
                pass

        counters["scanned"] += 1
        counters["unique_ports"].add(port)
        time.sleep(interval)


def run(target: str, rate: int, duration: int):
    targets = _expand_targets(target)

    print()
    print("=" * 60)
    print("  PORT SCAN SIMULATOR")
    print(f"  Target(s): {target}  ({len(targets)} host(s))")
    print(f"  Ports    : {len(EXTENDED_PORTS)} port list")
    print(f"  Rate     : ~{rate} ports/s")
    print(f"  Duration : {duration}s")
    print(f"  Started  : {datetime.now().strftime('%H:%M:%S')}")
    print("=" * 60)
    print()
    print("  Run simultaneously:")
    print(f"    python scripts/collect_traffic_windows.py \\")
    print(f"      --interface \"Wi-Fi\" --label \"Port Scan\" --duration {duration}")
    print()
    print("  Press Ctrl+C to stop early.")
    print()

    counters = {
        "scanned": 0, "open": 0, "closed": 0,
        "filtered": 0, "errors": 0,
        "unique_ports": set(),
    }
    stop_event = threading.Event()

    n_threads = max(1, rate // 20)
    threads = []
    for _ in range(n_threads):
        t = threading.Thread(
            target=_scan_worker,
            args=(targets, EXTENDED_PORTS, rate // n_threads, stop_event, counters),
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
            actual_rate = counters["scanned"] / max(elapsed, 0.1)
            print(f"\r  Scanned: {counters['scanned']:>7}  "
                  f"Unique ports: {len(counters['unique_ports']):>4}  "
                  f"Rate: {actual_rate:>6.1f}/s  "
                  f"Remaining: {int(remaining):>4}s   ",
                  end="", flush=True)
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\n  Stopped by user.")

    stop_event.set()
    for t in threads:
        t.join(timeout=2)

    elapsed = time.time() - start
    print(f"\n\n  Done. Scanned {counters['scanned']} ports across "
          f"{len(targets)} host(s) in {elapsed:.1f}s")
    print(f"  Open: {counters['open']}  Closed: {counters['closed']}  "
          f"Filtered: {counters['filtered']}")
    print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Port Scan attack simulator")
    parser.add_argument("--target",   default=DEFAULT_TARGET,
                        help="Target IP or CIDR range (e.g. 192.168.1.0/24)")
    parser.add_argument("--rate",     type=int, default=DEFAULT_RATE,
                        help="Ports scanned per second")
    parser.add_argument("--duration", type=int, default=DEFAULT_DURATION,
                        help="Duration in seconds")
    args = parser.parse_args()
    run(args.target, args.rate, args.duration)
