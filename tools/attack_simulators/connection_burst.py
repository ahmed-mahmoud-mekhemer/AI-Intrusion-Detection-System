#!/usr/bin/env python3
# tools/attack_simulators/connection_burst.py
# ─────────────────────────────────────────────────────────────────────────────
# Connection Burst simulator for IDS training data collection.
#
# Simulates an HTTP/connection flood where many ESTABLISHED connections send
# data simultaneously. Unlike SYN Flood, most traffic is ACK/PSH (data), not
# SYN. Key discriminators vs SYN Flood:
#   - syn_rate stays near baseline (new connections, but quickly established)
#   - unique_dst_ports is LOW (same target ports: 80, 443, 8080)
#   - avg_pkt_size is HIGH (full HTTP requests, not tiny SYN packets)
#   - total_rate is very HIGH (many concurrent connections sending data)
#
# No admin required.
#
# Usage:
#   python tools/attack_simulators/connection_burst.py
#   python tools/attack_simulators/connection_burst.py --target 192.168.1.1
#   python tools/attack_simulators/connection_burst.py --concurrency 80 --duration 300
# ─────────────────────────────────────────────────────────────────────────────

import argparse
import random
import socket
import threading
import time
from datetime import datetime

DEFAULT_TARGET      = "127.0.0.1"
DEFAULT_PORTS       = [80, 443, 8080, 8443]   # few distinct ports — key discriminator
DEFAULT_CONCURRENCY = 60     # simultaneous connections
DEFAULT_DURATION    = 300

# HTTP-like payload — large packets (ACK/PSH flood signature)
HTTP_PAYLOADS = [
    b"GET / HTTP/1.1\r\nHost: target\r\nConnection: keep-alive\r\n\r\n",
    b"POST /api/data HTTP/1.1\r\nHost: target\r\nContent-Length: 512\r\n\r\n" + b"X" * 512,
    b"GET /images/large.jpg HTTP/1.1\r\nHost: target\r\nAccept: */*\r\n\r\n",
    b"HEAD /status HTTP/1.1\r\nHost: target\r\n\r\n",
]


def _connection_worker(target: str, ports: list, stop_event: threading.Event,
                       counters: dict):
    """Opens a connection, sends repeated requests, reconnects on close."""
    while not stop_event.is_set():
        port = random.choice(ports)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)

        try:
            s.connect((target, port))
            counters["connections"] += 1

            # Keep sending data on this connection for a short burst
            burst_end = time.time() + random.uniform(1.0, 4.0)
            while time.time() < burst_end and not stop_event.is_set():
                payload = random.choice(HTTP_PAYLOADS)
                try:
                    s.sendall(payload)
                    counters["sent"] += 1
                    counters["bytes"] += len(payload)
                    # Try to receive response (optional — keeps connection alive)
                    try:
                        s.recv(4096)
                    except Exception:
                        break
                    time.sleep(random.uniform(0.01, 0.05))
                except Exception:
                    break

        except (ConnectionRefusedError, socket.timeout, OSError):
            counters["refused"] += 1
        except Exception:
            counters["errors"] += 1
        finally:
            try:
                s.close()
            except Exception:
                pass

        # Brief pause before reconnecting
        time.sleep(random.uniform(0.05, 0.2))


def run(target: str, ports: list, concurrency: int, duration: int):
    print()
    print("=" * 60)
    print("  CONNECTION BURST SIMULATOR")
    print(f"  Target     : {target}")
    print(f"  Ports      : {ports}  (few distinct — ACK/data flood)")
    print(f"  Concurrency: {concurrency} simultaneous connections")
    print(f"  Duration   : {duration}s")
    print(f"  Started    : {datetime.now().strftime('%H:%M:%S')}")
    print("=" * 60)
    print()
    print("  Traffic profile: HIGH total_rate, LOW syn_rate, FEW dst ports")
    print("  (This is how Connection Burst differs from SYN Flood)")
    print()
    print("  Run simultaneously:")
    print(f"    python scripts/collect_traffic_windows.py \\")
    print(f"      --interface \"Wi-Fi\" --label \"Connection Burst\" --duration {duration}")
    print()
    print("  Press Ctrl+C to stop early.")
    print()

    counters = {
        "connections": 0, "sent": 0, "bytes": 0,
        "refused": 0, "errors": 0,
    }
    stop_event = threading.Event()

    threads = []
    for _ in range(concurrency):
        t = threading.Thread(
            target=_connection_worker,
            args=(target, ports, stop_event, counters),
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
            rate  = counters["sent"] / max(elapsed, 0.1)
            mbps  = counters["bytes"] * 8 / max(elapsed, 0.1) / 1_000_000
            print(f"\r  Connections: {counters['connections']:>6}  "
                  f"Requests: {counters['sent']:>7}  "
                  f"Rate: {rate:>6.1f}/s  "
                  f"{mbps:.2f} Mbps  "
                  f"Remaining: {int(remaining):>4}s   ",
                  end="", flush=True)
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\n  Stopped by user.")

    stop_event.set()
    for t in threads:
        t.join(timeout=3)

    elapsed = time.time() - start
    print(f"\n\n  Done. {counters['connections']} connections, "
          f"{counters['sent']} requests, "
          f"{counters['bytes']//1024} KB sent in {elapsed:.1f}s")
    print(f"  Refused (target not listening): {counters['refused']}")
    print()
    if counters["refused"] > counters["connections"] * 0.5:
        print("  NOTE: Most connections were refused — the target may not have")
        print("  a web server running. For better data, point --target at a")
        print("  host running HTTP (e.g. your local IDS dashboard on :8000).")
        print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Connection Burst (HTTP flood) simulator")
    parser.add_argument("--target",      default=DEFAULT_TARGET,
                        help="Target IP (run a web server there for best results)")
    parser.add_argument("--ports",       type=int, nargs="+", default=DEFAULT_PORTS,
                        help="Target ports (default: 80 443 8080 8443)")
    parser.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY,
                        help="Number of simultaneous connections")
    parser.add_argument("--duration",    type=int, default=DEFAULT_DURATION,
                        help="Duration in seconds")
    args = parser.parse_args()
    run(args.target, args.ports, args.concurrency, args.duration)
