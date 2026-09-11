# backend/services/live_monitor_service.py
# ─────────────────────────────────────────────────────────────────────────────
# Lightweight Live Rule-Based Monitoring Layer
#
# Architecture: Hybrid IDS layer 1 of 2
#   This service:   tshark stdout stream → rule engine → immediate alerts
#   Other service:  tshark PCAP chunks  → CICFlowMeter → ML → alerts
#
# Design principles:
#   - No PCAP files written
#   - No CICFlowMeter
#   - No ML model
#   - Producer/consumer queue between capture thread and rule thread
#   - In-memory cooldown to suppress alert spam
#   - Uses existing save_alert() / AlertORM — no new DB table
#   - Thread-safe state via a dataclass + lock
#
# tshark invocation:
#   tshark -i <iface> -T fields -l -e frame.time_epoch -e ip.src ...
#   Each line = one packet as tab-separated field values.
#
# Runtime requirements:
#   Wireshark / tshark on system PATH (or default Windows install path)
#   Npcap with WinPcap-compatible mode for live capture
# ─────────────────────────────────────────────────────────────────────────────
import queue
import shutil
import subprocess
import threading
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from backend.utils.logger import get_logger

logger = get_logger(__name__)

# ── tshark discovery (mirrors capture_service.py) ────────────────────────────

_TSHARK_CANDIDATES = [
    "tshark",
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
]


def _find_tshark() -> str:
    for candidate in _TSHARK_CANDIDATES:
        if shutil.which(candidate) or Path(candidate).exists():
            return candidate
    raise RuntimeError(
        "tshark not found. Install Wireshark and ensure tshark.exe is on PATH."
    )


# ── tshark field definitions ──────────────────────────────────────────────────

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

_FIELD_ARGS = []
for f in _FIELDS:
    _FIELD_ARGS += ["-e", f]

_FIELD_IDX = {name: i for i, name in enumerate(_FIELDS)}


def _parse_line(line: str) -> Optional[dict]:
    """
    Parse one tab-separated tshark output line into a packet dict.
    Returns None for non-IP frames (no ip.src/ip.dst).
    """
    parts = line.strip().split("\t")
    if len(parts) < len(_FIELDS):
        parts += [""] * (len(_FIELDS) - len(parts))

    def get(name: str) -> str:
        return parts[_FIELD_IDX[name]]

    src_ip = get("ip.src")
    dst_ip = get("ip.dst")
    if not src_ip or not dst_ip:
        return None   # non-IP frame (ARP, etc.) — skip

    tcp_src = get("tcp.srcport")
    tcp_dst = get("tcp.dstport")
    udp_src = get("udp.srcport")
    udp_dst = get("udp.dstport")

    # Prefer TCP ports, fall back to UDP
    src_port = int(tcp_src) if tcp_src else (int(udp_src) if udp_src else 0)
    dst_port = int(tcp_dst) if tcp_dst else (int(udp_dst) if udp_dst else 0)

    proto_num = get("ip.proto")
    proto_map = {"6": "TCP", "17": "UDP", "1": "ICMP"}
    protocol  = proto_map.get(proto_num, proto_num or "OTHER")

    # tcp.flags is a hex string like "0x002" (SYN=0x002, ACK=0x010, etc.)
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
        epoch = datetime.now(timezone.utc).timestamp()

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


# ── Detection rules ───────────────────────────────────────────────────────────

# Sliding-window rule parameters
_WINDOW_SECONDS    = 10   # look-back window for burst/scan detection (seconds)
_SYN_WINDOW_SECONDS = 15  # wider window for SYN flood — allows normal TLS bursts to
                           # settle; real floods sustain high rates across any window
_PORT_SCAN_THRESH  = 15   # unique TCP dst_ports from same src in window → Port Scan
_UDP_BURST_THRESH  = 25   # unique UDP dst_ports from same src in window → UDP Burst
_SYN_FLOOD_THRESH  = 150  # pure SYN packets from same src in window → SYN Flood
                           # raised from 80: normal browsing (YouTube, CDN, TLS-heavy
                           # sites) + frontend reconnects can produce 60-80 SYNs in 10 s;
                           # 150 is safely above that and still well below real flood rates
_ICMP_FLOOD_THRESH = 20   # ICMP packets from same src in window → ICMP Flood
_CONN_BURST_THRESH = 120  # total packets from same src in window → Conn Burst
                           # raised from 50: CDN servers (Google, Akamai) legitimately
                           # send 50–100 packets per tab load; 120 only catches real floods

# Brute-force detection parameters
# Heuristic: repeated TCP SYN packets from the same src_ip to the SAME dst_port
# within a short window indicate an automated login guesser (SSH, RDP, FTP, Telnet).
# Unlike the port scan rule (many ports), brute force hammers ONE port repeatedly.
# We use a composite key (src_ip, dst_port) so each service is tracked separately.
#
# Threshold rationale:
#   A human retrying a failed SSH login might do 2–4 attempts in 20 s.
#   Automated tools (Hydra, Medusa, ncrack) typically do 10–100+ per second.
#   20 SYNs to the same port in 20 s is safely above human behaviour and well
#   below the rate at which normal keep-alive reconnects happen.
#
# False-positive risk:
#   - A misconfigured service that reconnects aggressively could trigger this.
#   - Legitimate admin scripts that open many short-lived SSH sessions.
#   - Mitigated by the 60 s cooldown — at most one alert per (src, port) per minute.
#
# ── DISABLED — superseded by the honeypot authentication layer ────────────────
# The honeypot (honeypot_service.py) provides application-layer brute-force
# detection on ports 2222/2323/2121 with actual login attempt evidence.
# This SYN-only heuristic is kept here for reference and can be re-enabled by
# setting _BRUTE_FORCE_ENABLED = True below.
_BRUTE_FORCE_ENABLED = False  # set True to restore network-layer brute-force rule
_BRUTE_FORCE_PORTS   = {22, 21, 23, 3389}  # SSH, FTP, Telnet, RDP
_BRUTE_FORCE_THRESH  = 20   # SYN packets to the same (src_ip, dst_port) in window
_BRUTE_FORCE_WINDOW  = 20   # seconds — wider than the general 10 s window because
                             # human retry delays can stretch a few seconds between attempts

# Alert cooldown: same (rule, src_ip) suppressed for this many seconds
_COOLDOWN_SECONDS = 60    # raised from 30 — one alert per minute per rule/src is enough

# TCP flag bit masks
_FLAG_SYN = 0x002
_FLAG_ACK = 0x010

# ── Traffic classification helpers ────────────────────────────────────────────
#
# False-positive sources observed on a home/office LAN:
#
#   1. DNS (port 53, TCP or UDP)
#      - Your router responds to every DNS query from src_port=53 to a different
#        ephemeral dst_port on your machine → looks like port scan / SYN flood.
#      - Your machine sends DNS queries to port 53 → SYNs to the router on port
#        53 count toward SYN flood.
#      Exclusion: any packet where src OR dst port is 53.
#
#   2. HTTPS return traffic from CDN / web servers (src_port 443 or 80)
#      - Opening 3 browser tabs triggers tens of TCP connections each.
#        The remote server sends many packets back → Connection Burst fires.
#      Exclusion: inbound TCP/UDP from well-known service src ports (80, 443, …).
#
#   3. Multicast / broadcast (SSDP, mDNS, LLMNR, NetBIOS)
#      - Destination is a multicast group or broadcast address → not a real target.
#      Exclusion: dst_ip in multicast/broadcast range, or port in discovery set.
#
#   4. Loopback / link-local addresses — never real threats on a LAN.

# Source ports that indicate this is a *response* from a service, not a scan.
# When these appear as src_port, the packet is inbound service traffic.
_SERVICE_SRC_PORTS = {
    53,    # DNS response
    80,    # HTTP response
    443,   # HTTPS response
    8080,  # alt-HTTP response (remove from suspicious ports too)
    8443,  # alt-HTTPS
    5353,  # mDNS
    5355,  # LLMNR
    67,    # DHCP server
    68,    # DHCP client
    123,   # NTP
}

# Destination ports that belong exclusively to multicast/broadcast services.
_DISCOVERY_DST_PORTS = {
    53,    # DNS query
    1900,  # SSDP / UPnP
    5353,  # mDNS
    5355,  # LLMNR
    137,   # NetBIOS Name Service
    138,   # NetBIOS Datagram
}

# Remove 8080 from suspicious ports — it appears in _SERVICE_SRC_PORTS above
# and generates false positives on normal HTTPS alt-port traffic.
_SUSPICIOUS_PORTS = {4444, 1337, 31337, 23, 3389, 5900, 6666, 12345}


def _is_multicast(ip: str) -> bool:
    """True for IPv4 multicast range 224.0.0.0/4 (224.x.x.x – 239.x.x.x)."""
    try:
        first_octet = int(ip.split(".", 1)[0])
        return 224 <= first_octet <= 239
    except (ValueError, IndexError):
        return False


def _is_broadcast(ip: str) -> bool:
    """True for limited broadcast (255.255.255.255) and common subnet broadcast."""
    return ip == "255.255.255.255" or ip.endswith(".255")


def _is_loopback(ip: str) -> bool:
    return ip.startswith("127.")


def _is_link_local(ip: str) -> bool:
    """True for IPv4 link-local range 169.254.0.0/16."""
    return ip.startswith("169.254.")


def _is_private(ip: str) -> bool:
    """True for RFC-1918 private ranges (192.168.x.x, 10.x.x.x, 172.16-31.x.x)."""
    if ip.startswith("192.168.") or ip.startswith("10."):
        return True
    if ip.startswith("172."):
        try:
            second = int(ip.split(".")[1])
            return 16 <= second <= 31
        except (ValueError, IndexError):
            pass
    return False


def _is_noise_traffic(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                      protocol: str) -> bool:
    """
    Return True for packets that are known-benign and must not feed scan/burst
    rule counters.

    Excluded patterns:
      - Multicast or broadcast destinations (SSDP, mDNS, LLMNR, router adverts)
      - Loopback / link-local addresses
      - DNS traffic in either direction (src or dst port 53) — TCP or UDP.
        DNS over TCP uses SYN packets and produces port variety that mimics scans.
      - Inbound responses from well-known service ports (80, 443, 8080, NTP…).
        CDN return traffic easily exceeds burst thresholds during normal browsing.
      - UDP discovery/service destination ports (mDNS, LLMNR, NetBIOS, SSDP).
    """
    if _is_multicast(dst_ip) or _is_broadcast(dst_ip):
        return True
    if _is_loopback(src_ip) or _is_loopback(dst_ip):
        return True
    if _is_link_local(src_ip) or _is_link_local(dst_ip):
        return True
    # DNS in either direction — both TCP and UDP generate scan-like patterns
    if src_port == 53 or dst_port == 53:
        return True
    # Inbound responses from known service ports are not attack traffic
    if src_port in _SERVICE_SRC_PORTS:
        return True
    # Multicast/broadcast service destination ports
    if dst_port in _DISCOVERY_DST_PORTS:
        return True
    return False


def _is_scan_eligible(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                      protocol: str) -> bool:
    """
    Return True only for traffic that could realistically be a port scan.

    A port scan comes FROM an external/unknown host TO our network.
    Inbound responses from the public internet (CDN, DNS, web servers) arriving
    at high ephemeral dst_ports on our private LAN host are NOT scans — they are
    normal asymmetric TCP: we initiated, they respond to our ephemeral ports.

    Excludes:
      - Any noise traffic (multicast, DNS, service responses)
      - Traffic where the destination is an ephemeral port AND the source is a
        well-known service port — this is a response, not a probe.
    """
    if _is_noise_traffic(src_ip, dst_ip, src_port, dst_port, protocol):
        return False
    # Ephemeral dst_port + service src_port = inbound response, not a scan probe
    if dst_port > 1024 and src_port in _SERVICE_SRC_PORTS:
        return False
    return True


class _WindowTracker:
    """
    Tracks timestamped events per key inside a sliding time window.
    Automatically evicts stale entries older than the window.
    """

    def __init__(self, window: float = _WINDOW_SECONDS):
        self._window  = window
        self._buckets: dict[Any, list[float]] = defaultdict(list)

    def add(self, key: Any, epoch: float) -> int:
        """Record an event and return the current count within the window."""
        bucket = self._buckets[key]
        bucket.append(epoch)
        cutoff = epoch - self._window
        self._buckets[key] = [t for t in bucket if t >= cutoff]
        return len(self._buckets[key])


class _RuleEngine:
    """
    Stateful, in-process rule engine.
    Evaluates each packet dict and returns a list of alert dicts.
    """

    def __init__(self):
        self._syn_tracker      = _WindowTracker(window=_SYN_WINDOW_SECONDS)  # key: src_ip → SYN timestamps
        self._icmp_tracker     = _WindowTracker()  # key: src_ip → ICMP timestamps
        self._burst_tracker    = _WindowTracker()  # key: src_ip → all pkt timestamps
        # Brute-force tracker uses a wider window and a composite key (src_ip, dst_port)
        # so each targeted service is counted independently.
        self._brute_tracker    = _WindowTracker(window=_BRUTE_FORCE_WINDOW)

        # Per-source (epoch, dst_port) tuples for TCP port-scan tracking only.
        # UDP port variety is handled separately by _udp_dst_ports.
        self._tcp_dst_ports: dict[str, list[tuple[float, int]]] = defaultdict(list)
        self._udp_dst_ports: dict[str, list[tuple[float, int]]] = defaultdict(list)

        # Cooldown: (rule_name, src_ip) → last_fired epoch
        self._cooldown: dict[tuple[str, str], float] = {}

    def _on_cooldown(self, rule: str, src_ip: str, epoch: float) -> bool:
        key = (rule, src_ip)
        last = self._cooldown.get(key, 0.0)
        if epoch - last < _COOLDOWN_SECONDS:
            return True
        self._cooldown[key] = epoch
        return False

    @staticmethod
    def _evict(store: list[tuple[float, int]], cutoff: float) -> list[tuple[float, int]]:
        return [(t, p) for (t, p) in store if t >= cutoff]

    def evaluate(self, pkt: dict) -> list[dict]:
        """
        Evaluate a single packet against all rules.
        Returns a (possibly empty) list of alert dicts.
        """
        src    = pkt["src_ip"]
        dst    = pkt["dst_ip"]
        sport  = pkt.get("src_port", 0)
        dport  = pkt["dst_port"]
        proto  = pkt["protocol"]
        flags  = pkt["tcp_flags"]
        epoch  = pkt["epoch"]
        cutoff = epoch - _WINDOW_SECONDS

        alerts = []

        # ── Rule 1: Suspicious destination port ──────────────────────────────
        # Skip multicast/broadcast/noise destinations — never real targets.
        if dport in _SUSPICIOUS_PORTS and not _is_noise_traffic(src, dst, sport, dport, proto):
            rule = "suspicious_port"
            if not self._on_cooldown(rule, src, epoch):
                alerts.append({
                    "rule":     rule,
                    "label":    f"Suspicious Port {dport}",
                    "severity": "HIGH",
                    "src_ip":   src,
                    "dst_ip":   dst,
                    "dst_port": dport,
                    "protocol": proto,
                    "detail":   f"Traffic to known suspicious port {dport}",
                })

        # ── Rule 2a: TCP Port Scan ────────────────────────────────────────────
        # Only count TCP packets that could genuinely be scan probes.
        # _is_scan_eligible excludes: DNS, inbound service responses (src 443/80),
        # multicast/broadcast, loopback, and link-local.
        # This prevents the router (192.168.1.1:53) and CDN servers from
        # appearing to scan our ephemeral ports.
        if proto == "TCP" and _is_scan_eligible(src, dst, sport, dport, proto):
            self._tcp_dst_ports[src].append((epoch, dport))
            self._tcp_dst_ports[src] = self._evict(self._tcp_dst_ports[src], cutoff)
            tcp_unique = len({p for _, p in self._tcp_dst_ports[src]})
            if tcp_unique >= _PORT_SCAN_THRESH:
                rule = "port_scan"
                if not self._on_cooldown(rule, src, epoch):
                    alerts.append({
                        "rule":     rule,
                        "label":    "Live Port Scan",
                        "severity": "HIGH",
                        "src_ip":   src,
                        "dst_ip":   dst,
                        "dst_port": dport,
                        "protocol": proto,
                        "detail":   f"{tcp_unique} unique TCP ports in {_WINDOW_SECONDS}s",
                    })

        # ── Rule 2b: UDP Burst ────────────────────────────────────────────────
        # UDP port variety is normal for DNS, DHCP, SSDP, and mDNS — label
        # separately at lower severity, and only after noise is filtered.
        if proto == "UDP" and _is_scan_eligible(src, dst, sport, dport, proto):
            self._udp_dst_ports[src].append((epoch, dport))
            self._udp_dst_ports[src] = self._evict(self._udp_dst_ports[src], cutoff)
            udp_unique = len({p for _, p in self._udp_dst_ports[src]})
            if udp_unique >= _UDP_BURST_THRESH:
                rule = "udp_burst"
                if not self._on_cooldown(rule, src, epoch):
                    alerts.append({
                        "rule":     rule,
                        "label":    "UDP Burst",
                        "severity": "MEDIUM",
                        "src_ip":   src,
                        "dst_ip":   dst,
                        "dst_port": dport,
                        "protocol": proto,
                        "detail":   f"{udp_unique} unique UDP ports in {_WINDOW_SECONDS}s",
                    })

        # ── Rule 3: SYN flood (pure SYN, no ACK) ─────────────────────────────
        # Only count SYNs that are scan-eligible — excludes DNS SYNs (your
        # machine querying port 53 generates SYN packets that triggered this
        # rule falsely when just opening browser tabs).
        if (proto == "TCP"
                and (flags & _FLAG_SYN) and not (flags & _FLAG_ACK)
                and _is_scan_eligible(src, dst, sport, dport, proto)):
            count = self._syn_tracker.add(src, epoch)
            if count >= _SYN_FLOOD_THRESH:
                rule = "syn_flood"
                if not self._on_cooldown(rule, src, epoch):
                    alerts.append({
                        "rule":     rule,
                        "label":    "SYN Flood",
                        "severity": "CRITICAL",
                        "src_ip":   src,
                        "dst_ip":   dst,
                        "dst_port": dport,
                        "protocol": proto,
                        "detail":   f"{count} SYN packets in {_SYN_WINDOW_SECONDS}s",
                    })

        # ── Rule 4: Brute Force Attempt (DISABLED) ───────────────────────────────
        # Superseded by the honeypot authentication layer which provides
        # application-layer detection with actual login attempt evidence.
        # Re-enable by setting _BRUTE_FORCE_ENABLED = True at the top of this file.
        #
        # Original heuristic: same src_ip sends many TCP SYNs to the SAME
        # well-known auth port within a short window — the network-level signature
        # of tools like Hydra, Medusa, and ncrack.  Kept here as documentation
        # and for future use cases where the honeypot layer is not deployed.
        if (_BRUTE_FORCE_ENABLED
                and proto == "TCP"
                and (flags & _FLAG_SYN) and not (flags & _FLAG_ACK)
                and dport in _BRUTE_FORCE_PORTS
                and not _is_noise_traffic(src, dst, sport, dport, proto)):
            bf_key = (src, dport)   # track per (attacker IP, targeted service port)
            count  = self._brute_tracker.add(bf_key, epoch)
            if count >= _BRUTE_FORCE_THRESH:
                rule = "brute_force"
                if not self._on_cooldown(rule, src, epoch):
                    service = {22: "SSH", 21: "FTP", 23: "Telnet", 3389: "RDP"}.get(dport, str(dport))
                    alerts.append({
                        "rule":     rule,
                        "label":    "Brute Force Attempt",
                        "severity": "HIGH",
                        "src_ip":   src,
                        "dst_ip":   dst,
                        "dst_port": dport,
                        "protocol": proto,
                        "detail":   f"{count} {service} SYN attempts in {_BRUTE_FORCE_WINDOW}s",
                    })

        # ── Rule 5: ICMP flood ────────────────────────────────────────────────
        if proto == "ICMP":
            count = self._icmp_tracker.add(src, epoch)
            if count >= _ICMP_FLOOD_THRESH:
                rule = "icmp_flood"
                if not self._on_cooldown(rule, src, epoch):
                    alerts.append({
                        "rule":     rule,
                        "label":    "ICMP Flood",
                        "severity": "HIGH",
                        "src_ip":   src,
                        "dst_ip":   dst,
                        "dst_port": 0,
                        "protocol": proto,
                        "detail":   f"{count} ICMP packets in {_WINDOW_SECONDS}s",
                    })

        # ── Rule 6: Connection burst (total packets from src in window) ───────
        # Only count packets that pass the noise filter — multicast/broadcast
        # sources, DNS responses, and CDN return traffic are excluded so that
        # normal browsing (Google, YouTube, etc.) does not trigger this rule.
        if _is_scan_eligible(src, dst, sport, dport, proto):
            count = self._burst_tracker.add(src, epoch)
            if count >= _CONN_BURST_THRESH:
                rule = "conn_burst"
                if not self._on_cooldown(rule, src, epoch):
                    alerts.append({
                        "rule":     rule,
                        "label":    "Connection Burst",
                        "severity": "LOW",
                        "src_ip":   src,
                        "dst_ip":   dst,
                        "dst_port": dport,
                        "protocol": proto,
                        "detail":   f"{count} packets in {_WINDOW_SECONDS}s",
                    })

        return alerts


# ── Shared session state ──────────────────────────────────────────────────────

@dataclass
class _MonitorState:
    running:       bool            = False
    interface:     str             = ""
    started_at:    str             = ""
    packets_seen:  int             = 0
    alerts_fired:  int             = 0
    recent_events: list[dict]      = field(default_factory=list)
    error:         Optional[str]   = None
    anomaly_score: float           = 0.0


_MAX_RECENT_EVENTS = 100   # cap the in-memory event list

_state      = _MonitorState()
_state_lock = threading.Lock()
_stop_event = threading.Event()


def _update_state(**kwargs) -> None:
    with _state_lock:
        for k, v in kwargs.items():
            setattr(_state, k, v)


def _append_event(event: dict) -> None:
    with _state_lock:
        _state.recent_events.insert(0, event)
        if len(_state.recent_events) > _MAX_RECENT_EVENTS:
            _state.recent_events.pop()
        _state.alerts_fired += 1


# ── Worker threads ────────────────────────────────────────────────────────────

def _producer(tshark_path: str, interface: str, pkt_queue: queue.Queue) -> None:
    """
    Reads tshark -T fields stdout line by line and pushes parsed packet dicts
    to pkt_queue. Sends None as sentinel when done or on error.
    """
    cmd = [
        tshark_path,
        "-i", interface,
        "-T", "fields",
        "-l",                # line-buffered output — essential for streaming
        "-E", "separator=\t",
        "-E", "header=n",
        "-E", "quote=n",
    ] + _FIELD_ARGS

    logger.info(f"[live] tshark cmd: {' '.join(cmd)}")

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,          # line-buffered
        )
    except FileNotFoundError:
        _update_state(running=False, error=f"tshark not found at: {tshark_path}")
        pkt_queue.put(None)
        return
    except Exception as exc:
        _update_state(running=False, error=f"tshark launch failed: {exc}")
        pkt_queue.put(None)
        return

    try:
        for line in proc.stdout:
            if _stop_event.is_set():
                break
            line = line.rstrip("\n")
            if not line:
                continue
            pkt = _parse_line(line)
            if pkt:
                try:
                    pkt_queue.put_nowait(pkt)
                except queue.Full:
                    pass   # consumer is behind — drop packet rather than block tshark
    except Exception as exc:
        logger.error(f"[live/producer] read error: {exc}")
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            pass
        pkt_queue.put(None)
        logger.info("[live/producer] exited.")


_SEVERITY_UPGRADE = {"LOW": "MEDIUM", "MEDIUM": "HIGH"}


def _consumer(pkt_queue: queue.Queue) -> None:
    """
    Pulls parsed packet dicts from the queue, evaluates rules, and saves alerts.
    Imports alert_service lazily to avoid circular imports at module load time.

    Four detection tiers:
      RULE          — rule fired, IF score below hybrid threshold (< 0.52)
      HYBRID        — rule fired AND IF score >= 0.52 (severity upgraded)
      AI-CLASSIFIED — IF anomaly confirmed + RF classifier matched (conf >= 0.70)
      AI-UNKNOWN    — IF anomaly confirmed, RF below confidence threshold
    """
    import time as _time
    from backend.services.alert_service import save_alert
    from backend.models.alert import Alert
    from backend.utils.database import SessionLocal
    from backend.services import anomaly_service

    engine = _RuleEngine()
    db     = SessionLocal()

    _SCORE_INTERVAL      = 10.0
    _last_score_time     = _time.time()
    _last_rule_alert_time = 0.0   # epoch of last rule-based alert (gate 4 for AI-BEHAVIORAL)

    anomaly_service.reset_for_new_session()

    try:
        while True:
            try:
                pkt = pkt_queue.get(timeout=1.0)
            except queue.Empty:
                if _stop_event.is_set():
                    break
                continue

            if pkt is None:
                break

            anomaly_service.record_packet(pkt)

            with _state_lock:
                _state.packets_seen += 1

            now = _time.time()
            if now - _last_score_time >= _SCORE_INTERVAL:
                score = anomaly_service.compute_and_score()
                with _state_lock:
                    _state.anomaly_score = score

                # Check AI-BEHAVIORAL alert (all 5 gates evaluated inside)
                features  = anomaly_service.get_feature_vector()
                pkt_count = anomaly_service.get_window_pkt_count()
                should_fire, reason, _ = anomaly_service.check_behavioral_alert(
                    score, features, pkt_count, _last_rule_alert_time
                )
                if should_fire:
                    # Stage 2: classify the confirmed anomaly.
                    # classify_behavioral_alert() answers "what type?", not "is it real?".
                    # That question was already answered by check_behavioral_alert() above.
                    cl_label, cl_conf, cl_expl = anomaly_service.classify_behavioral_alert(
                        features, score
                    )
                    if not cl_label:
                        # BENIGN suppression: RF contradicts IF with high confidence.
                        # The anomaly score crossed the gate threshold but the RF
                        # classifier is confident this is normal traffic.  Skip alert.
                        logger.info(
                            f"[live] behavioral alert suppressed (RF: BENIGN | "
                            f"IF score={score:.3f}) — {cl_expl}"
                        )
                    else:
                        # AI-CLASSIFIED: pattern matched with confidence
                        # AI-UNKNOWN:    anomaly confirmed but no pattern exceeds threshold
                        b_detection_type = "AI-CLASSIFIED" if cl_conf > 0.0 else "AI-UNKNOWN"

                        ts = datetime.now(timezone.utc).isoformat()
                        b_alert = Alert(
                            flow_id        = str(uuid.uuid4()),
                            label          = cl_label,
                            severity       = "HIGH",
                            confidence     = score,
                            src_ip         = "0.0.0.0",
                            dst_ip         = "0.0.0.0",
                            src_port       = 0,
                            dst_port       = 0,
                            protocol       = "MULTI",
                            timestamp      = ts,
                            source         = "live",
                            detection_type = b_detection_type,
                            detail         = cl_expl,
                        )
                        try:
                            save_alert(db, b_alert)
                        except Exception as exc:
                            logger.error(f"[live/consumer] behavioral alert save failed: {exc}")
                        b_event = {
                            "label":          cl_label,
                            "severity":       "HIGH",
                            "src_ip":         "0.0.0.0",
                            "dst_ip":         "0.0.0.0",
                            "dst_port":       0,
                            "protocol":       "MULTI",
                            "detail":         cl_expl,
                            "timestamp":      ts,
                            "confidence":     score,
                            "detection_type": b_detection_type,
                        }
                        _append_event(b_event)
                        logger.info(
                            f"[live] {b_detection_type} | {cl_label}"
                            f" | conf={cl_conf:.2f} | {cl_expl}"
                        )

                _last_score_time = now

            fired = engine.evaluate(pkt)

            for alert_data in fired:
                ts            = datetime.fromtimestamp(pkt["epoch"]).isoformat()
                current_score = anomaly_service.get_anomaly_score()
                model_loaded  = anomaly_service.is_model_loaded()

                _last_rule_alert_time = _time.time()

                # Classify: HYBRID if model is loaded and score is elevated
                # Threshold 0.52 is calibrated to actual IF output range (normal≈0.47,
                # attack≈0.57) — see evaluation_output/if_score_distributions.png
                if model_loaded and current_score >= 0.52:
                    detection_type = "HYBRID"
                    severity       = _SEVERITY_UPGRADE.get(
                        alert_data["severity"], alert_data["severity"]
                    )
                    detail = (
                        alert_data.get("detail", "")
                        + f"  |  AI score {current_score:.0%}"
                    )
                else:
                    detection_type = "RULE"
                    severity       = alert_data["severity"]
                    detail         = alert_data.get("detail", "")

                alert = Alert(
                    flow_id        = str(uuid.uuid4()),
                    label          = alert_data["label"],
                    severity       = severity,
                    confidence     = current_score,
                    src_ip         = alert_data["src_ip"],
                    dst_ip         = alert_data["dst_ip"],
                    src_port       = pkt.get("src_port", 0),
                    dst_port       = alert_data["dst_port"],
                    protocol       = alert_data["protocol"],
                    timestamp      = ts,
                    source         = "live",
                    detection_type = detection_type,
                    detail         = detail,
                )

                try:
                    save_alert(db, alert)
                except Exception as exc:
                    logger.error(f"[live/consumer] save_alert failed: {exc}")

                event = {
                    "label":          alert_data["label"],
                    "severity":       severity,
                    "src_ip":         alert_data["src_ip"],
                    "dst_ip":         alert_data["dst_ip"],
                    "dst_port":       alert_data["dst_port"],
                    "protocol":       alert_data["protocol"],
                    "detail":         detail,
                    "timestamp":      ts,
                    "confidence":     current_score,
                    "detection_type": detection_type,
                }
                _append_event(event)
                logger.info(
                    f"[live] ALERT {alert_data['label']} | "
                    f"{alert_data['src_ip']} -> {alert_data['dst_ip']}:{alert_data['dst_port']} | "
                    f"type={detection_type} score={current_score:.3f}"
                )

    finally:
        db.close()
        _update_state(running=False)
        logger.info("[live/consumer] exited.")


def _monitor_worker(interface: str) -> None:
    """Top-level worker: starts producer + consumer threads, waits for both."""
    try:
        tshark = _find_tshark()
    except RuntimeError as exc:
        _update_state(running=False, error=str(exc))
        return

    pkt_queue: queue.Queue = queue.Queue(maxsize=5000)

    producer_thread = threading.Thread(
        target=_producer,
        args=(tshark, interface, pkt_queue),
        daemon=True,
        name="ids-live-producer",
    )
    consumer_thread = threading.Thread(
        target=_consumer,
        args=(pkt_queue,),
        daemon=True,
        name="ids-live-consumer",
    )

    producer_thread.start()
    consumer_thread.start()

    producer_thread.join()
    consumer_thread.join()

    logger.info("[live] Monitor session ended.")


# ── Public API ────────────────────────────────────────────────────────────────

def start_monitor(interface: str = "Wi-Fi") -> dict:
    """
    Start the live rule-based monitoring session in a background thread.
    Returns immediately — poll get_monitor_status() for updates.
    """
    with _state_lock:
        if _state.running:
            return {"status": "already_running", "interface": _state.interface}

        _state.running       = True
        _state.interface     = interface
        _state.started_at    = datetime.now().isoformat()
        _state.packets_seen  = 0
        _state.alerts_fired  = 0
        _state.recent_events = []
        _state.error         = None
        _state.anomaly_score = 0.0

    _stop_event.clear()

    threading.Thread(
        target=_monitor_worker,
        args=(interface,),
        daemon=True,
        name="ids-live-monitor",
    ).start()

    logger.info(f"[live] Monitor started on interface: {interface!r}")
    return {
        "status":     "started",
        "interface":  interface,
        "started_at": _state.started_at,
    }


def stop_monitor() -> dict:
    """Signal the live monitor to stop after the current packet is processed."""
    with _state_lock:
        if not _state.running:
            return {"status": "not_running"}

    _stop_event.set()
    logger.info("[live] Stop requested.")
    return {"status": "stopping"}


def get_monitor_status() -> dict:
    """Return the current live monitor state for frontend polling."""
    from backend.services import realtime_classifier_service as _rt_clf
    with _state_lock:
        return {
            "running":          _state.running,
            "interface":        _state.interface,
            "started_at":       _state.started_at,
            "packets_seen":     _state.packets_seen,
            "alerts_fired":     _state.alerts_fired,
            "recent_events":    list(_state.recent_events),
            "error":            _state.error,
            "anomaly_score":    _state.anomaly_score,
            "rf_model_loaded":  _rt_clf.is_model_loaded(),
        }
