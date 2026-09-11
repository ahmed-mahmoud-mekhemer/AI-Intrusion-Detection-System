# backend/services/honeypot_service.py
# ─────────────────────────────────────────────────────────────────────────────
# Low-Interaction Authentication Honeypot Layer
#
# Academic framing:
#   A low-interaction authentication honeypot that emulates SSH, Telnet, and
#   FTP service banners to detect brute-force credential-stuffing attacks at
#   the application layer, complementing the network-layer rule-based monitor.
#
# Architecture:
#   - One TCP listener thread per active service (SSH / Telnet / FTP)
#   - One short-lived handler thread per inbound connection
#   - Sliding-window attempt counter per (src_ip, service) key
#   - Cooldown dict to suppress alert spam (same pattern as live_monitor)
#   - Alerts persisted via existing save_alert() — no new DB table
#   - Alerts stored with source="honeypot" for easy filtering
#
# Safety constraints (low-interaction design):
#   - No real authentication backend
#   - No shell access granted under any circumstances
#   - Received input is NEVER executed
#   - Passwords are masked before logging or storage
#   - Binds to 0.0.0.0 by default (LAN-visible) — change to 127.0.0.1 for
#     localhost-only operation
#   - All listener threads are daemon threads — they die with the process
#
# Detection heuristic:
#   Same source IP performs ≥ ATTEMPT_THRESHOLD failed logins against a
#   honeypot service within WINDOW_SECONDS → Brute Force Attack alert.
#   Keyed per (src_ip, service_name) so SSH and FTP attacks from the same
#   host produce independent alerts.
# ─────────────────────────────────────────────────────────────────────────────
import socket
import threading
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from backend.utils.logger import get_logger

logger = get_logger(__name__)

# ── Detection parameters ──────────────────────────────────────────────────────

ATTEMPT_THRESHOLD = 5    # failed logins within the window → alert
WINDOW_SECONDS    = 15   # sliding-window look-back (seconds)
COOLDOWN_SECONDS  = 60   # suppress duplicate alerts per (src_ip, service)

# ── Fake service definitions ──────────────────────────────────────────────────
#
# Each entry describes one honeypot listener.
# Fields:
#   name    — human-readable label used in alerts and logs
#   port    — TCP port to bind
#   handler — callable(conn, addr, service_def) that drives the fake session
#
# To add a new fake service: define a handler function and append an entry.

def _handle_ssh(conn: socket.socket, addr: tuple, svc: dict,
                on_attempt) -> None:
    """
    Simulates an SSH-2.0 login prompt.
    Calls on_attempt(username) immediately after each rejection.
    Passwords are never stored or passed to the callback.

    Protocol sketch:
      ← SSH-2.0 banner
      → (client SSH handshake bytes — ignored, we just read lines)
      ← "login: "
      → username
      ← "Password: "
      → password (discarded)
      ← "Permission denied, please try again.\n"
      (repeat up to _MAX_ATTEMPTS_PER_CONN times)
    """
    try:
        conn.settimeout(10)
        # Real SSH clients send a binary handshake; telnet/netcat clients send text.
        # Sending the banner as a text line works for both in a demo context.
        conn.sendall(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
        for _ in range(_MAX_ATTEMPTS_PER_CONN):
            conn.sendall(b"login: ")
            username = _recv_line(conn)
            if username is None:
                break
            conn.sendall(b"Password: ")
            _recv_line(conn)   # read password — value discarded immediately
            conn.sendall(b"Permission denied, please try again.\r\n")
            on_attempt(username[:64])   # record immediately after rejection
    except (OSError, TimeoutError):
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def _handle_telnet(conn: socket.socket, addr: tuple, svc: dict,
                   on_attempt) -> None:
    """Simulates a minimal Telnet login banner.
    Calls on_attempt(username) immediately after each rejection."""
    try:
        conn.settimeout(10)
        conn.sendall(b"\r\nUbuntu 22.04.3 LTS\r\n\r\n")
        for _ in range(_MAX_ATTEMPTS_PER_CONN):
            conn.sendall(b"login: ")
            username = _recv_line(conn)
            if username is None:
                break
            conn.sendall(b"Password: ")
            _recv_line(conn)
            conn.sendall(b"Login incorrect\r\n\r\n")
            on_attempt(username[:64])   # record immediately after rejection
    except (OSError, TimeoutError):
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def _handle_ftp(conn: socket.socket, addr: tuple, svc: dict,
                on_attempt) -> None:
    """
    Simulates a minimal FTP server greeting and USER/PASS exchange.
    Accepts the RFC-959 USER and PASS commands; always rejects with 530.
    Calls on_attempt(username) immediately after each 530 rejection.
    """
    try:
        conn.settimeout(10)
        conn.sendall(b"220 FTP server ready.\r\n")
        for _ in range(_MAX_ATTEMPTS_PER_CONN):
            line = _recv_line(conn)
            if line is None:
                break
            upper = line.upper()
            if upper.startswith("USER"):
                username = line[5:].strip()[:64]
                conn.sendall(b"331 Password required for " + username.encode() + b".\r\n")
                pass_line = _recv_line(conn)   # PASS <password> — value discarded
                if pass_line is None:
                    break
                conn.sendall(b"530 Login incorrect.\r\n")
                on_attempt(username)   # record immediately after 530 rejection
            elif upper.startswith("QUIT"):
                conn.sendall(b"221 Goodbye.\r\n")
                break
            else:
                conn.sendall(b"530 Please login with USER and PASS.\r\n")
    except (OSError, TimeoutError):
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


# Maximum login attempts we will service from a single TCP connection.
# Prevents a single persistent connection from monopolising a handler thread.
_MAX_ATTEMPTS_PER_CONN = 10

# Service registry — edit only here to add/remove services.
_SERVICE_DEFS: list[dict] = [
    {"name": "SSH",    "port": 2222, "handler": _handle_ssh},
    {"name": "Telnet", "port": 2323, "handler": _handle_telnet},
    {"name": "FTP",    "port": 2121, "handler": _handle_ftp},
]

# ── Shared state ──────────────────────────────────────────────────────────────

@dataclass
class _HoneypotState:
    running:        bool             = False
    active_services: list[str]       = field(default_factory=list)
    started_at:     str              = ""
    total_attempts: int              = 0
    total_alerts:   int              = 0
    recent_events:  list[dict]       = field(default_factory=list)
    error:          Optional[str]    = None


_MAX_RECENT_EVENTS = 100

_state      = _HoneypotState()
_state_lock = threading.Lock()
_stop_event = threading.Event()

# Attempt tracking: (src_ip, service_name) → list of epoch floats
_attempts: dict[tuple[str, str], list[float]] = defaultdict(list)
_attempts_lock = threading.Lock()

# Cooldown: (src_ip, service_name) → last_alert_epoch
_cooldown: dict[tuple[str, str], float] = {}
_cooldown_lock = threading.Lock()

# ── Helpers ───────────────────────────────────────────────────────────────────

def _recv_line(conn: socket.socket, max_bytes: int = 256) -> Optional[str]:
    """
    Read bytes from the socket until \\n or max_bytes reached.
    Returns the decoded, stripped string or None on EOF/error.
    """
    buf = b""
    try:
        while len(buf) < max_bytes:
            chunk = conn.recv(1)
            if not chunk:
                return None
            buf += chunk
            if buf.endswith(b"\n"):
                break
    except (OSError, TimeoutError):
        return None
    return buf.decode("utf-8", errors="replace").strip()


def _record_attempt(src_ip: str, service: str, username: str, epoch: float) -> int:
    """
    Slide the window for (src_ip, service), record the new attempt,
    and return the current count within the window.
    """
    key = (src_ip, service)
    cutoff = epoch - WINDOW_SECONDS
    with _attempts_lock:
        bucket = _attempts[key]
        bucket.append(epoch)
        _attempts[key] = [t for t in bucket if t >= cutoff]
        return len(_attempts[key])


def _on_cooldown(src_ip: str, service: str, epoch: float) -> bool:
    key = (src_ip, service)
    with _cooldown_lock:
        last = _cooldown.get(key, 0.0)
        if epoch - last < COOLDOWN_SECONDS:
            return True
        _cooldown[key] = epoch
        return False


def _append_event(event: dict) -> None:
    with _state_lock:
        _state.recent_events.insert(0, event)
        if len(_state.recent_events) > _MAX_RECENT_EVENTS:
            _state.recent_events.pop()
        _state.total_alerts += 1


def _fire_alert(src_ip: str, service: str, dst_port: int,
                username: str, count: int, epoch: float) -> None:
    """Persist a Brute Force Attack alert using the existing save_alert()."""
    # Lazy imports avoid circular dependency at module load time
    from backend.services.alert_service import save_alert
    from backend.models.alert import Alert
    from backend.utils.database import SessionLocal

    ts    = datetime.fromtimestamp(epoch).isoformat()
    label = f"Brute Force Attack ({service})"

    alert = Alert(
        flow_id        = str(uuid.uuid4()),
        label          = label,
        severity       = "HIGH",
        confidence     = None,
        src_ip         = src_ip,
        dst_ip         = "honeypot",
        src_port       = 0,
        dst_port       = dst_port,
        protocol       = "TCP",
        timestamp      = ts,
        source         = "honeypot",
        detection_type = "TRAP",
    )

    db = SessionLocal()
    try:
        save_alert(db, alert)
    except Exception as exc:
        logger.error(f"[honeypot] save_alert failed: {exc}")
    finally:
        db.close()

    event = {
        "service":   service,
        "src_ip":    src_ip,
        "username":  username,           # last observed username (not a password)
        "attempts":  count,
        "dst_port":  dst_port,
        "timestamp": ts,
    }
    _append_event(event)

    # Bridge into the live monitor's shared recent_events feed so the
    # Real-Time screen shows honeypot alerts alongside tshark rule alerts.
    # Shape must match what _render_live_row() in realtime_monitor.py reads.
    try:
        from backend.services.live_monitor_service import _append_event as _live_append
        _live_append({
            "label":          label,
            "severity":       "HIGH",
            "src_ip":         src_ip,
            "dst_ip":         "honeypot",
            "dst_port":       dst_port,
            "protocol":       "TCP",
            "detail":         f"{count} failed {service} logins in {WINDOW_SECONDS}s (user: {username})",
            "timestamp":      ts,
            "detection_type": "TRAP",
        })
    except Exception:
        pass  # never block the alert path for a UI feed failure

    logger.warning(
        f"[honeypot] BRUTE FORCE {service} | {src_ip} | "
        f"user='{username}' | {count} attempts in {WINDOW_SECONDS}s"
    )


# ── Per-connection handler ────────────────────────────────────────────────────

def _connection_handler(conn: socket.socket, addr: tuple, svc: dict) -> None:
    """
    Runs in a short-lived daemon thread per inbound connection.
    Defines a per-attempt callback and passes it into the protocol handler
    so each failed login is evaluated for threshold immediately.
    """
    src_ip  = addr[0]
    service = svc["name"]
    port    = svc["port"]

    with _state_lock:
        _state.total_attempts += 1

    logger.info(f"[honeypot/{service}] connection from {src_ip}:{addr[1]}")

    def _on_failed_attempt(username: str) -> None:
        """Called by the protocol handler immediately after each rejection."""
        epoch = datetime.now(timezone.utc).timestamp()
        count = _record_attempt(src_ip, service, username, epoch)
        if count >= ATTEMPT_THRESHOLD and not _on_cooldown(src_ip, service, epoch):
            _fire_alert(src_ip, service, port, username, count, epoch)

    svc["handler"](conn, addr, svc, _on_failed_attempt)


# ── TCP listener thread ───────────────────────────────────────────────────────

def _listener(svc: dict) -> None:
    """
    Runs in a daemon thread.  Accepts connections and spawns a handler
    thread for each one.  Exits cleanly when _stop_event is set.
    """
    service = svc["name"]
    port    = svc["port"]

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(("0.0.0.0", port))
        server.listen(16)
        server.settimeout(1.0)   # allows the stop_event check loop to tick
        logger.info(f"[honeypot/{service}] listening on 0.0.0.0:{port}")
    except OSError as exc:
        logger.error(f"[honeypot/{service}] bind failed on port {port}: {exc}")
        _update_state(error=f"{service} bind failed: {exc}")
        return

    while not _stop_event.is_set():
        try:
            conn, addr = server.accept()
        except socket.timeout:
            continue
        except OSError:
            break

        t = threading.Thread(
            target=_connection_handler,
            args=(conn, addr, svc),
            daemon=True,
            name=f"honeypot-{service}-{addr[0]}",
        )
        t.start()

    server.close()
    logger.info(f"[honeypot/{service}] listener stopped.")


# ── State helpers ─────────────────────────────────────────────────────────────

def _update_state(**kwargs) -> None:
    with _state_lock:
        for k, v in kwargs.items():
            setattr(_state, k, v)


# ── Public API ────────────────────────────────────────────────────────────────

def start_honeypot(services: Optional[list[str]] = None) -> dict:
    """
    Start honeypot listener threads for the requested services.

    services — list of service names to enable, e.g. ["SSH", "FTP"].
               Defaults to all defined services if None.

    Returns immediately — the listeners run in daemon threads.
    """
    with _state_lock:
        if _state.running:
            return {
                "status":   "already_running",
                "services": _state.active_services,
            }

    # Resolve which service definitions to start
    requested = {s.upper() for s in services} if services else None
    to_start  = [
        svc for svc in _SERVICE_DEFS
        if requested is None or svc["name"].upper() in requested
    ]

    if not to_start:
        return {"status": "error", "detail": "No matching services found."}

    _stop_event.clear()
    with _attempts_lock:
        _attempts.clear()
    with _cooldown_lock:
        _cooldown.clear()

    active_names = []
    errors       = []
    for svc in to_start:
        t = threading.Thread(
            target=_listener,
            args=(svc,),
            daemon=True,
            name=f"honeypot-listener-{svc['name']}",
        )
        t.start()
        active_names.append(svc["name"])

    started_at = datetime.utcnow().isoformat()
    with _state_lock:
        _state.running         = True
        _state.active_services = active_names
        _state.started_at      = started_at
        _state.total_attempts  = 0
        _state.total_alerts    = 0
        _state.recent_events   = []
        _state.error           = None

    logger.info(f"[honeypot] started services: {active_names}")
    return {
        "status":     "started",
        "services":   active_names,
        "started_at": started_at,
        "ports":      {svc["name"]: svc["port"] for svc in to_start},
    }


def stop_honeypot() -> dict:
    """Signal all honeypot listeners to shut down gracefully."""
    with _state_lock:
        if not _state.running:
            return {"status": "not_running"}

    _stop_event.set()

    with _state_lock:
        _state.running = False

    logger.info("[honeypot] stop requested.")
    return {"status": "stopping"}


def get_honeypot_status() -> dict:
    """Return current honeypot state for frontend polling."""
    with _state_lock:
        return {
            "running":         _state.running,
            "active_services": list(_state.active_services),
            "started_at":      _state.started_at,
            "total_attempts":  _state.total_attempts,
            "total_alerts":    _state.total_alerts,
            "recent_events":   list(_state.recent_events),
            "error":           _state.error,
            "config": {
                "threshold":        ATTEMPT_THRESHOLD,
                "window_seconds":   WINDOW_SECONDS,
                "cooldown_seconds": COOLDOWN_SECONDS,
            },
            "available_services": [
                {"name": s["name"], "port": s["port"]} for s in _SERVICE_DEFS
            ],
        }
