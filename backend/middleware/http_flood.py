# backend/middleware/http_flood.py
# ─────────────────────────────────────────────────────────────────────────────
# HTTP Flood Detection Middleware
#
# Layer-7 DoS / application-layer request flood detector.
#
# Design:
#   Starlette BaseHTTPMiddleware attached to the FastAPI app in main.py.
#   Tracks per-source-IP request counts inside a sliding time window using
#   the same _WindowTracker pattern as live_monitor_service.py.
#   When the threshold is exceeded, one HIGH alert is persisted via the shared
#   save_alert() pipeline and a cooldown suppresses duplicates.
#
# Parameters:
#   THRESHOLD  = 100 requests from the same IP within WINDOW_SECONDS
#   WINDOW     = 10 seconds
#   COOLDOWN   = 60 seconds (suppress repeated alerts for the same attacker IP)
#
# Alert shape:
#   label     = "HTTP Flood"
#   severity  = "HIGH"
#   source    = "live"        ← same as live rule-engine alerts
#   src_ip    = attacker IP
#   dst_ip    = "backend"
#   dst_port  = 8000
#   protocol  = "HTTP"
#
# Excluded paths:
#   /stats/health is excluded from counting — it is polled every 8 s by the
#   frontend health-check and would trigger false positives on normal app use.
#
# Thread safety:
#   All shared state is protected by a single threading.Lock.
#   The alert is fired in a daemon thread so the HTTP response is not delayed.
# ─────────────────────────────────────────────────────────────────────────────
import threading
import uuid
from collections import defaultdict
from datetime import datetime, timezone

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from backend.utils.logger import get_logger

logger = get_logger(__name__)

# ── Detection parameters ──────────────────────────────────────────────────────

_THRESHOLD       = 100   # requests from same IP within window → alert
_WINDOW_SECONDS  = 10    # sliding look-back window (seconds)
_COOLDOWN_SECONDS = 60   # suppress duplicate alerts per attacker IP (seconds)

# Paths that are excluded from request counting.
# The frontend health-check polls /stats/health every 8 s — counting it would
# produce false positives during normal operation.
# "/" is intentionally NOT excluded — flooding the root is a realistic demo
# attack vector and must trigger the alert.
_EXCLUDED_PATHS = {"/stats/health"}

# ── In-process state (module-level singletons) ────────────────────────────────

_lock     = threading.Lock()
_buckets: dict[str, list[float]] = defaultdict(list)   # IP → [epoch, ...]
_cooldown: dict[str, float]      = {}                   # IP → last_alert_epoch


# ── Sliding window helper ─────────────────────────────────────────────────────

def _record(ip: str, epoch: float) -> int:
    """Record a request, evict stale entries, return current count in window."""
    cutoff = epoch - _WINDOW_SECONDS
    with _lock:
        bucket = _buckets[ip]
        bucket.append(epoch)
        _buckets[ip] = [t for t in bucket if t >= cutoff]
        return len(_buckets[ip])


def _on_cooldown(ip: str, epoch: float) -> bool:
    """Return True if this IP is still within the alert suppression window."""
    with _lock:
        last = _cooldown.get(ip, 0.0)
        if epoch - last < _COOLDOWN_SECONDS:
            return True
        _cooldown[ip] = epoch
        return False


# ── Alert persistence (runs in daemon thread, never blocks responses) ─────────

def _fire_alert(src_ip: str, count: int, epoch: float) -> None:
    from backend.services.alert_service import save_alert
    from backend.models.alert import Alert
    from backend.utils.database import SessionLocal

    ts = datetime.fromtimestamp(epoch).isoformat()

    alert = Alert(
        flow_id   = str(uuid.uuid4()),
        label     = "HTTP Flood",
        severity  = "HIGH",
        confidence= None,
        src_ip    = src_ip,
        dst_ip    = "backend",
        src_port  = 0,
        dst_port  = 8000,
        protocol  = "HTTP",
        timestamp = ts,
        source    = "live",
    )

    db = SessionLocal()
    try:
        save_alert(db, alert)
        logger.warning(
            f"[http_flood] HTTP FLOOD | {src_ip} | "
            f"{count} requests in {_WINDOW_SECONDS}s"
        )
        # Push into the live monitor's in-memory recent_events list so the
        # Real-Time screen shows HTTP Flood alongside tshark-based alerts.
        # Import is guarded — if the monitor is not running the call is a no-op.
        try:
            from backend.services.live_monitor_service import _append_event
            _append_event({
                "label":     "HTTP Flood",
                "severity":  "HIGH",
                "src_ip":    src_ip,
                "dst_ip":    "backend",
                "dst_port":  8000,
                "protocol":  "HTTP",
                "detail":    f"{count} requests in {_WINDOW_SECONDS}s",
                "timestamp": ts,
            })
        except Exception:
            pass  # never fail the alert path because of the UI feed
    except Exception as exc:
        logger.error(f"[http_flood] save_alert failed: {exc}")
    finally:
        db.close()


# ── Middleware class ───────────────────────────────────────────────────────────

class HTTPFloodMiddleware(BaseHTTPMiddleware):
    """
    Counts inbound HTTP requests per source IP.
    Fires an HTTP Flood alert when the threshold is exceeded within the window.
    """

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        if path not in _EXCLUDED_PATHS:
            # Prefer X-Forwarded-For for clients behind a proxy; fall back to
            # the direct connection host (covers the demo LAN scenario).
            forwarded = request.headers.get("x-forwarded-for")
            src_ip = forwarded.split(",")[0].strip() if forwarded else request.client.host

            epoch = datetime.now(timezone.utc).timestamp()
            count = _record(src_ip, epoch)

            if count >= _THRESHOLD and not _on_cooldown(src_ip, epoch):
                threading.Thread(
                    target=_fire_alert,
                    args=(src_ip, count, epoch),
                    daemon=True,
                ).start()

        return await call_next(request)
