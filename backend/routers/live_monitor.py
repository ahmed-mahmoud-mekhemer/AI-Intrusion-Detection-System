# backend/routers/live_monitor.py
# ─────────────────────────────────────────────────────────────────────────────
# Router for the Lightweight Live Rule-Based Monitoring Layer.
#
# Endpoints:
#   POST /live/start   — start live tshark stream + rule engine
#   POST /live/stop    — signal graceful stop
#   GET  /live/status  — poll for current state, packet count, recent alerts
#
# Intentionally separate from /realtime/* so the existing deep ML layer
# is not affected in any way.
# ─────────────────────────────────────────────────────────────────────────────
from fastapi import APIRouter

from backend.services.live_monitor_service import (
    start_monitor,
    stop_monitor,
    get_monitor_status,
)

router = APIRouter(prefix="/live", tags=["Live Monitor"])


@router.post("/start")
def start_live_monitor(interface: str = "Wi-Fi"):
    """
    Start the live rule-based packet monitoring session.

    Launches a background tshark stream reader + rule engine.
    Returns immediately — poll /live/status for updates.

    Parameters:
        interface: Network interface name (e.g. "Wi-Fi", "Ethernet").
                   Use GET /realtime/interfaces to list available names.
    """
    return start_monitor(interface=interface)


@router.post("/stop")
def stop_live_monitor():
    """
    Signal the live monitor to stop.

    Stop is near-immediate — the rule engine finishes the current packet
    and the tshark process is terminated.
    """
    return stop_monitor()


@router.get("/status")
def live_monitor_status():
    """
    Return the current live monitoring state.

    Frontend polls this every ~2 seconds.

    Response fields:
        running       (bool)   — whether capture is active
        interface     (str)    — active network interface
        started_at    (str)    — ISO timestamp of session start
        packets_seen  (int)    — total packets processed by rule engine
        alerts_fired  (int)    — total rule alerts saved to DB this session
        recent_events (list)   — last ≤100 alert events (newest first)
        error         (str|null) — error message if session failed
    """
    return get_monitor_status()
