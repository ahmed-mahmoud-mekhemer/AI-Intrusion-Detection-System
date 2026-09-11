# backend/routers/honeypot.py
# ─────────────────────────────────────────────────────────────────────────────
# Router for the Authentication Honeypot Layer.
#
# Endpoints:
#   POST /honeypot/start   — start one or more fake service listeners
#   POST /honeypot/stop    — gracefully shut down all listeners
#   GET  /honeypot/status  — poll for current state and recent events
#
# Kept completely separate from /live/* and /realtime/* so neither existing
# layer can be affected by honeypot lifecycle operations.
# ─────────────────────────────────────────────────────────────────────────────
from typing import Optional

from fastapi import APIRouter

from backend.services.honeypot_service import (
    start_honeypot,
    stop_honeypot,
    get_honeypot_status,
)

router = APIRouter(prefix="/honeypot", tags=["Honeypot"])


@router.post("/start")
def start(services: Optional[list[str]] = None):
    """
    Start the authentication honeypot.

    Parameters:
        services — optional list of service names to activate, e.g.
                   ["SSH", "FTP", "Telnet"].  Omit to start all services.

    The listener(s) run in background daemon threads and return immediately.
    Use GET /honeypot/status to monitor activity.

    Available services and their default ports:
        SSH     → 2222
        Telnet  → 2323
        FTP     → 2121
    """
    return start_honeypot(services=services)


@router.post("/stop")
def stop():
    """
    Signal all honeypot listeners to stop.

    In-flight connections are handled to completion; no new connections
    are accepted after this call.
    """
    return stop_honeypot()


@router.get("/status")
def status():
    """
    Return the current honeypot state.

    Response fields:
        running          (bool)   — whether any listener is active
        active_services  (list)   — names of running service listeners
        started_at       (str)    — ISO timestamp of last start
        total_attempts   (int)    — total connections received this session
        total_alerts     (int)    — total brute-force alerts fired this session
        recent_events    (list)   — last ≤100 alert events (newest first)
        error            (str|null)
        config           (dict)   — active threshold/window/cooldown values
        available_services (list) — all configured services with their ports
    """
    return get_honeypot_status()
