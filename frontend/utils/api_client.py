# frontend/utils/api_client.py
# ─────────────────────────────────────────────────────────────────────────────
# Central HTTP client for all communication with the FastAPI backend.
# All network calls go through this module — screens never call httpx directly.
# ─────────────────────────────────────────────────────────────────────────────
import httpx
import logging
from pathlib import Path
from typing import Optional

from frontend.utils.config import API_BASE_URL, REQUEST_TIMEOUT

logger = logging.getLogger(__name__)


class APIError(Exception):
    """Raised when the backend returns an error or is unreachable."""
    pass


def _get() -> dict:
    """Return a shared httpx Client config dict."""
    return {"base_url": API_BASE_URL, "timeout": REQUEST_TIMEOUT}


# ── Health ────────────────────────────────────────────────────────────────────

def check_health() -> bool:
    """Returns True if the backend is reachable."""
    try:
        r = httpx.get(f"{API_BASE_URL}/stats/health", timeout=3)
        return r.status_code == 200
    except Exception:
        return False


# ── Stats / Dashboard ─────────────────────────────────────────────────────────

def get_summary() -> dict:
    """Fetch alert summary counts for the dashboard."""
    try:
        r = httpx.get(f"{API_BASE_URL}/stats/summary", timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        raise APIError(f"Failed to fetch summary: {e}")


# ── PCAP Analysis ─────────────────────────────────────────────────────────────

def analyze_pcap(pcap_path: Path) -> list:
    """
    Upload a PCAP or CSV file for ML analysis.
    Returns a list of detection result dicts.

    Response is a bare list — contract unchanged.
    """
    try:
        with open(pcap_path, "rb") as f:
            r = httpx.post(
                f"{API_BASE_URL}/analyze/pcap",
                files={"file": (pcap_path.name, f, "application/octet-stream")},
                timeout=600,  # large PCAPs can take several minutes through CICFlowMeter
            )
        r.raise_for_status()
        return r.json()
    except Exception as e:
        raise APIError(f"PCAP analysis failed: {e}")


def get_pcap_meta(pcap_path: Path) -> int:
    """
    Returns the true packet count for a PCAP file via /analyze/pcap/meta.

    Only called for .pcap files — returns 0 immediately for any other extension.
    This is intentional: packet count is not meaningful for pre-processed CSV input.

    Returns 0 on any failure. Callers treat 0 as 'unavailable' (UI shows '—').
    Non-fatal by design — must never block the main analysis workflow.

    Common reasons for returning 0:
      - File is .csv, not .pcap (expected, not an error)
      - capinfos not on system PATH (Wireshark not installed or PATH not set)
      - Backend unreachable
      - Unexpected exception
    All failures are logged at WARNING level so they are diagnosable.
    """
    if pcap_path.suffix.lower() != ".pcap":
        logger.debug(
            f"get_pcap_meta: skipping non-PCAP file '{pcap_path.name}' "
            f"(suffix='{pcap_path.suffix}') — Total Packets card will show '—'"
        )
        return 0
    try:
        with open(pcap_path, "rb") as f:
            r = httpx.post(
                f"{API_BASE_URL}/analyze/pcap/meta",
                files={"file": (pcap_path.name, f, "application/octet-stream")},
                timeout=15,
            )
        r.raise_for_status()
        count = r.json().get("packet_count", 0)
        logger.info(f"get_pcap_meta: packet_count={count} for '{pcap_path.name}'")
        return count
    except Exception as e:
        logger.warning(
            f"get_pcap_meta failed for '{pcap_path.name}': {e} — "
            f"Total Packets card will show '—'. "
            f"Verify capinfos is installed: run 'capinfos --version' in a terminal."
        )
        return 0


# ── Real-Time Capture ─────────────────────────────────────────────────────────

def get_interfaces() -> list:
    """Fetch available tshark interfaces from the backend."""
    try:
        r = httpx.get(f"{API_BASE_URL}/realtime/interfaces", timeout=5)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        raise APIError(f"Failed to get interfaces: {e}")


def start_capture(interface: str = "Wi-Fi", duration: int = 15) -> dict:
    try:
        r = httpx.post(
            f"{API_BASE_URL}/realtime/start",
            params={"interface": interface, "duration": duration},
            timeout=REQUEST_TIMEOUT,
        )
        r.raise_for_status()
        return r.json()
    except Exception as e:
        raise APIError(f"Failed to start capture: {e}")


def stop_capture() -> dict:
    try:
        r = httpx.post(f"{API_BASE_URL}/realtime/stop", timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        raise APIError(f"Failed to stop capture: {e}")


def get_capture_status() -> dict:
    try:
        r = httpx.get(f"{API_BASE_URL}/realtime/status", timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        raise APIError(f"Failed to get capture status: {e}")


# ── Alerts ────────────────────────────────────────────────────────────────────

def get_alerts(
    skip: int = 0,
    limit: int = 100,
    severity: Optional[str] = None,
    source: Optional[str] = None,
) -> list:
    params = {"skip": skip, "limit": limit}
    if severity:
        params["severity"] = severity
    if source:
        params["source"] = source
    try:
        r = httpx.get(f"{API_BASE_URL}/alerts/", params=params, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        raise APIError(f"Failed to fetch alerts: {e}")


def delete_alert(alert_id: int) -> dict:
    try:
        r = httpx.delete(f"{API_BASE_URL}/alerts/{alert_id}", timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        raise APIError(f"Failed to delete alert {alert_id}: {e}")


# ── Live Rule-Based Monitor ───────────────────────────────────────────────────

def start_live_monitor(interface: str = "Wi-Fi") -> dict:
    """Start the lightweight live rule-based monitoring session."""
    try:
        r = httpx.post(
            f"{API_BASE_URL}/live/start",
            params={"interface": interface},
            timeout=REQUEST_TIMEOUT,
        )
        r.raise_for_status()
        return r.json()
    except Exception as e:
        raise APIError(f"Failed to start live monitor: {e}")


def stop_live_monitor() -> dict:
    """Stop the live monitoring session."""
    try:
        r = httpx.post(f"{API_BASE_URL}/live/stop", timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        raise APIError(f"Failed to stop live monitor: {e}")


def get_live_status() -> dict:
    """Poll the live monitor state (running, packets_seen, alerts_fired, recent_events)."""
    try:
        r = httpx.get(f"{API_BASE_URL}/live/status", timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        raise APIError(f"Failed to get live status: {e}")


# ── Authentication Honeypot ───────────────────────────────────────────────────

def start_honeypot(services: Optional[list[str]] = None) -> dict:
    """Start the authentication honeypot listeners (SSH/Telnet/FTP)."""
    try:
        params = {}
        if services:
            params["services"] = services
        r = httpx.post(
            f"{API_BASE_URL}/honeypot/start",
            params=params,
            timeout=REQUEST_TIMEOUT,
        )
        r.raise_for_status()
        return r.json()
    except Exception as e:
        raise APIError(f"Failed to start honeypot: {e}")


def stop_honeypot() -> dict:
    """Stop all honeypot listeners."""
    try:
        r = httpx.post(f"{API_BASE_URL}/honeypot/stop", timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        raise APIError(f"Failed to stop honeypot: {e}")


def get_honeypot_status() -> dict:
    """Poll the honeypot state (running, attempts, alerts, recent_events)."""
    try:
        r = httpx.get(f"{API_BASE_URL}/honeypot/status", timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        raise APIError(f"Failed to get honeypot status: {e}")
