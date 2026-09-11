# backend/routers/realtime.py
# ─────────────────────────────────────────────────────────────────────────────
# Routes for real-time traffic capture management.
# ─────────────────────────────────────────────────────────────────────────────
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.services import capture_service
from backend.services.alert_service import result_to_alert, save_alert
from backend.models.result import DetectionResult
from backend.utils.database import get_db

router = APIRouter(prefix="/realtime", tags=["Real-Time"])


@router.post("/start")
def start_capture(interface: str = "eth0"):
    """Start capturing live traffic on the given network interface."""
    return capture_service.start_capture(interface)


@router.post("/stop")
def stop_capture():
    """Stop the current capture session."""
    return capture_service.stop_capture()


@router.get("/interfaces")
def list_interfaces():
    """List available tshark network interfaces for the dropdown."""
    return capture_service.get_interfaces()


@router.get("/status")
def capture_status():
    """
    Poll for current capture status and recent detection results.
    The frontend calls this every ~2 seconds to get live updates.
    """
    return capture_service.get_capture_status()
