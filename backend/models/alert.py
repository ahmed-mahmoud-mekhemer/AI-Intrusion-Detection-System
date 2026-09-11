# backend/models/alert.py
# ─────────────────────────────────────────────────────────────────────────────
# Alert schema — a persisted detection event.
# ─────────────────────────────────────────────────────────────────────────────
from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class Alert(BaseModel):
    """An alert generated from a detection result."""
    id: Optional[int] = None
    flow_id: str
    label: str
    severity: str
    confidence: Optional[float] = None
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    timestamp: str
    created_at: Optional[datetime] = None
    source: str = "pcap"   # "pcap" | "live" | "honeypot"
    detection_type: Optional[str] = "RULE"   # "RULE" | "HYBRID" | "AI-CLASSIFIED" | "AI-UNKNOWN"
    detail: Optional[str] = None             # human-readable explanation (rule trigger / RF output)

    class Config:
        from_attributes = True
