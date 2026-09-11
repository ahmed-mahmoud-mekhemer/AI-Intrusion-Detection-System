# backend/models/result.py
# ─────────────────────────────────────────────────────────────────────────────
# Detection result returned by the ML pipeline for one flow.
# ─────────────────────────────────────────────────────────────────────────────
from pydantic import BaseModel
from typing import Optional


class DetectionResult(BaseModel):
    """Result of running the 3-stage detection pipeline on one flow."""
    flow_id: str
    is_anomalous: bool                    # Stage 1 result
    label: str                            # Final label (BENIGN / attack / SUSPICIOUS)
    confidence: Optional[float] = None    # Stage 2 classifier confidence
    stage_reached: int                    # 1=normal, 2=classified, 3=unknown
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    timestamp: str
