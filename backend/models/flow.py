# backend/models/flow.py
# ─────────────────────────────────────────────────────────────────────────────
# Pydantic schema representing a single extracted network flow.
# ─────────────────────────────────────────────────────────────────────────────
from pydantic import BaseModel
from typing import Optional


class NetworkFlow(BaseModel):
    """A single network flow with extracted features."""
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    timestamp: str
    # Feature vector is passed separately to the ML layer; this is the metadata.
    duration: Optional[float] = None
    total_fwd_packets: Optional[int] = None
    total_bwd_packets: Optional[int] = None
