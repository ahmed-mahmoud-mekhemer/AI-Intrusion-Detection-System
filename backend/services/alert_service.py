# backend/services/alert_service.py
from typing import List, Optional
from sqlalchemy.orm import Session

from backend.utils.database import AlertORM
from backend.models.alert import Alert
from backend.models.result import DetectionResult
from backend.utils.logger import get_logger
from shared.attack_labels import LABEL_SEVERITY_MAP
from shared.constants import LABEL_BENIGN

logger = get_logger(__name__)


def result_to_alert(result: DetectionResult, source: str = "pcap") -> Optional[Alert]:
    """Convert a DetectionResult to an Alert. Returns None for BENIGN."""
    if result.label == LABEL_BENIGN:
        return None

    severity = LABEL_SEVERITY_MAP.get(result.label, "MEDIUM") or "MEDIUM"

    return Alert(
        flow_id=result.flow_id,
        label=result.label,
        severity=severity,
        confidence=result.confidence,
        src_ip=result.src_ip,
        dst_ip=result.dst_ip,
        src_port=result.src_port,
        dst_port=result.dst_port,
        protocol=result.protocol,
        timestamp=result.timestamp,
        source=source,
    )


def save_alert(db: Session, alert: Alert) -> Optional[AlertORM]:
    """
    Persist an alert.

    Deduplication is based on flow_id only — each flow gets a UUID in
    pcap_service.py, so flow_id is guaranteed unique per analysis run.
    This prevents double-saves if save_alert() is accidentally called twice
    for the same result, while allowing every distinct flow to be persisted.

    Previous dedup used (label + src_ip + dst_ip + dst_port + timestamp),
    which caused false deduplication when multiple malicious flows shared
    the same metadata (common with CSV files where all timestamps are identical
    and IPs are N/A). That logic dropped legitimate detections silently.
    """
    duplicate = (
        db.query(AlertORM)
        .filter(AlertORM.flow_id == alert.flow_id)
        .first()
    )
    if duplicate:
        return None   # same flow submitted twice — skip silently

    db_alert = AlertORM(**alert.model_dump(exclude={"id", "created_at"}))
    db.add(db_alert)
    db.commit()
    db.refresh(db_alert)
    return db_alert


def get_alerts(
    db: Session,
    skip: int = 0,
    limit: int = 100,
    severity: Optional[str] = None,
    source: Optional[str] = None,
) -> List[AlertORM]:
    """Retrieve alerts with optional filters, newest first."""
    query = db.query(AlertORM)
    if severity:
        query = query.filter(AlertORM.severity == severity)
    if source:
        query = query.filter(AlertORM.source == source)
    return query.order_by(AlertORM.id.desc()).offset(skip).limit(limit).all()


def delete_alert(db: Session, alert_id: int) -> bool:
    """Delete a single alert by ID."""
    alert = db.query(AlertORM).filter(AlertORM.id == alert_id).first()
    if not alert:
        return False
    db.delete(alert)
    db.commit()
    return True


def clear_all_alerts(db: Session) -> int:
    """Delete all alerts. Returns the number of rows deleted."""
    count = db.query(AlertORM).count()
    db.query(AlertORM).delete()
    db.commit()
    logger.info(f"Cleared {count} alerts from the database.")
    return count


def get_summary(db: Session) -> dict:
    """
    Return aggregate counts for the dashboard.

    total_alerts  — every persisted alert regardless of severity
    total_threats — same as total_alerts (all non-BENIGN detections are threats)
                    exposed separately so the frontend can use either key
    critical/high/medium/low — breakdown by severity
    """
    total    = db.query(AlertORM).count()
    critical = db.query(AlertORM).filter(AlertORM.severity == "CRITICAL").count()
    high     = db.query(AlertORM).filter(AlertORM.severity == "HIGH").count()
    medium   = db.query(AlertORM).filter(AlertORM.severity == "MEDIUM").count()
    low      = db.query(AlertORM).filter(AlertORM.severity == "LOW").count()

    return {
        "total_alerts":  total,
        "total_threats": total,   # every saved alert is a non-BENIGN detection
        "critical": critical,
        "high":     high,
        "medium":   medium,
        "low":      low,
    }
