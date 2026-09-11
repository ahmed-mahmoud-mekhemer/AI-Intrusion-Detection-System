# backend/routers/alerts.py
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.services.alert_service import get_alerts, delete_alert, clear_all_alerts
from backend.models.alert import Alert
from backend.utils.database import get_db

router = APIRouter(prefix="/alerts", tags=["Alerts"])


@router.get("/", response_model=List[Alert])
def list_alerts(
    skip: int = 0,
    limit: int = 100,
    severity: Optional[str] = None,
    source: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """List alerts with optional filtering by severity or source."""
    return get_alerts(db, skip=skip, limit=limit, severity=severity, source=source)


@router.delete("/clear")
def clear_alerts(db: Session = Depends(get_db)):
    """Delete ALL alerts from the database. Used for testing/reset."""
    count = clear_all_alerts(db)
    return {"status": "cleared", "deleted": count}


@router.delete("/{alert_id}")
def remove_alert(alert_id: int, db: Session = Depends(get_db)):
    """Delete a specific alert by its ID."""
    deleted = delete_alert(db, alert_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Alert not found.")
    return {"status": "deleted", "id": alert_id}
