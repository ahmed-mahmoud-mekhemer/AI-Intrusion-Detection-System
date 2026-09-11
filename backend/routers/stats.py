# backend/routers/stats.py
# ─────────────────────────────────────────────────────────────────────────────
# Routes for dashboard summary statistics.
# ─────────────────────────────────────────────────────────────────────────────
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.services.alert_service import get_summary
from backend.utils.database import get_db

router = APIRouter(prefix="/stats", tags=["Stats"])


@router.get("/summary")
def summary(db: Session = Depends(get_db)):
    """
    Return aggregate alert counts grouped by severity.
    Used by the dashboard to populate stat cards.
    """
    return get_summary(db)


@router.get("/health")
def health():
    """Simple health check — frontend calls this to verify backend is up."""
    return {"status": "ok", "service": "IDS Backend"}
