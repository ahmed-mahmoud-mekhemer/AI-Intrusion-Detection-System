# backend/routers/analyze.py
import shutil
import uuid
from pathlib import Path

from fastapi import APIRouter, UploadFile, File, HTTPException, Depends
from sqlalchemy.orm import Session
from typing import List

from backend.config import UPLOAD_DIR
from backend.services.pcap_service import analyze_csv, analyze_pcap, get_packet_count
from backend.services.alert_service import result_to_alert, save_alert
from backend.models.result import DetectionResult
from backend.utils.database import get_db
from backend.utils.logger import get_logger

router = APIRouter(prefix="/analyze", tags=["Analysis"])
logger = get_logger(__name__)


@router.post("/pcap", response_model=List[DetectionResult])
async def analyze_file(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    """
    Upload a CICIDS2017 CSV file (or PCAP) for analysis.
    Returns one DetectionResult per flow row.
    Non-benign results are automatically saved as alerts.

    Response shape: List[DetectionResult] — unchanged, backward-compatible.
    """
    filename = file.filename or ""
    is_csv  = filename.lower().endswith(".csv")
    is_pcap = filename.lower().endswith(".pcap")

    if not (is_csv or is_pcap):
        raise HTTPException(
            status_code=400,
            detail="Only .csv (CICIDS2017) or .pcap files are accepted."
        )

    temp_path = UPLOAD_DIR / f"{uuid.uuid4().hex}_{filename}"

    try:
        with open(temp_path, "wb") as buf:
            shutil.copyfileobj(file.file, buf)

        logger.info(f"Received file: {filename}")

        results = analyze_csv(temp_path) if is_csv else analyze_pcap(temp_path)

        alert_count = 0
        for result in results:
            alert = result_to_alert(result, source="pcap")
            if alert:
                save_alert(db, alert)
                alert_count += 1

        logger.info(f"Done — {len(results)} flows, {alert_count} alerts saved.")
        return results

    finally:
        if temp_path.exists():
            temp_path.unlink()


@router.post("/pcap/meta")
async def get_pcap_metadata(file: UploadFile = File(...)):
    """
    Lightweight metadata endpoint — returns packet count only.

    Does NOT invoke CICFlowMeter or the ML pipeline.
    Uses capinfos (ships with Wireshark) to read PCAP file metadata.
    Completes in ~200ms regardless of PCAP size.

    Returns {"packet_count": N} for PCAP files.
    Returns {"packet_count": 0} for non-PCAP input (e.g. CSV) — not an error.

    This endpoint exists to populate the 'Total Packets' metric card in the
    frontend without coupling packet count to the analysis response shape.
    The /pcap endpoint contract is preserved exactly.
    """
    filename = file.filename or ""
    if not filename.lower().endswith(".pcap"):
        return {"packet_count": 0}

    temp_path = UPLOAD_DIR / f"{uuid.uuid4().hex}_{filename}"
    try:
        with open(temp_path, "wb") as buf:
            shutil.copyfileobj(file.file, buf)
        count = get_packet_count(temp_path)
        logger.info(f"Packet count for {filename}: {count}")
        return {"packet_count": count}
    finally:
        if temp_path.exists():
            temp_path.unlink()
