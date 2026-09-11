# backend/config.py
# ─────────────────────────────────────────────────────────────────────────────
# Backend configuration. All tuneable settings live here.
# ─────────────────────────────────────────────────────────────────────────────
import os
from pathlib import Path

# Project root (two levels up from this file: backend/ → ids_project/)
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# ─── Server ─────────────────────────────────────────────
HOST = "127.0.0.1"
PORT = 8000

# ─── Database ───────────────────────────────────────────
DB_PATH = PROJECT_ROOT / "data" / "alerts.db"
DATABASE_URL = f"sqlite:///{DB_PATH}"

# ─── Model Paths ────────────────────────────────────────
MODELS_DIR = PROJECT_ROOT / "data" / "models"
ANOMALY_MODEL_PATH      = MODELS_DIR / "anomaly_model.joblib"
CLASSIFIER_MODEL_PATH   = MODELS_DIR / "classifier_model.joblib"
SCALER_PATH             = MODELS_DIR / "scaler.joblib"
RT_CLASSIFIER_PATH      = MODELS_DIR / "rt_classifier_model.joblib"   # 6-feature realtime RF
RT_CLASSIFIER_META_PATH = MODELS_DIR / "rt_classifier_meta.json"

# ─── Detection ──────────────────────────────────────────
CONFIDENCE_THRESHOLD = float(os.getenv("IDS_CONFIDENCE_THRESHOLD", "0.70"))

# ─── Upload temp directory ──────────────────────────────
UPLOAD_DIR = PROJECT_ROOT / "data" / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
