# ml_engine/models/model_store.py
# ─────────────────────────────────────────────────────────────────────────────
# Handles loading and saving of trained model files (.joblib).
# ─────────────────────────────────────────────────────────────────────────────
from pathlib import Path
from typing import Any, Optional
import joblib

from backend.utils.logger import get_logger

logger = get_logger(__name__)


def save_model(model: Any, path: Path) -> None:
    """Serialize a model/scaler to disk using joblib."""
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, path)
    logger.info(f"Model saved → {path}")


def load_model(path: Path) -> Optional[Any]:
    """
    Load a model from disk.
    Returns None (with a warning) if the file doesn't exist yet.
    """
    if not path.exists():
        logger.warning(f"Model file not found: {path}. Train the model first.")
        return None
    model = joblib.load(path)
    logger.info(f"Model loaded ← {path}")
    return model
