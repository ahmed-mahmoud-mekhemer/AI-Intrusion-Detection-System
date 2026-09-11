# ml_engine/training/train_anomaly.py
# ─────────────────────────────────────────────────────────────────────────────
# Phase 3: Train the Isolation Forest anomaly detector.
# Run from project root: python -m ml_engine.training.train_anomaly
#
# Expects CICIDS2017 CSV files in: data/cicids2017/
# Saves model to:                  data/models/anomaly_model.joblib
# ─────────────────────────────────────────────────────────────────────────────
import sys
from pathlib import Path

# Allow running from project root
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import glob
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

from ml_engine.models.anomaly_model import AnomalyDetector
from ml_engine.models.model_store import save_model
from ml_engine.preprocessing.feature_extractor import (
    clean_cicids_dataframe,
    extract_features_from_dataframe,
)
from ml_engine.preprocessing.feature_names import FEATURE_NAMES
from backend.utils.logger import get_logger

logger = get_logger("train_anomaly")

DATA_DIR = Path("data/cicids2017")
MODELS_DIR = Path("data/models")


def load_cicids_csvs() -> pd.DataFrame:
    csv_files = glob.glob(str(DATA_DIR / "*.csv"))
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in {DATA_DIR}. Download CICIDS2017 first.")
    logger.info(f"Found {len(csv_files)} CSV file(s).")
    frames = []
    for f in csv_files:
        logger.info(f"  Loading {Path(f).name} …")
        df = pd.read_csv(f, low_memory=False)
        frames.append(df)
    return pd.concat(frames, ignore_index=True)


def main():
    logger.info("=== Training Anomaly Detector (Isolation Forest) ===")

    df = load_cicids_csvs()
    df = clean_cicids_dataframe(df)

    # Train only on BENIGN flows — the model learns "normal" traffic
    benign_df = df[df["Label"] == "BENIGN"]
    logger.info(f"BENIGN flows for training: {len(benign_df):,}")

    X_benign = extract_features_from_dataframe(benign_df[FEATURE_NAMES])

    # Fit scaler on BENIGN data, then transform
    logger.info("Fitting StandardScaler …")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_benign)

    logger.info("Training Isolation Forest …")
    detector = AnomalyDetector(contamination=0.05, n_estimators=100)
    detector.fit(X_scaled)

    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    detector.save(MODELS_DIR / "anomaly_model.joblib")
    save_model(scaler, MODELS_DIR / "scaler.joblib")

    logger.info("Anomaly model and scaler saved successfully.")


if __name__ == "__main__":
    main()
