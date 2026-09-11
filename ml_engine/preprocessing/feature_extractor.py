# ml_engine/preprocessing/feature_extractor.py
# ─────────────────────────────────────────────────────────────────────────────
# Converts raw network flow data into the 78-feature vector used by CICIDS2017.
#
# Phase 4 TODO: Implement real flow statistics computation from scapy packets.
# For now, this module handles the case where flows already have CICFlowMeter
# CSV columns, mapping them to the canonical feature order.
# ─────────────────────────────────────────────────────────────────────────────
import numpy as np
import pandas as pd
from typing import Dict, List, Optional

from ml_engine.preprocessing.feature_names import FEATURE_NAMES


def extract_features_from_cicids_row(row: Dict) -> np.ndarray:
    """
    Extract a feature vector from a single CICIDS2017 CSV row (as a dict).
    Maps column names to the canonical feature order, filling missing values with 0.

    Args:
        row: Dictionary with CICIDS2017 column names as keys.

    Returns:
        np.ndarray of shape (78,), dtype float32.
    """
    vector = []
    for feature in FEATURE_NAMES:
        value = row.get(feature, row.get(feature.strip(), 0.0))
        try:
            value = float(value)
        except (ValueError, TypeError):
            value = 0.0
        # Replace infinities and NaN with 0 (common in CICIDS2017)
        if not np.isfinite(value):
            value = 0.0
        vector.append(value)
    return np.array(vector, dtype=np.float32)


def extract_features_from_dataframe(df: pd.DataFrame) -> np.ndarray:
    """
    Batch-extract feature matrix from a CICIDS2017 DataFrame.

    Args:
        df: DataFrame with CICIDS2017 column headers.

    Returns:
        np.ndarray of shape (n_samples, 78), dtype float32.
    """
    # Strip whitespace from column names (CICIDS CSVs often have leading spaces)
    df.columns = df.columns.str.strip()

    matrix = []
    for _, row in df.iterrows():
        matrix.append(extract_features_from_cicids_row(row.to_dict()))
    return np.array(matrix, dtype=np.float32)


def clean_cicids_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """
    Clean a raw CICIDS2017 DataFrame:
    - Strip column whitespace
    - Replace inf/NaN with 0
    - Drop rows with missing labels
    """
    df.columns = df.columns.str.strip()

    # Replace infinite values
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(0, inplace=True)

    # Drop rows where Label is missing
    if " Label" in df.columns:
        df.rename(columns={" Label": "Label"}, inplace=True)
    if "Label" in df.columns:
        df = df[df["Label"].notna()]

    return df


# ── Phase 4: Real packet-to-flow statistics (placeholder) ────────────────────
def extract_features_from_packets(packets: list) -> Optional[np.ndarray]:
    """
    Phase 4 TODO: Compute CICIDS-compatible flow statistics from a list of
    scapy packets belonging to a single bidirectional flow.

    This requires computing: IAT stats, packet length stats, flag counts,
    header lengths, bulk rates, active/idle times, etc.

    For now, returns None (signals that mock data should be used).
    """
    # TODO: Implement CICFlowMeter-compatible statistics computation
    return None
