# ml_engine/models/anomaly_model.py
# ─────────────────────────────────────────────────────────────────────────────
# Isolation Forest wrapper for Stage 1: anomaly detection.
# ─────────────────────────────────────────────────────────────────────────────
import numpy as np
from sklearn.ensemble import IsolationForest
from pathlib import Path
from typing import Optional

from ml_engine.models.model_store import save_model, load_model


class AnomalyDetector:
    """
    Wraps scikit-learn's Isolation Forest.
    - fit(): train on a feature matrix (typically on BENIGN flows only)
    - predict(): returns True if anomalous, False if normal
    """

    def __init__(self, contamination: float = 0.05, n_estimators: int = 100):
        self.contamination = contamination
        self.n_estimators = n_estimators
        self._model: Optional[IsolationForest] = None

    def fit(self, X: np.ndarray) -> None:
        """Train on a (n_samples, 78) feature matrix."""
        self._model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=42,
            n_jobs=-1,
        )
        self._model.fit(X)

    def predict(self, x: np.ndarray) -> bool:
        """
        Predict whether a single sample is anomalous.

        Args:
            x: Feature vector of shape (78,) or (1, 78).

        Returns:
            True if anomalous (attack), False if normal.
        """
        if self._model is None:
            raise RuntimeError("AnomalyDetector has not been trained or loaded.")
        x = x.reshape(1, -1)
        # Isolation Forest: -1 = outlier (anomalous), 1 = inlier (normal)
        return self._model.predict(x)[0] == -1

    def save(self, path: Path) -> None:
        save_model(self._model, path)

    def load(self, path: Path) -> None:
        self._model = load_model(path)

    @property
    def is_loaded(self) -> bool:
        return self._model is not None
