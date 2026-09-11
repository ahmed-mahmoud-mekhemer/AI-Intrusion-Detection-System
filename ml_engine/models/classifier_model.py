# ml_engine/models/classifier_model.py
# ─────────────────────────────────────────────────────────────────────────────
# Random Forest wrapper for Stage 2: attack classification.
# ─────────────────────────────────────────────────────────────────────────────
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from pathlib import Path
from typing import Optional, Tuple, List

from ml_engine.models.model_store import save_model, load_model


class AttackClassifier:
    """
    Wraps scikit-learn's Random Forest for multi-class attack classification.
    - fit(): train on labeled CICIDS2017 flow features
    - predict(): returns (label, confidence) for a single sample
    """

    def __init__(self, n_estimators: int = 100):
        self.n_estimators = n_estimators
        self._model: Optional[RandomForestClassifier] = None
        self._classes: Optional[List[str]] = None

    def fit(self, X: np.ndarray, y: np.ndarray) -> None:
        """
        Train the classifier.

        Args:
            X: Feature matrix (n_samples, 78)
            y: Label array (n_samples,) — string class names
        """
        self._model = RandomForestClassifier(
            n_estimators=self.n_estimators,
            random_state=42,
            n_jobs=-1,
            class_weight="balanced",  # Handle CICIDS2017 class imbalance
        )
        self._model.fit(X, y)
        self._classes = list(self._model.classes_)

    def predict(self, x: np.ndarray) -> Tuple[str, float]:
        """
        Predict the attack label and confidence for a single flow.

        Args:
            x: Feature vector of shape (78,) or (1, 78).

        Returns:
            Tuple of (label: str, confidence: float in [0, 1])
        """
        if self._model is None:
            raise RuntimeError("AttackClassifier has not been trained or loaded.")
        x = x.reshape(1, -1)
        probas = self._model.predict_proba(x)[0]
        best_idx = int(np.argmax(probas))
        label = self._classes[best_idx]
        confidence = float(probas[best_idx])
        return label, confidence

    def save(self, path: Path) -> None:
        save_model({"model": self._model, "classes": self._classes}, path)

    def load(self, path: Path) -> None:
        data = load_model(path)
        if data:
            self._model = data["model"]
            self._classes = data["classes"]

    @property
    def is_loaded(self) -> bool:
        return self._model is not None
