# ml_engine/predictor.py
# ─────────────────────────────────────────────────────────────────────────────
# IDSPredictor — 3-state detection pipeline
#
# Every flow produces exactly one of three outcomes:
#
#   BENIGN            — safe traffic, no alert
#   KNOWN_ATTACK      — matches a trained attack class with high confidence
#   UNKNOWN_MALICIOUS — anomalous or low-confidence; treated as a real alert
#
# Decision logic:
#
#   1. RF confident BENIGN + Isolation Forest agrees normal → BENIGN
#   2. RF confident BENIGN + Isolation Forest says anomalous → UNKNOWN_MALICIOUS
#   3. RF confident ATTACK                                  → KNOWN_ATTACK
#   4. RF low confidence (any label)                        → UNKNOWN_MALICIOUS
#
# Principle: low confidence NEVER defaults to BENIGN.
# ─────────────────────────────────────────────────────────────────────────────
import numpy as np
import joblib
from pathlib import Path

from backend.models.result import DetectionResult
from backend.utils.logger import get_logger

logger = get_logger(__name__)

# ── Model file paths ──────────────────────────────────────────────────────────
_CLASSIFIER_PATH   = Path("data/models/classifier_model.joblib")
_ANOMALY_PATH      = Path("data/models/anomaly_model.joblib")
_SCALER_PATH       = Path("data/models/scaler.joblib")

# ── Decision thresholds ───────────────────────────────────────────────────────
# RF must reach this confidence to declare BENIGN (higher bar — false negatives
# are dangerous in an IDS).
BENIGN_CONFIDENCE_MIN  = 0.80

# RF must reach this confidence to declare a KNOWN ATTACK.
ATTACK_CONFIDENCE_MIN  = 0.70

# Isolation Forest decision_function threshold.
# Scores above this → normal. Scores below → anomalous.
# IsolationForest.offset_ is the automatic threshold; we add a small margin.
ANOMALY_SCORE_THRESHOLD = -0.05

# Output label constants
LABEL_BENIGN    = "BENIGN"
LABEL_UNKNOWN   = "UNKNOWN_MALICIOUS"


class IDSPredictor:
    """
    Loads all three trained models and runs the 3-state detection pipeline.

    Usage:
        predictor = IDSPredictor()
        result = predictor.predict(flow_dict, flow_meta)
    """

    def __init__(self):
        self._clf           = None   # RandomForestClassifier
        self._iso           = None   # IsolationForest (optional — degrades gracefully)
        self._scaler        = None   # StandardScaler
        self._feature_names = None   # list[str] — exact training column order
        self._classes       = None   # list[str] — RF class names
        self._load()

    def _load(self):
        # ── Classifier (required) ─────────────────────────────────────────────
        if not _CLASSIFIER_PATH.exists():
            raise FileNotFoundError(
                f"Classifier not found at {_CLASSIFIER_PATH}. "
                "Run ml_engine/training/train_classifier.py first."
            )
        clf_data            = joblib.load(_CLASSIFIER_PATH)
        self._clf                    = clf_data["model"]
        self._feature_names          = clf_data["feature_names"]
        self._classes                = list(self._clf.classes_)
        # Per-class confidence overrides for low-sample classes (e.g. Bot)
        self._high_uncertainty       = clf_data.get("high_uncertainty_classes", {})

        # ── Scaler (required) ─────────────────────────────────────────────────
        if not _SCALER_PATH.exists():
            raise FileNotFoundError(
                f"Scaler not found at {_SCALER_PATH}. "
                "Run ml_engine/training/train_classifier.py first."
            )
        self._scaler = joblib.load(_SCALER_PATH)["scaler"]

        # ── Isolation Forest (optional) ───────────────────────────────────────
        if _ANOMALY_PATH.exists():
            self._iso = joblib.load(_ANOMALY_PATH)["model"]
            logger.info("IsolationForest loaded — anomaly detection active.")
        else:
            logger.warning(
                "anomaly_model.joblib not found — "
                "anomaly detection disabled. RF-only mode."
            )

        logger.info(
            f"IDSPredictor ready — "
            f"{len(self._feature_names)} features, "
            f"classes: {self._classes}"
        )

    # ── Public API ────────────────────────────────────────────────────────────

    def predict(self, flow_dict: dict, flow_meta: dict) -> DetectionResult:
        """
        Run the full 3-state pipeline on one flow.

        Args:
            flow_dict:  dict with CICIDS2017 feature columns as keys.
            flow_meta:  dict with flow_id, src_ip, dst_ip, src_port,
                        dst_port, protocol, timestamp.

        Returns:
            DetectionResult with label in {BENIGN, <attack>, UNKNOWN_MALICIOUS}
        """
        # ── 1. Build & scale feature vector ──────────────────────────────────
        x = self._build_vector(flow_dict)          # shape (1, n_features)
        x_scaled = self._scaler.transform(x)

        # ── 2. Classifier probabilities ───────────────────────────────────────
        probas      = self._clf.predict_proba(x_scaled)[0]
        best_idx    = int(np.argmax(probas))
        rf_label    = self._classes[best_idx]
        rf_conf     = float(probas[best_idx])

        # ── 3. Isolation Forest anomaly score ─────────────────────────────────
        # decision_function > 0 → normal, < 0 → anomalous
        # We use it as a veto on BENIGN decisions when the RF is uncertain.
        if self._iso is not None:
            anomaly_score = float(self._iso.decision_function(x_scaled)[0])
            iso_says_anomalous = anomaly_score < ANOMALY_SCORE_THRESHOLD
        else:
            anomaly_score      = None
            iso_says_anomalous = False   # no veto without the model

        # ── 4. Decision logic (3-state) ───────────────────────────────────────
        label, stage = self._decide(
            rf_label, rf_conf, iso_says_anomalous
        )

        return self._build_result(
            meta          = flow_meta,
            label         = label,
            confidence    = rf_conf,
            stage         = stage,
            anomaly_score = anomaly_score,
        )

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _decide(
        self,
        rf_label: str,
        rf_conf: float,
        iso_anomalous: bool,
    ) -> tuple[str, int]:
        """
        Core 3-state decision function.
        Returns (label, stage_number).

        Stage 1 → BENIGN
        Stage 2 → KNOWN_ATTACK  (exact label e.g. "DDoS", "PortScan")
        Stage 3 → UNKNOWN_MALICIOUS
        """

        # ── Path A: RF says BENIGN ────────────────────────────────────────────
        if rf_label == LABEL_BENIGN:
            if rf_conf >= BENIGN_CONFIDENCE_MIN and not iso_anomalous:
                return LABEL_BENIGN, 1
            else:
                # Low confidence OR anomaly veto — never silently pass as benign
                return LABEL_UNKNOWN, 3

        # ── Path B: RF says a known attack ────────────────────────────────────
        else:
            # Some classes have very few training samples (Bot, Web Attack-XSS etc.)
            # and produce many false positives. Use a stricter per-class threshold.
            required_conf = self._high_uncertainty.get(rf_label, ATTACK_CONFIDENCE_MIN)

            if rf_conf >= required_conf:
                return rf_label, 2   # confident known attack
            else:
                # Below threshold → don't guess, escalate to unknown
                return LABEL_UNKNOWN, 3

    def _build_vector(self, flow_dict: dict) -> np.ndarray:
        """
        Align flow_dict to the training feature order.
        Missing columns → 0.0. Non-finite values → 0.0.
        """
        row = []
        for col in self._feature_names:
            val = flow_dict.get(col, 0.0)
            try:
                val = float(val)
            except (ValueError, TypeError):
                val = 0.0
            if not np.isfinite(val):
                val = 0.0
            row.append(val)
        return np.array(row, dtype=np.float32).reshape(1, -1)

    @staticmethod
    def _build_result(meta, label, confidence, stage, anomaly_score) -> DetectionResult:
        is_anomalous = label != LABEL_BENIGN
        return DetectionResult(
            flow_id       = meta.get("flow_id", ""),
            is_anomalous  = is_anomalous,
            label         = label,
            confidence    = confidence,
            stage_reached = stage,
            src_ip        = meta.get("src_ip",    "N/A"),
            dst_ip        = meta.get("dst_ip",    "N/A"),
            src_port      = meta.get("src_port",   0),
            dst_port      = meta.get("dst_port",   0),
            protocol      = meta.get("protocol",  "N/A"),
            timestamp     = meta.get("timestamp", ""),
        )
