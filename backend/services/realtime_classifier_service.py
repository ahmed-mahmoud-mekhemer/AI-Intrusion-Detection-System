# backend/services/realtime_classifier_service.py
# ─────────────────────────────────────────────────────────────────────────────
# Supervised Realtime Attack Classifier
#
# Role in the hybrid IDS:
#   anomaly_service  →  checks_behavioral_alert (5-gate filter)
#                            │
#                            ▼  score ≥ 0.55, all gates pass
#                    classify_behavioral_alert()
#                            │
#                     [this module]  ← tries RF first
#                            │  conf ≥ 0.70 and not BENIGN
#                            ▼
#                    AI-CLASSIFIED:  "Likely SYN Flood" / "Likely Port Scan" …
#                            │
#                     conf < 0.70 or BENIGN  →  fall through to EMA classifier
#
# Design:
#   - Lazy load: model is loaded on first call, not at import time
#   - Thread-safe: single _load_lock guards model initialization
#   - Graceful degradation: returns (label, 0.0, reason) if model absent/broken,
#     which triggers the EMA-ratio fallback in classify_behavioral_alert()
#   - Open-set: confidence threshold (CONFIDENCE_THRESHOLD) rejects uncertain
#     predictions so they become AI-UNKNOWN rather than a forced label
#   - BENIGN class: if the RF says "BENIGN" with high confidence on an IF-flagged
#     anomaly, the system suppresses the alert (border-noise suppression)
#
# Feature vector (14 features — must match anomaly_service.py and training):
#   [total_rate, syn_rate, icmp_rate, udp_rate, unique_dst_ports, avg_pkt_size,
#    ack_rate, rst_rate, fin_rate, syn_ack_ratio, pkt_size_std,
#    unique_src_ips, dst_port_entropy, bytes_rate]
# ─────────────────────────────────────────────────────────────────────────────
import threading
from pathlib import Path
from typing import Optional

from backend.utils.logger import get_logger

logger = get_logger(__name__)

# ── Model path ─────────────────────────────────────────────────────────────────

_MODEL_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "data" / "models" / "rt_classifier_model.joblib"
)

# ── Open-set confidence threshold ─────────────────────────────────────────────
# Predictions with max(predict_proba) below this are rejected as uncertain
# and fall through to the EMA-ratio classifier → eventually AI-UNKNOWN.
CONFIDENCE_THRESHOLD: float = 0.70

# ── Attack label prefix ───────────────────────────────────────────────────────
# The RF predicts class names like "SYN Flood". The caller prepends "Likely "
# to produce the final UI label. BENIGN is the exception (no prefix needed).
_BENIGN_CLASS = "BENIGN"

# ── Internal state ─────────────────────────────────────────────────────────────
_model      = None        # loaded sklearn Pipeline
_classes    = None        # list[str] — ordered class labels from training
_load_lock  = threading.Lock()
_model_ok   = False       # True once successfully loaded


def _load_model() -> None:
    """Lazy-load the RF pipeline from disk. Called on first classify() call."""
    global _model, _classes, _model_ok

    with _load_lock:
        if _model_ok:
            return

        if not _MODEL_PATH.exists():
            logger.warning(
                f"[rt_clf] Model not found at {_MODEL_PATH}. "
                "Run scripts/train_realtime_classifier.py to create it. "
                "EMA-ratio classifier will be used as fallback."
            )
            return

        try:
            import joblib
            _model   = joblib.load(_MODEL_PATH)
            _classes = list(_model.classes_)
            _model_ok = True
            logger.info(
                f"[rt_clf] RF classifier loaded. "
                f"Classes: {_classes}  Threshold: {CONFIDENCE_THRESHOLD:.0%}"
            )
        except Exception as exc:
            logger.error(f"[rt_clf] Failed to load RF model: {exc}")
            _model   = None
            _model_ok = False


def is_model_loaded() -> bool:
    """Return True if the RF model is loaded and ready."""
    _load_model()
    return _model_ok


def classify(features: list) -> tuple:
    """
    Attempt to classify a 6-feature window using the trained Random Forest.

    Parameters
    ----------
    features : list of float, length 14
        [total_rate, syn_rate, icmp_rate, udp_rate, unique_dst_ports, avg_pkt_size,
         ack_rate, rst_rate, fin_rate, syn_ack_ratio, pkt_size_std,
         unique_src_ips, dst_port_entropy, bytes_rate]

    Returns
    -------
    (label: str, confidence: float, explanation: str)

    label:
        "Likely SYN Flood"   — RF classified with confidence ≥ threshold
        "Likely Port Scan"   — …
        "BENIGN"             — RF says traffic looks normal (suppress alert)
        ""                   — model absent or confidence below threshold
                               caller falls through to EMA-ratio classifier

    confidence:
        0.0  → model absent, error, or confidence below threshold (fall through)
        >0.0 → RF confidence (max predict_proba)

    explanation:
        Human-readable description for the alert detail field.
    """
    _load_model()

    if not _model_ok or _model is None:
        return "", 0.0, "RF model not loaded — using EMA classifier"

    try:
        import numpy as np
        X = np.array(features, dtype=float).reshape(1, -1)

        proba     = _model.predict_proba(X)[0]
        max_prob  = float(proba.max())
        top_idx   = int(proba.argmax())
        top_class = _classes[top_idx]

        # ── BENIGN prediction ──────────────────────────────────────────────────
        if top_class == _BENIGN_CLASS:
            if max_prob >= CONFIDENCE_THRESHOLD:
                # IF gate fired but RF says traffic is normal → border noise
                expl = (
                    f"RF: looks like normal traffic ({max_prob:.0%} confidence) "
                    f"| border-noise suppression"
                )
                return _BENIGN_CLASS, round(max_prob, 3), expl
            else:
                # Uncertain even about benign → let EMA decide
                return "", 0.0, f"RF uncertain (BENIGN {max_prob:.0%}, below threshold)"

        # ── Attack prediction ──────────────────────────────────────────────────
        if max_prob < CONFIDENCE_THRESHOLD:
            # Not confident enough — fall through to EMA classifier
            return (
                "",
                0.0,
                f"RF uncertain: {top_class} ({max_prob:.0%} confidence, "
                f"below {CONFIDENCE_THRESHOLD:.0%} threshold)"
            )

        # Compute runner-up for explanation richness
        sorted_idx = proba.argsort()[::-1]
        runner_up  = _classes[sorted_idx[1]] if len(_classes) > 1 else ""
        runner_p   = float(proba[sorted_idx[1]]) if len(_classes) > 1 else 0.0

        label = f"Likely {top_class}"
        expl  = (
            f"RF classifier: {top_class} ({max_prob:.0%} confidence)"
            + (f" | next: {runner_up} ({runner_p:.0%})" if runner_p > 0.10 else "")
        )
        return label, round(max_prob, 3), expl

    except Exception as exc:
        logger.error(f"[rt_clf] Prediction error: {exc}")
        return "", 0.0, f"RF prediction error: {exc}"
