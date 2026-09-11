# backend/services/detection_service.py
# ─────────────────────────────────────────────────────────────────────────────
# Orchestrates the detection pipeline.
# Lazy-loads IDSPredictor on first use so the backend starts instantly.
# Falls back to mock predictions only when models are not yet trained.
# ─────────────────────────────────────────────────────────────────────────────
from typing import List
import uuid

from backend.models.result import DetectionResult
from backend.utils.logger import get_logger
from shared.constants import LABEL_BENIGN, LABEL_UNKNOWN

logger = get_logger(__name__)

_predictor = None   # loaded once on first call


def _get_predictor():
    """Load IDSPredictor on first use. Returns None if models are missing."""
    global _predictor
    if _predictor is None:
        try:
            from ml_engine.predictor import IDSPredictor
            _predictor = IDSPredictor()
            logger.info("IDSPredictor loaded — real model is active.")
        except FileNotFoundError as e:
            logger.warning(f"Model files not found: {e}")
            logger.warning("Falling back to mock predictions. Train the model first.")
            _predictor = "mock"
        except Exception as e:
            logger.error(f"Unexpected error loading predictor: {e}")
            _predictor = "mock"
    return _predictor


def _mock_predict(flow: dict) -> DetectionResult:
    """
    Fallback used only when no trained model is available.
    Clearly logged as mock so it's obvious in the console.
    """
    import random
    labels = [LABEL_BENIGN, "DDoS", LABEL_UNKNOWN]
    label = random.choice(labels)
    is_anomalous = label != LABEL_BENIGN
    logger.debug(f"[MOCK] flow {flow.get('flow_id','')} → {label}")
    return DetectionResult(
        flow_id       = flow.get("flow_id", str(uuid.uuid4())),
        is_anomalous  = is_anomalous,
        label         = label,
        confidence    = round(__import__("random").uniform(0.5, 0.99), 2) if is_anomalous else None,
        stage_reached = 1 if not is_anomalous else 2,
        src_ip        = flow.get("src_ip", "0.0.0.0"),
        dst_ip        = flow.get("dst_ip", "0.0.0.0"),
        src_port      = flow.get("src_port", 0),
        dst_port      = flow.get("dst_port", 0),
        protocol      = flow.get("protocol", "TCP"),
        timestamp     = flow.get("timestamp", ""),
    )


def detect_flows(flows: List[dict]) -> List[DetectionResult]:
    """
    Run detection on a list of flow dicts.

    Each flow dict must contain:
      - Metadata keys:  flow_id, src_ip, dst_ip, src_port, dst_port, protocol, timestamp
      - Feature keys:   all CICIDS2017 column names (the same ones used during training)
                        These are stored directly in the dict alongside metadata.

    When the real model is loaded, the predictor extracts features by column name,
    so extra metadata keys in the dict are safely ignored.
    """
    predictor = _get_predictor()
    results = []

    for flow in flows:
        try:
            if predictor == "mock":
                result = _mock_predict(flow)
            else:
                # flow_dict = the full dict (predictor picks feature columns by name)
                # flow_meta = just the metadata fields predictor needs for the result object
                flow_meta = {
                    "flow_id":   flow.get("flow_id", str(uuid.uuid4())),
                    "src_ip":    flow.get("src_ip", "0.0.0.0"),
                    "dst_ip":    flow.get("dst_ip", "0.0.0.0"),
                    "src_port":  flow.get("src_port", 0),
                    "dst_port":  flow.get("dst_port", 0),
                    "protocol":  flow.get("protocol", "TCP"),
                    "timestamp": flow.get("timestamp", ""),
                }
                result = predictor.predict(flow_dict=flow, flow_meta=flow_meta)
            results.append(result)
        except Exception as e:
            logger.error(f"Detection failed for flow {flow.get('flow_id', '?')}: {e}")

    return results
