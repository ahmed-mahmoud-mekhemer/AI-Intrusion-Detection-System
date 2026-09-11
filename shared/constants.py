# shared/constants.py

# Detection outcome labels — the only 3 possible outputs
LABEL_BENIGN    = "BENIGN"
LABEL_UNKNOWN   = "UNKNOWN_MALICIOUS"

# Confidence thresholds
BENIGN_CONFIDENCE_MIN           = 0.80   # RF must be >= this to call BENIGN
CLASSIFICATION_CONFIDENCE_THRESHOLD = 0.70   # RF must be >= this to call a KNOWN ATTACK
ANOMALY_SCORE_THRESHOLD         = -0.05  # IsolationForest decision_function cutoff

# Alert severity levels
SEVERITY_LOW      = "LOW"
SEVERITY_MEDIUM   = "MEDIUM"
SEVERITY_HIGH     = "HIGH"
SEVERITY_CRITICAL = "CRITICAL"

# Backend defaults
DEFAULT_BACKEND_HOST = "127.0.0.1"
DEFAULT_BACKEND_PORT = 8000
DEFAULT_BACKEND_URL  = f"http://{DEFAULT_BACKEND_HOST}:{DEFAULT_BACKEND_PORT}"

# Model paths
ANOMALY_MODEL_PATH     = "data/models/anomaly_model.joblib"
CLASSIFIER_MODEL_PATH  = "data/models/classifier_model.joblib"
SCALER_MODEL_PATH      = "data/models/scaler.joblib"
