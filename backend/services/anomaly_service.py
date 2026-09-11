# backend/services/anomaly_service.py
# ─────────────────────────────────────────────────────────────────────────────
# Lightweight Real-Time Anomaly Scoring Module
#
# Role in the hybrid IDS:
#   Rule engine  →  catches known attack signatures (labels + severity)
#   This module  →  scores every rule alert with an ML confidence value
#                   using a pre-trained Isolation Forest pipeline
#
# Design constraints:
#   - No new DB tables, no new API routes (beyond what live_monitor exposes)
#   - Thread-safe: called from the consumer thread, read from status thread
#   - Graceful fallback: if model file absent, returns neutral score 0.5
#   - Zero impact on latency: feature extraction is O(n) over 10-s window
#
# Feature vector (14 features, computed over rolling 10-second window):
#   total_rate       — packets/second from all sources
#   syn_rate         — pure SYN packets/second (SYN=1, ACK=0)
#   icmp_rate        — ICMP packets/second
#   udp_rate         — UDP packets/second
#   unique_dst_ports — count of distinct destination ports seen
#   avg_pkt_size     — average frame length in bytes
#   ack_rate         — ACK packets/second (TCP with ACK bit set)
#   rst_rate         — RST packets/second (TCP RST bit)
#   fin_rate         — FIN packets/second (TCP FIN bit)
#   syn_ack_ratio    — SYN / (SYN + ACK), in [0, 1]; ~1.0 = real SYN flood
#   pkt_size_std     — std dev of frame lengths (low = uniform flood)
#   unique_src_ips   — distinct source IPs in window
#   dst_port_entropy — Shannon entropy of destination port distribution
#   bytes_rate       — total bytes/second
#
# Score output convention:
#   0.0 = perfectly normal traffic
#   1.0 = maximally anomalous
#   0.5 = neutral / model not loaded
# ─────────────────────────────────────────────────────────────────────────────
import math
import threading
from collections import Counter, deque
from pathlib import Path
from typing import Optional

from backend.utils.logger import get_logger

logger = get_logger(__name__)

# ── Optional supervised realtime classifier ────────────────────────────────────
# Imported here so the caller's first classify_behavioral_alert() call is fast.
# If the RF model file is absent the import still succeeds; classify() returns
# confidence=0.0 which triggers the EMA-ratio fallback transparently.
try:
    from backend.services import realtime_classifier_service as _rt_clf
    _HAS_RT_CLF = True
except Exception:
    _rt_clf     = None    # type: ignore
    _HAS_RT_CLF = False

# ── Constants ─────────────────────────────────────────────────────────────────

_WINDOW_SECONDS = 10
_FLAG_SYN = 0x002
_FLAG_ACK = 0x010
_FLAG_RST = 0x004
_FLAG_FIN = 0x001

_MODEL_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "data" / "models" / "rt_anomaly_model.joblib"
)

FEATURE_NAMES = [
    "total_rate",        # 0
    "syn_rate",          # 1
    "icmp_rate",         # 2
    "udp_rate",          # 3
    "unique_dst_ports",  # 4
    "avg_pkt_size",      # 5
    "ack_rate",          # 6
    "rst_rate",          # 7
    "fin_rate",          # 8
    "syn_ack_ratio",     # 9  SYN/(SYN+ACK) ∈ [0,1]
    "pkt_size_std",      # 10
    "unique_src_ips",    # 11
    "dst_port_entropy",  # 12 Shannon entropy of dst port distribution
    "bytes_rate",        # 13 total bytes/s
]

# ── Model loader ──────────────────────────────────────────────────────────────

_model        = None   # sklearn Pipeline (StandardScaler + IsolationForest)
_model_loaded = False  # True once load attempted (avoids repeated disk hits)
_model_lock   = threading.Lock()


def _load_model():
    global _model, _model_loaded
    with _model_lock:
        if _model_loaded:
            return
        _model_loaded = True
        if not _MODEL_PATH.exists():
            logger.warning(
                f"[anomaly] Model not found at {_MODEL_PATH}. "
                "Run scripts/train_anomaly_model.py to create it. "
                "Anomaly scoring disabled (returning neutral 0.5)."
            )
            return
        try:
            import joblib
            _model = joblib.load(_MODEL_PATH)
            logger.info(f"[anomaly] Model loaded from {_MODEL_PATH}")
        except Exception as exc:
            logger.error(f"[anomaly] Failed to load model: {exc}")


# ── Sliding-window packet store ───────────────────────────────────────────────

_pkt_window: deque = deque()  # deque of lightweight packet records
_window_lock = threading.Lock()

_current_score: float = 0.5   # latest computed anomaly score, thread-safe read
_score_lock = threading.Lock()

# ── EMA baseline (for behavioral explainability) ──────────────────────────────

_EMA_ALPHA   = 0.1    # smoothing factor — slow adaptation to avoid masking attacks
_EMA_MIN_OBS = 10     # observations needed before EMA is considered "warm"

_ema_state: list = []   # EMA value per feature, same order as FEATURE_NAMES
_ema_count: int  = 0    # number of update() calls
_ema_lock        = threading.Lock()

# ── Behavioral alert gates ────────────────────────────────────────────────────

_BEHAVIORAL_SCORE_THRESH    = 0.55   # minimum IF anomaly score to even consider
_BEHAVIORAL_MIN_PACKETS     = 25     # must have at least this many pkts in window
_BEHAVIORAL_MIN_DEVIATIONS  = 2      # at least N features must deviate from EMA
_BEHAVIORAL_DEVIATION_RATIO = 3.0    # feature / EMA ratio to count as deviation
_BEHAVIORAL_COOLDOWN        = 60.0   # seconds between consecutive behavioral alerts
                                     # (was 120 — reduced to make the tier demonstrable
                                     # in a live session without excessive waiting)

_behavioral_last_fired: float = 0.0
_behavioral_lock = threading.Lock()


def record_packet(pkt: dict) -> None:
    """
    Record a parsed packet dict into the rolling 10-second window.
    Called from the consumer thread for every packet.
    Tuple layout: (epoch, src_ip, protocol, tcp_flags, dst_port, frame_len)
    """
    entry = (
        pkt.get("epoch", 0.0),
        pkt.get("src_ip", ""),
        pkt.get("protocol", ""),
        pkt.get("tcp_flags", 0),
        pkt.get("dst_port", 0),
        pkt.get("frame_len", 0),
    )
    with _window_lock:
        _pkt_window.append(entry)


def compute_and_score() -> float:
    """
    Build the feature vector from the current window, run the Isolation Forest,
    update _current_score, and return it.

    Convention: returns 0.5 if model is absent.
    Called by the consumer thread every _SCORE_INTERVAL_SECONDS.
    """
    import time

    _load_model()

    now    = time.time()
    cutoff = now - _WINDOW_SECONDS

    with _window_lock:
        # Evict packets older than the window
        while _pkt_window and _pkt_window[0][0] < cutoff:
            _pkt_window.popleft()
        pkts = list(_pkt_window)

    n = len(pkts)
    if n == 0:
        features = [0.0] * len(FEATURE_NAMES)
    else:
        # Tuple layout: (epoch, src_ip, protocol, tcp_flags, dst_port, frame_len)
        syn_count  = 0
        ack_count  = 0
        rst_count  = 0
        fin_count  = 0
        icmp_count = 0
        udp_count  = 0
        total_bytes = 0
        dst_ports  = []
        src_ips    = []
        sizes      = []

        for epoch, src_ip, proto, flags, dport, flen in pkts:
            is_syn = bool(flags & _FLAG_SYN) and not bool(flags & _FLAG_ACK)
            is_ack = bool(flags & _FLAG_ACK)
            is_rst = bool(flags & _FLAG_RST)
            is_fin = bool(flags & _FLAG_FIN)
            if proto == "TCP":
                if is_syn:
                    syn_count += 1
                if is_ack:
                    ack_count += 1
                if is_rst:
                    rst_count += 1
                if is_fin:
                    fin_count += 1
            elif proto == "ICMP":
                icmp_count += 1
            elif proto == "UDP":
                udp_count += 1
            if dport > 0:
                dst_ports.append(dport)
            if src_ip:
                src_ips.append(src_ip)
            sizes.append(flen)
            total_bytes += flen

        avg_size = sum(sizes) / n
        size_std = math.sqrt(sum((s - avg_size) ** 2 for s in sizes) / n) if n > 1 else 0.0

        sa_denom = syn_count + ack_count
        syn_ack_ratio = syn_count / sa_denom if sa_denom > 0 else 0.0

        # Shannon entropy of destination port distribution
        def _entropy(vals: list) -> float:
            if not vals:
                return 0.0
            c = Counter(vals)
            tot = len(vals)
            return -sum((v / tot) * math.log2(v / tot) for v in c.values())

        features = [
            n           / _WINDOW_SECONDS,   # 0  total_rate
            syn_count   / _WINDOW_SECONDS,   # 1  syn_rate
            icmp_count  / _WINDOW_SECONDS,   # 2  icmp_rate
            udp_count   / _WINDOW_SECONDS,   # 3  udp_rate
            float(len(set(dst_ports))),       # 4  unique_dst_ports
            avg_size,                         # 5  avg_pkt_size
            ack_count   / _WINDOW_SECONDS,   # 6  ack_rate
            rst_count   / _WINDOW_SECONDS,   # 7  rst_rate
            fin_count   / _WINDOW_SECONDS,   # 8  fin_rate
            syn_ack_ratio,                    # 9  syn_ack_ratio
            size_std,                         # 10 pkt_size_std
            float(len(set(src_ips))),         # 11 unique_src_ips
            _entropy(dst_ports),              # 12 dst_port_entropy
            total_bytes / _WINDOW_SECONDS,   # 13 bytes_rate
        ]

    score = _score_features(features)

    # Update EMA baseline so behavioral analysis has a reference point
    update_baseline(features)

    with _score_lock:
        global _current_score
        _current_score = score

    return score


def get_anomaly_score() -> float:
    """Return the most recently computed anomaly score. Thread-safe read."""
    with _score_lock:
        return _current_score


def get_feature_vector() -> list:
    """
    Return the current feature vector without updating the score.
    Useful for diagnostics and the status endpoint.
    """
    import time
    now    = time.time()
    cutoff = now - _WINDOW_SECONDS

    with _window_lock:
        pkts = [
            (e, si, pr, fl, dp, fn)
            for (e, si, pr, fl, dp, fn) in _pkt_window
            if e >= cutoff
        ]

    n = len(pkts)
    if n == 0:
        return [0.0] * len(FEATURE_NAMES)

    syn_count = ack_count = rst_count = fin_count = 0
    icmp_count = udp_count = 0
    total_bytes = 0
    dst_ports: list = []
    src_ips: list = []
    sizes: list = []

    for epoch, src_ip, proto, flags, dport, flen in pkts:
        is_syn = bool(flags & _FLAG_SYN) and not bool(flags & _FLAG_ACK)
        if proto == "TCP":
            if is_syn:
                syn_count += 1
            if flags & _FLAG_ACK:
                ack_count += 1
            if flags & _FLAG_RST:
                rst_count += 1
            if flags & _FLAG_FIN:
                fin_count += 1
        elif proto == "ICMP":
            icmp_count += 1
        elif proto == "UDP":
            udp_count += 1
        if dport > 0:
            dst_ports.append(dport)
        if src_ip:
            src_ips.append(src_ip)
        sizes.append(flen)
        total_bytes += flen

    avg_size = sum(sizes) / n
    size_std = math.sqrt(sum((s - avg_size) ** 2 for s in sizes) / n) if n > 1 else 0.0
    sa_denom = syn_count + ack_count
    syn_ack_ratio = syn_count / sa_denom if sa_denom > 0 else 0.0

    def _entropy(vals: list) -> float:
        if not vals:
            return 0.0
        c = Counter(vals)
        tot = len(vals)
        return -sum((v / tot) * math.log2(v / tot) for v in c.values())

    return [
        round(n           / _WINDOW_SECONDS, 3),   # 0  total_rate
        round(syn_count   / _WINDOW_SECONDS, 3),   # 1  syn_rate
        round(icmp_count  / _WINDOW_SECONDS, 3),   # 2  icmp_rate
        round(udp_count   / _WINDOW_SECONDS, 3),   # 3  udp_rate
        float(len(set(dst_ports))),                 # 4  unique_dst_ports
        round(avg_size, 1),                         # 5  avg_pkt_size
        round(ack_count   / _WINDOW_SECONDS, 3),   # 6  ack_rate
        round(rst_count   / _WINDOW_SECONDS, 3),   # 7  rst_rate
        round(fin_count   / _WINDOW_SECONDS, 3),   # 8  fin_rate
        round(syn_ack_ratio, 3),                    # 9  syn_ack_ratio
        round(size_std, 1),                         # 10 pkt_size_std
        float(len(set(src_ips))),                   # 11 unique_src_ips
        round(_entropy(dst_ports), 3),              # 12 dst_port_entropy
        round(total_bytes / _WINDOW_SECONDS, 1),   # 13 bytes_rate
    ]


# ── EMA baseline functions ────────────────────────────────────────────────────

def update_baseline(features: list) -> None:
    """Update the per-feature EMA with the latest feature vector."""
    global _ema_state, _ema_count
    with _ema_lock:
        if not _ema_state:
            _ema_state = list(features)
        else:
            _ema_state = [
                _EMA_ALPHA * f + (1.0 - _EMA_ALPHA) * e
                for f, e in zip(features, _ema_state)
            ]
        _ema_count += 1


def get_deviating_features(features: list) -> list:
    """
    Return names of features whose current value exceeds
    _BEHAVIORAL_DEVIATION_RATIO × their EMA baseline.
    Returns [] if EMA is not warm yet.
    """
    with _ema_lock:
        if _ema_count < _EMA_MIN_OBS or not _ema_state:
            return []
        deviating = []
        for i, (f, e) in enumerate(zip(features, _ema_state)):
            if e == 0.0:
                if f > 1.0:   # anything above noise when baseline is zero
                    deviating.append(FEATURE_NAMES[i])
            elif f / e >= _BEHAVIORAL_DEVIATION_RATIO:
                deviating.append(FEATURE_NAMES[i])
        return deviating


def get_ema_status() -> dict:
    """Return EMA state for diagnostics / status endpoints."""
    with _ema_lock:
        return {
            "count":    _ema_count,
            "warm":     _ema_count >= _EMA_MIN_OBS,
            "baseline": [round(v, 3) for v in _ema_state] if _ema_state else [],
        }


def is_model_loaded() -> bool:
    """True once the Isolation Forest pipeline has been successfully loaded."""
    return _model is not None


def get_window_pkt_count() -> int:
    """Return the number of packets in the current 10-second scoring window."""
    import time
    now    = time.time()
    cutoff = now - _WINDOW_SECONDS
    with _window_lock:
        return sum(1 for (e, *_) in _pkt_window if e >= cutoff)


def score_feature_vector_direct(features: list) -> float:
    """
    Score a pre-computed feature vector directly through the Isolation Forest.
    Bypasses the packet window — intended for evaluation and testing only.

    Returns 0.5 (neutral) if the model is not loaded.
    """
    _load_model()
    return _score_features(features)


def reset_for_new_session() -> None:
    """Reset all in-session state: EMA baseline, behavioral cooldown, score, window."""
    global _ema_state, _ema_count, _behavioral_last_fired, _current_score
    with _ema_lock:
        _ema_state = []
        _ema_count = 0
    with _behavioral_lock:
        _behavioral_last_fired = 0.0
    with _score_lock:
        _current_score = 0.5
    with _window_lock:
        _pkt_window.clear()


def check_behavioral_alert(
    score: float,
    features: list,
    pkt_count: int,
    last_rule_epoch: float,
) -> tuple:
    """
    Multi-gate false-positive suppression for AI-BEHAVIORAL alerts.

    Gates (all must pass):
      1. IF anomaly score >= _BEHAVIORAL_SCORE_THRESH (0.55)
      2. At least _BEHAVIORAL_MIN_PACKETS (25) packets in the current window
      3. EMA is warm AND at least _BEHAVIORAL_MIN_DEVIATIONS (2) features deviate
      4. No rule-based alert fired in the last 30 seconds
      5. Global _BEHAVIORAL_COOLDOWN (60s) between consecutive behavioral alerts

    Returns: (should_fire: bool, reason: str, deviating_features: list)
    """
    import time as _t
    now = _t.time()

    if score < _BEHAVIORAL_SCORE_THRESH:
        return False, "", []

    if pkt_count < _BEHAVIORAL_MIN_PACKETS:
        return False, "", []

    deviating = get_deviating_features(features)
    if len(deviating) < _BEHAVIORAL_MIN_DEVIATIONS:
        return False, "", []

    if last_rule_epoch > 0 and (now - last_rule_epoch) < 30.0:
        return False, "", []

    with _behavioral_lock:
        global _behavioral_last_fired
        if now - _behavioral_last_fired < _BEHAVIORAL_COOLDOWN:
            return False, "", []
        _behavioral_last_fired = now

    reason = (
        f"IF score {score:.0%} | {len(deviating)} behavioral indicators: "
        + ", ".join(deviating)
    )
    return True, reason, deviating


# ── Behavioral alert classifier ───────────────────────────────────────────────
#
# Stage 2 of the AI pipeline — operates AFTER Isolation Forest confirms an anomaly.
#
# Design principle — separation of concerns:
#   Isolation Forest    →  DETECTION        (is this traffic anomalous?)
#   RF classifier       →  CLASSIFICATION   (what named attack does it match?)
#   EMA baseline        →  EXPLAINABILITY   (which features deviate and by how much?)
#
# The EMA layer does NOT guess attack names — that is the RF model's job.
# When RF is not loaded or falls below its confidence threshold, we return the
# generic suspicious label with the names of deviating features. This is more
# academically defensible than ratio-based heuristic naming.
#
# Output labels:
#   "Likely [Attack]"                — RF classifier matched with conf >= 0.70
#   "Suspicious Behavioral Traffic"  — IF confirmed anomaly, RF uncertain / absent

_SUSPICIOUS_LABEL = "Suspicious Behavioral Traffic"


def classify_behavioral_alert(features: list, score: float) -> tuple:
    """
    Classify a confirmed IF anomaly into a named behavioral pattern, or return
    a generic label if no pattern passes the confidence threshold.

    Called AFTER check_behavioral_alert() returns True (anomaly confirmed).
    This layer answers: "what *type* of anomaly is this?"

    Returns: (label: str, confidence: float, explanation: str)

    label:
      "Likely [Attack]"                — matched a known pattern with conf >= 0.5
      "Suspicious Behavioral Traffic"  — anomaly confirmed but unclassifiable

    confidence:
      0.0       → unclassified
      0.5–1.0   → proportional to how far above the minimum detection threshold

    explanation:
      Human-readable string for the alert detail field.
      Format: "<feature> Nx above baseline | [secondary] | IF score XX%"
    """
    # ── Layer 0: Supervised RF Classifier (trained on CICIDS2017-profiled data) ──
    # Tried first. Falls through transparently when:
    #   • model file not present (returns conf=0.0)
    #   • max predict_proba < CONFIDENCE_THRESHOLD (too uncertain)
    # The EMA-ratio rules below provide the fallback.
    if _HAS_RT_CLF and _rt_clf is not None:
        rf_label, rf_conf, rf_expl = _rt_clf.classify(features)
        if rf_label == "BENIGN" and rf_conf >= _rt_clf.CONFIDENCE_THRESHOLD:
            # IF gate fired but RF says traffic is normal → border noise.
            # Return empty label so the caller knows to suppress the alert entirely.
            # (Returning _SUSPICIOUS_LABEL here would fire an AI-UNKNOWN alert,
            # which contradicts the suppression intent and generates false positives.)
            return "", 0.0, rf_expl
        if rf_label and rf_conf >= _rt_clf.CONFIDENCE_THRESHOLD:
            # Confident attack classification from supervised model
            full_expl = rf_expl + f" | IF score {score:.0%}"
            return rf_label, rf_conf, full_expl
        # rf_conf == 0.0 or below threshold → fall through to EMA report

    with _ema_lock:
        if _ema_count < _EMA_MIN_OBS or not _ema_state:
            return _SUSPICIOUS_LABEL, 0.0, "EMA baseline not established"
        baseline = list(_ema_state)

    feat = dict(zip(FEATURE_NAMES, features))
    base = dict(zip(FEATURE_NAMES, baseline))

    def _r(name: str) -> float:
        """Feature / EMA ratio. Near-zero baseline → 10× scale."""
        b = base.get(name, 0.0)
        v = feat.get(name, 0.0)
        if b < 0.1:
            return v * 10.0 if v > 0.0 else 0.0
        return v / b

    syn_r   = _r("syn_rate")
    icmp_r  = _r("icmp_rate")
    udp_r   = _r("udp_rate")
    ack_r   = _r("ack_rate")
    rst_r   = _r("rst_rate")
    ports_r = _r("unique_dst_ports")
    total_r = _r("total_rate")

    # ── EMA fallback: report deviating features without guessing attack name ───
    # Named attack classification is the RF classifier's job.
    # The EMA layer only reports WHICH features deviate and by how much.
    # This is more honest: ratio-based heuristics cannot reliably distinguish
    # SYN Flood from Port Scan when working from baselines alone.
    elevated = [
        name for name, r in [
            ("syn_rate", syn_r), ("icmp_rate", icmp_r), ("udp_rate", udp_r),
            ("ack_rate", ack_r), ("rst_rate", rst_r),
            ("unique_dst_ports", ports_r), ("total_rate", total_r),
        ]
        if r >= 2.0
    ]
    expl = (
        f"IF score {score:.0%}"
        + (f" | elevated: {', '.join(elevated)}" if elevated else
           " | subtle multi-feature deviation — no dominant pattern")
    )
    return _SUSPICIOUS_LABEL, 0.0, expl


# ── Internal scoring ──────────────────────────────────────────────────────────

def _score_features(features: list) -> float:
    """
    Run the feature vector through the Isolation Forest pipeline.
    Returns a float in [0.0, 1.0]:
        decision_function() returns positive for inliers, negative for anomalies.
        We convert: anomaly_score = clamp(0.5 - raw_score, 0, 1)
        so high anomaly → score close to 1.0, normal traffic → score close to 0.0.
    """
    if _model is None:
        return 0.5   # neutral — model not loaded

    try:
        import numpy as np
        X   = np.array(features, dtype=float).reshape(1, -1)
        raw = float(_model.decision_function(X)[0])
        # decision_function typical range: [-0.5, +0.5]
        # clamp to [0, 1] after inversion
        score = max(0.0, min(1.0, 0.5 - raw))
        return round(score, 4)
    except Exception as exc:
        logger.error(f"[anomaly] Scoring error: {exc}")
        return 0.5
