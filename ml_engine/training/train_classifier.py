# ml_engine/training/train_classifier.py
# ─────────────────────────────────────────────────────────────────────────────
# Full IDS Training Pipeline — Multi-class RF + Isolation Forest
# Run from project root: python -m ml_engine.training.train_classifier
# ─────────────────────────────────────────────────────────────────────────────
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import glob
import numpy as np
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import classification_report

import logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s — %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("train_full_ids")

DATA_DIR   = Path("data/cicids2017")
MODELS_DIR = Path("data/models")

NON_FEATURE_COLS = {
    "Flow ID", "Source IP", "Source Port", "Destination IP",
    "Destination Port", "Protocol", "Timestamp", "Label",
    "Src IP", "Dst IP", "Src Port", "Dst Port",
}

# ── Label normalization ───────────────────────────────────────────────────────
# Covers UTF-8 and Windows-1252 (latin-1) encodings of the dash character.
LABEL_MAP = {
    "BENIGN":                              "BENIGN",
    "Benign":                              "BENIGN",
    # DDoS / DoS
    "DDoS":                                "DDoS",
    "DoS Hulk":                            "DoS Hulk",
    "DoS GoldenEye":                       "DoS GoldenEye",
    "DoS slowloris":                       "DoS slowloris",
    "DoS Slowhttptest":                    "DoS Slowhttptest",
    # Patator
    "FTP-Patator":                         "FTP-Patator",
    "SSH-Patator":                         "SSH-Patator",
    # PortScan
    "PortScan":                            "PortScan",
    "Port Scan":                           "PortScan",
    # Bot / Infiltration / Heartbleed
    "Bot":                                 "Bot",
    "Infiltration":                        "Infiltration",
    "Heartbleed":                          "Heartbleed",
    # Web Attacks — UTF-8 em-dash
    "Web Attack \u2013 Brute Force":       "Web Attack-Brute Force",
    "Web Attack \u2014 Brute Force":       "Web Attack-Brute Force",
    "Web Attack – Brute Force":            "Web Attack-Brute Force",
    "Web Attack - Brute Force":            "Web Attack-Brute Force",
    "Web Attack \u2013 XSS":              "Web Attack-XSS",
    "Web Attack \u2014 XSS":              "Web Attack-XSS",
    "Web Attack – XSS":                   "Web Attack-XSS",
    "Web Attack - XSS":                   "Web Attack-XSS",
    "Web Attack \u2013 Sql Injection":    "Web Attack-SQL Injection",
    "Web Attack \u2014 Sql Injection":    "Web Attack-SQL Injection",
    "Web Attack – Sql Injection":         "Web Attack-SQL Injection",
    "Web Attack - Sql Injection":         "Web Attack-SQL Injection",
    # Windows-1252 replacement character variants (shows as \ufffd or \x96)
    "Web Attack \x96 Brute Force":        "Web Attack-Brute Force",
    "Web Attack \ufffd Brute Force":      "Web Attack-Brute Force",
    "Web Attack \x96 XSS":               "Web Attack-XSS",
    "Web Attack \ufffd XSS":             "Web Attack-XSS",
    "Web Attack \x96 Sql Injection":     "Web Attack-SQL Injection",
    "Web Attack \ufffd Sql Injection":   "Web Attack-SQL Injection",
}

# Classes with very few samples — require higher confidence at inference time.
# Bot has high recall but terrible precision (lots of false positives).
# These are flagged in the saved model for the predictor to apply stricter thresholds.
HIGH_UNCERTAINTY_CLASSES = {
    "Bot":                    0.90,   # only reliable above 90% confidence
    "Infiltration":           0.85,
    "Heartbleed":             0.85,
    "Web Attack-XSS":         0.80,
    "Web Attack-SQL Injection": 0.85,
}


def normalize_label(raw: str) -> str:
    cleaned = str(raw).strip()
    return LABEL_MAP.get(cleaned, cleaned)


def load_and_merge_csvs() -> pd.DataFrame:
    csv_files = sorted(glob.glob(str(DATA_DIR / "*.csv")))
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in {DATA_DIR.resolve()}")

    frames = []
    for path in csv_files:
        name = Path(path).name
        # Try UTF-8 first, fall back to latin-1 (covers Windows-1252 dash characters)
        for encoding in ("utf-8", "latin-1"):
            try:
                df = pd.read_csv(path, low_memory=False, encoding=encoding)
                df.columns = df.columns.str.strip()
                logger.info(f"  Loaded {name}: {len(df):,} rows  [{encoding}]")
                frames.append(df)
                break
            except UnicodeDecodeError:
                continue
            except Exception as e:
                logger.warning(f"  Skipping {name}: {e}")
                break

    combined = pd.concat(frames, ignore_index=True)
    logger.info(f"  Total rows: {len(combined):,}")
    return combined


def clean(df: pd.DataFrame) -> pd.DataFrame:
    if "Label" not in df.columns:
        raise ValueError("No 'Label' column found after merging.")

    df["Label"] = df["Label"].apply(normalize_label)
    df = df[df["Label"].notna() & (df["Label"].str.strip() != "")]

    string_cols  = [c for c in df.columns if c in NON_FEATURE_COLS]
    numeric_cols = [c for c in df.columns if c not in NON_FEATURE_COLS]

    df[numeric_cols] = (
        df[numeric_cols]
        .apply(pd.to_numeric, errors="coerce")
        .replace([np.inf, -np.inf], np.nan)
        .fillna(0)
    )
    return df


def select_features(df: pd.DataFrame):
    feature_cols = [c for c in df.columns if c not in NON_FEATURE_COLS]
    X = df[feature_cols].astype(np.float32)
    y = df["Label"]
    return X, y, feature_cols


def main():
    logger.info("=" * 60)
    logger.info("  Full IDS Training Pipeline")
    logger.info("=" * 60)

    # ── 1. Load ────────────────────────────────────────────────────────────────
    logger.info("Step 1: Loading CSV files …")
    df = load_and_merge_csvs()

    # ── 2. Clean ───────────────────────────────────────────────────────────────
    logger.info("Step 2: Cleaning …")
    df = clean(df)

    # ── 3. Label distribution ──────────────────────────────────────────────────
    logger.info("Step 3: Label distribution:")
    for label, count in df["Label"].value_counts().items():
        logger.info(f"    {label:<45} {count:>8,}  ({count/len(df)*100:.1f}%)")

    # Warn about labels that didn't get normalized (encoding issues)
    unrecognized = [l for l in df["Label"].unique()
                    if l not in LABEL_MAP.values() and l != "BENIGN"]
    if unrecognized:
        logger.warning(f"  Unrecognized labels (will train as-is): {unrecognized}")

    # ── 4. Features ────────────────────────────────────────────────────────────
    logger.info("Step 4: Selecting features …")
    X, y, feature_names = select_features(df)
    logger.info(f"  Feature count: {len(feature_names)}")

    # ── 5. Scale ───────────────────────────────────────────────────────────────
    logger.info("Step 5: Fitting StandardScaler …")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X.values)

    # ── 6. Split ───────────────────────────────────────────────────────────────
    logger.info("Step 6: Train/test split (80/20 stratified) …")
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.2, random_state=42, stratify=y
    )
    logger.info(f"  Train: {len(X_train):,}  |  Test: {len(X_test):,}")

    # ── 7. Train classifier ────────────────────────────────────────────────────
    logger.info("Step 7: Training Random Forest …")
    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=25,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)
    logger.info("Classifier training complete.")

    y_pred = clf.predict(X_test)
    print("\n=== CLASSIFIER REPORT ===")
    print(classification_report(y_test, y_pred, zero_division=0))

    # ── 8. Train anomaly detector ──────────────────────────────────────────────
    logger.info("Step 8: Training Isolation Forest on BENIGN samples …")
    benign_mask = (y == "BENIGN").values
    iso = IsolationForest(
        n_estimators=200,
        contamination=0.01,
        random_state=42,
        n_jobs=-1,
    )
    iso.fit(X_scaled[benign_mask])
    logger.info(f"  Isolation Forest trained. offset_: {iso.offset_:.4f}")

    # ── 9. Save ────────────────────────────────────────────────────────────────
    logger.info("Step 9: Saving models …")
    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    joblib.dump(
        {
            "model":                   clf,
            "feature_names":           feature_names,
            "high_uncertainty_classes": HIGH_UNCERTAINTY_CLASSES,
        },
        MODELS_DIR / "classifier_model.joblib"
    )

    joblib.dump(
        {"model": iso, "feature_names": feature_names},
        MODELS_DIR / "anomaly_model.joblib"
    )

    joblib.dump(
        {"scaler": scaler, "feature_names": feature_names},
        MODELS_DIR / "scaler.joblib"
    )

    logger.info(f"  Classes: {list(clf.classes_)}")
    logger.info("=" * 60)
    logger.info("  All 3 models saved successfully.")
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
