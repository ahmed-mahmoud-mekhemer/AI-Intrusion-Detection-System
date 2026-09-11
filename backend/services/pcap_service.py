# backend/services/pcap_service.py
# ─────────────────────────────────────────────────────────────────────────────
# Handles all file ingestion and flow detection.
#
# Supported inputs:
#   CSV  (CICIDS2017 format)  → real ML predictions    ACTIVE
#   PCAP via CICFlowMeter     → real ML predictions    ACTIVE
#
# CICFlowMeter is invoked in headless CLI mode by targeting the hidden
# class cic.cs.unb.ca.ifm.Cmd directly (bypassing the GUI manifest entry).
#
# Runtime requirements for PCAP analysis:
#   tools/CICFlowMeter/CICFlowMeter.jar
#   tools/CICFlowMeter/jnetpcap.dll
#   tools/CICFlowMeter/jnetpcap-pcap100.dll
#   Npcap installed with WinPcap API-compatible mode enabled
# ─────────────────────────────────────────────────────────────────────────────
import os
import shutil
import subprocess
import uuid
from pathlib import Path
from datetime import datetime
from typing import List

import pandas as pd
import numpy as np

from backend.services.detection_service import detect_flows
from backend.models.result import DetectionResult
from backend.utils.logger import get_logger

logger = get_logger(__name__)


def get_packet_count(pcap_path: Path) -> int:
    """
    Returns the true packet count from a PCAP file using capinfos.

    capinfos reads file metadata only — no packet parsing, completes in ~200ms.
    Requires Wireshark to be installed (capinfos ships with Wireshark/tshark).

    Pure function — no side effects, no shared state. Thread-safe.
    Returns 0 on any failure; callers treat 0 as 'unavailable' (UI shows '—').
    """
    try:
        result = subprocess.run(
            ["capinfos", "-c", "-M", str(pcap_path)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        for line in result.stdout.splitlines():
            if "Number of packets" in line:
                return int(line.split(":")[-1].strip())
    except Exception:
        pass
    return 0


# ── Configuration ─────────────────────────────────────────────────────────────

# How many rows to sample per CSV upload (keeps the UI responsive).
# Raise this value to analyse more flows per file.
MAX_ROWS = 300

# CICFlowMeter paths — resolved relative to the project root at import time.
# Project root is two levels up from this file:
#   backend/services/pcap_service.py → backend/ → project_root/
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_CICFLOW_DIR = _PROJECT_ROOT / "tools" / "CICFlowMeter"
_CICFLOW_JAR = _CICFLOW_DIR / "CICFlowMeter.jar"
_CICFLOW_CLASS = "cic.cs.unb.ca.ifm.Cmd"
# seconds — large PCAPs (multi-day captures) need more time
_CICFLOW_TIMEOUT = 540

# Uploads temp directory — created if it doesn't exist.
_UPLOADS_DIR = _PROJECT_ROOT / "data" / "uploads"

# ── CICFlowMeter → CICIDS2017 column name mapping ────────────────────────────
# CICFlowMeter JAR output uses different names than the CICIDS2017 training CSVs.
# These are renamed before feature extraction so the trained model can find them.

_CICFLOWMETER_COLUMN_MAP = {
    # Packet counts
    "Total Fwd Packet":           "Total Fwd Packets",
    "Total Bwd packets":          "Total Backward Packets",
    # Packet length totals
    "Total Length of Fwd Packet": "Total Length of Fwd Packets",
    "Total Length of Bwd Packet": "Total Length of Bwd Packets",
    # Min/max packet length (reversed word order)
    "Packet Length Min":          "Min Packet Length",
    "Packet Length Max":          "Max Packet Length",
    # Flag name difference (CWR vs CWE)
    "CWR Flag Count":             "CWE Flag Count",
    # Segment size averages
    "Fwd Segment Size Avg":       "Avg Fwd Segment Size",
    "Bwd Segment Size Avg":       "Avg Bwd Segment Size",
    # Bulk rate columns
    "Fwd Bytes/Bulk Avg":         "Fwd Avg Bytes/Bulk",
    "Fwd Packet/Bulk Avg":        "Fwd Avg Packets/Bulk",
    "Fwd Bulk Rate Avg":          "Fwd Avg Bulk Rate",
    "Bwd Bytes/Bulk Avg":         "Bwd Avg Bytes/Bulk",
    "Bwd Packet/Bulk Avg":        "Bwd Avg Packets/Bulk",
    "Bwd Bulk Rate Avg":          "Bwd Avg Bulk Rate",
    # Window / segment size columns
    "FWD Init Win Bytes":         "Init_Win_bytes_forward",
    "Bwd Init Win Bytes":         "Init_Win_bytes_backward",
    "Fwd Act Data Pkts":          "act_data_pkt_fwd",
    "Fwd Seg Size Min":           "min_seg_size_forward",
}

# ── Metadata column sets ──────────────────────────────────────────────────────

_STRING_COLS = {
    "Flow ID", "Source IP", "Destination IP",
    "Src IP", "Dst IP",
    "Protocol", "Timestamp", "Label",
}

_SRC_IP_KEYS    = ["Source IP",        "Src IP",   "src_ip"]
_DST_IP_KEYS    = ["Destination IP",   "Dst IP",   "dst_ip"]
_SRC_PORT_KEYS  = ["Source Port",      "Src Port", "src_port"]
_DST_PORT_KEYS  = ["Destination Port", "Dst Port", "dst_port"]
_PROTOCOL_KEYS  = ["Protocol",         "protocol"]
_TIMESTAMP_KEYS = ["Timestamp",        "timestamp"]


# ── Public API ────────────────────────────────────────────────────────────────

def analyze_pcap(pcap_path: Path) -> List[DetectionResult]:
    """
    Analyse a PCAP file using CICFlowMeter in headless CLI mode.

    Pipeline:
        PCAP → CICFlowMeter (Cmd class, no GUI) → CSV → analyze_csv() → results

    Raises:
        FileNotFoundError  — if the PCAP file does not exist
        RuntimeError       — if Java is missing, JAR is missing, DLLs are missing,
                             CICFlowMeter fails, or no CSV is produced
    """
    logger.info(f"PCAP analysis started: {pcap_path.name}")

    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    # Pre-flight checks before touching the filesystem
    _check_java()
    _check_cicflowmeter_setup()

    # Create an isolated temp session so concurrent uploads never collide
    session_id = uuid.uuid4().hex[:10]
    tmp_root   = _UPLOADS_DIR / f"pcap_{session_id}"
    input_dir  = tmp_root / "input"
    output_dir = tmp_root / "output"
    input_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)

    # CICFlowMeter scans the entire input directory — copy the PCAP in
    staged_pcap = input_dir / pcap_path.name
    shutil.copy2(pcap_path, staged_pcap)
    logger.info(f"  PCAP staged to: {staged_pcap}")

    try:
        csv_path = _run_cicflowmeter(input_dir, output_dir)
        logger.info(f"  CICFlowMeter output: {csv_path.name}")
        results = analyze_csv(csv_path)
        logger.info(f"  PCAP analysis complete: {len(results)} flows")
        return results
    finally:
        # Always clean up temp files, even if an exception is raised
        _cleanup(tmp_root)


def analyze_csv(csv_path: Path) -> List[DetectionResult]:
    """
    Load a CICIDS2017-format CSV and run real ML detection on each row.

    Handles:
    - Missing IP/port/protocol/timestamp columns → default to 'N/A' / 0
    - Numeric features with inf/NaN             → replaced with 0
    - String metadata columns                   → never filled with 0
    - Large files                               → sampled to MAX_ROWS
    """
    logger.info(f"Analyzing CSV: {csv_path.name}")

    if not csv_path.exists():
        raise FileNotFoundError(f"CSV file not found: {csv_path}")

    df = pd.read_csv(csv_path, low_memory=False)
    df.columns = df.columns.str.strip()
    df.rename(columns=_CICFLOWMETER_COLUMN_MAP, inplace=True)

    if df.empty:
        logger.warning("CSV is empty — no flows to analyse.")
        return []

    # Log which metadata columns are genuinely absent in this file
    missing_meta = [
        c for c in ["Source IP", "Destination IP", "Protocol", "Timestamp"]
        if c not in df.columns
    ]
    if missing_meta:
        logger.info(
            f"  Metadata columns absent (N/A defaults will be used): {missing_meta}")

    # Clean numeric columns only — string/IP columns must NOT be filled with 0
    numeric_cols = [c for c in df.columns if c not in _STRING_COLS]
    string_cols  = [c for c in df.columns if c in _STRING_COLS]
    df[numeric_cols] = (
        df[numeric_cols]
        .replace([np.inf, -np.inf], np.nan)
        .fillna(0)
    )
    df[string_cols] = df[string_cols].fillna("")

    # Stratified sample if the file is larger than MAX_ROWS.
    # Guarantees every attack class present in the file gets at least some rows
    # in the sample — a pure random sample would bury rare classes (e.g. Heartbleed)
    # under the dominant BENIGN majority.
    if len(df) > MAX_ROWS:
        logger.info(
            f"  Stratified sampling {MAX_ROWS} rows from {len(df):,} total.")
        if "Label" in df.columns:
            label_counts    = df["Label"].value_counts()
            n_classes       = len(label_counts)
            floor_per_class = max(1, MAX_ROWS // (n_classes * 2))
            sampled_parts   = []
            remaining_quota = MAX_ROWS

            for label, count in label_counts.items():
                n    = min(floor_per_class, count)
                part = df[df["Label"] == label].sample(n=n, random_state=42)
                sampled_parts.append(part)
                remaining_quota -= n

            if remaining_quota > 0:
                leftover = df.drop(
                    index=pd.concat(sampled_parts).index, errors="ignore")
                if len(leftover) > 0:
                    n_extra = min(remaining_quota, len(leftover))
                    sampled_parts.append(
                        leftover.sample(n=n_extra, random_state=42))

            df = pd.concat(sampled_parts).sample(
                frac=1, random_state=42).reset_index(drop=True)
        else:
            # No Label column (CICFlowMeter PCAP output) — plain random sample
            df = df.sample(n=MAX_ROWS, random_state=42).reset_index(drop=True)

    logger.info(f"  Processing {len(df)} rows ...")

    # Build one flow dict per row — predictor picks feature columns by name
    flows = []
    for _, row in df.iterrows():
        raw  = row.to_dict()
        flow = dict(raw)
        flow["flow_id"]   = str(uuid.uuid4())
        flow["src_ip"]    = _get_str(raw, _SRC_IP_KEYS,    "N/A")
        flow["dst_ip"]    = _get_str(raw, _DST_IP_KEYS,    "N/A")
        flow["src_port"]  = _get_int(raw, _SRC_PORT_KEYS,  0)
        flow["dst_port"]  = _get_int(raw, _DST_PORT_KEYS,  0)
        flow["protocol"]  = _get_str(raw, _PROTOCOL_KEYS,  "N/A")
        flow["timestamp"] = _get_str(
            raw, _TIMESTAMP_KEYS,
            default=datetime.now().isoformat(),
        )
        flows.append(flow)

    results = detect_flows(flows)
    logger.info(f"  Detection complete — {len(results)} results.")
    return results


# ── Pre-flight checks ─────────────────────────────────────────────────────────

def _check_java() -> None:
    """Verify Java is installed and accessible on the system PATH."""
    try:
        result = subprocess.run(
            ["java", "-version"],
            capture_output=True,
            timeout=10,
        )
        version_line = (result.stderr or result.stdout).decode(
            errors="replace").splitlines()
        version_str = version_line[0] if version_line else "(unknown)"
        logger.debug(f"Java detected: {version_str}")
    except FileNotFoundError:
        raise RuntimeError(
            "Java is not installed or not on the system PATH.\n"
            "Install Java 11 from https://adoptium.net/ and restart the backend."
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(
            "Java version check timed out. Java may be misconfigured.")


def _check_cicflowmeter_setup() -> None:
    """
    Verify that the CICFlowMeter JAR and required native DLLs are present.
    Does NOT verify Npcap installation (that failure surfaces at subprocess time).
    """
    if not _CICFLOW_JAR.exists():
        raise RuntimeError(
            f"CICFlowMeter JAR not found: {_CICFLOW_JAR}\n"
            "Build CICFlowMeter and place the JAR at: tools/CICFlowMeter/CICFlowMeter.jar\n"
            "Also place jnetpcap.dll and jnetpcap-pcap100.dll in the same folder."
        )

    required_dlls = ["jnetpcap.dll", "jnetpcap-pcap100.dll"]
    missing_dlls  = [dll for dll in required_dlls
                     if not (_CICFLOW_DIR / dll).exists()]
    if missing_dlls:
        raise RuntimeError(
            f"Required native DLLs missing from {_CICFLOW_DIR}: {missing_dlls}\n"
            "Extract them from the jnetpcap Windows distribution and place them\n"
            "in tools/CICFlowMeter/ alongside CICFlowMeter.jar."
        )


# ── CICFlowMeter subprocess ───────────────────────────────────────────────────

def _run_cicflowmeter(input_dir: Path, output_dir: Path) -> Path:
    """
    Invoke CICFlowMeter in headless CLI mode using the hidden Cmd class.

    The JAR manifest points to the GUI App class, so we bypass it with -cp
    and target cic.cs.unb.ca.ifm.Cmd directly.  This is the only reliable
    way to run CICFlowMeter without a display.

    Command structure:
        java
          -Djava.library.path=<absolute tools/CICFlowMeter dir>
          -cp <absolute CICFlowMeter.jar>
          cic.cs.unb.ca.ifm.Cmd
          <absolute input_dir>
          <absolute output_dir>

    Returns:
        Path to the generated CSV file (largest .csv in output_dir).

    Raises:
        RuntimeError on non-zero exit, timeout, or missing output.
    """
    jar_abs    = _CICFLOW_JAR.resolve()
    dll_dir    = _CICFLOW_DIR.resolve()
    input_abs  = input_dir.resolve()
    output_abs = output_dir.resolve()

    cmd = [
        "java",
        f"-Djava.library.path={dll_dir}",
        "-cp", str(jar_abs),
        _CICFLOW_CLASS,
        str(input_abs),
        str(output_abs),
    ]

    logger.info(f"Running CICFlowMeter (headless): {' '.join(cmd)}")

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=_CICFLOW_TIMEOUT,
            cwd=str(dll_dir),
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(
            f"CICFlowMeter timed out after {_CICFLOW_TIMEOUT}s.\n"
            "The PCAP file may be too large. "
            "Increase _CICFLOW_TIMEOUT in pcap_service.py or use a smaller file."
        )

    stdout = proc.stdout.decode(errors="replace").strip()
    stderr = proc.stderr.decode(errors="replace").strip()
    if stdout:
        logger.debug(f"CICFlowMeter stdout:\n{stdout}")
    if stderr:
        logger.debug(f"CICFlowMeter stderr:\n{stderr}")

    if proc.returncode != 0:
        raise RuntimeError(
            f"CICFlowMeter exited with code {proc.returncode}.\n"
            f"stdout: {stdout[:400]}\n"
            f"stderr: {stderr[:400]}\n\n"
            "Common causes:\n"
            "  - Npcap not installed or WinPcap compatibility mode not enabled\n"
            "  - jnetpcap.dll or jnetpcap-pcap100.dll missing from tools/CICFlowMeter/\n"
            "  - PCAP file is corrupted or in an unsupported format"
        )

    return _find_output_csv(output_abs)


def _find_output_csv(output_dir: Path) -> Path:
    """
    Find the CSV file CICFlowMeter wrote to output_dir.
    Returns the largest .csv if multiple exist (shouldn't happen with one PCAP).

    Raises RuntimeError if no CSV is found or the file is empty.
    """
    csv_files = list(output_dir.glob("*.csv"))

    if not csv_files:
        raise RuntimeError(
            f"CICFlowMeter ran successfully (exit 0) but produced no CSV in:\n"
            f"  {output_dir}\n\n"
            "Possible causes:\n"
            "  - PCAP contains no complete TCP/UDP bidirectional flows\n"
            "    (e.g. ARP-only traffic, single-packet flows, broadcast only)\n"
            "  - PCAP file is valid but too short to form complete flows\n"
            "  - CICFlowMeter version incompatibility with this PCAP format\n"
            "Try opening the PCAP in Wireshark to verify it has TCP/UDP flows."
        )

    if len(csv_files) > 1:
        logger.warning(
            f"{len(csv_files)} CSV files found in output — using the largest: "
            f"{sorted(csv_files, key=lambda p: p.stat().st_size, reverse=True)[0].name}"
        )

    csv_path = max(csv_files, key=lambda p: p.stat().st_size)

    try:
        sample = pd.read_csv(csv_path, nrows=2)
        if sample.empty:
            raise RuntimeError(
                f"CICFlowMeter produced an empty CSV (header only): {csv_path.name}\n"
                "The PCAP has no complete bidirectional flows."
            )
    except Exception as e:
        raise RuntimeError(f"Failed to read CICFlowMeter output CSV: {e}")

    logger.info(
        f"  CSV validated: {csv_path.name} ({csv_path.stat().st_size:,} bytes)")
    return csv_path


# ── Utility helpers ───────────────────────────────────────────────────────────

def _cleanup(tmp_root: Path) -> None:
    """Silently remove the temporary session directory and all its contents."""
    try:
        if tmp_root.exists():
            shutil.rmtree(tmp_root)
            logger.debug(f"Cleaned up temp dir: {tmp_root}")
    except Exception as e:
        logger.warning(f"Failed to clean up temp dir '{tmp_root}': {e}")


def _get_str(row: dict, keys: list, default: str) -> str:
    """Return the first non-empty string value found among the given keys."""
    for key in keys:
        val = row.get(key)
        if val is not None and str(val).strip() not in ("", "nan", "0", "0.0"):
            return str(val).strip()
    return default


def _get_int(row: dict, keys: list, default: int = 0) -> int:
    """Return the first valid integer found among the given keys."""
    for key in keys:
        val = row.get(key)
        if val is not None:
            try:
                return int(float(val))
            except (ValueError, TypeError):
                continue
    return default
