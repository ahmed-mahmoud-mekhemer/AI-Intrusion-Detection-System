# backend/services/capture_service.py
# ─────────────────────────────────────────────────────────────────────────────
# Live packet capture using tshark (Wireshark CLI).
#
# Exposes three public functions consumed by the /realtime router:
#   start_capture(interface, duration)  → kicks off background capture thread
#   stop_capture()                      → signals early stop
#   get_capture_status()                → returns current state + latest results
#
# Pipeline reuse: each chunk PCAP is fed directly into the existing
#   pcap_service.analyze_pcap() → detect_flows() chain.
#
# Runtime requirements:
#   - Wireshark (tshark) installed; tshark.exe on PATH or in default location
#   - Npcap installed with WinPcap API-compatible mode enabled
#   - Process must have sufficient privileges to capture on the interface
# ─────────────────────────────────────────────────────────────────────────────
import queue
import shutil
import subprocess
import tempfile
import threading
import time as _time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from backend.utils.logger import get_logger

logger = get_logger(__name__)

# ── tshark discovery ──────────────────────────────────────────────────────────

_TSHARK_CANDIDATES = [
    "tshark",
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
]

DEFAULT_INTERFACE = "Wi-Fi"   # confirmed active interface (tshark -D index 4)
DEFAULT_DURATION  = 15        # seconds
_CHUNK_SIZE       = 5         # seconds per capture chunk; internal only


def _find_tshark() -> str:
    for candidate in _TSHARK_CANDIDATES:
        if shutil.which(candidate) or Path(candidate).exists():
            return candidate
    raise RuntimeError(
        "tshark not found. Install Wireshark from https://www.wireshark.org/download.html "
        "and ensure tshark.exe is on the system PATH. "
        "Also confirm Npcap is installed with WinPcap API-compatible mode enabled."
    )


# ── Session state ─────────────────────────────────────────────────────────────

@dataclass
class _CaptureState:
    running:      bool        = False
    interface:    str         = ""
    duration:     int         = 0
    started_at:   str         = ""
    error:        str | None  = None
    results:      list[Any]   = field(default_factory=list)
    chunks_done:  int         = 0
    total_chunks: int         = 0


_state      = _CaptureState()
_state_lock = threading.Lock()
_stop_event = threading.Event()


# ── Internal capture + analysis worker ───────────────────────────────────────

def _capture_worker(interface: str, duration: int, chunk_size: int) -> None:
    """
    Runs in a background thread.
    Producer/consumer pipeline:
      - Producer thread: tshark captures successive chunks, pushes PCAP paths to queue
      - Consumer (this thread): pulls PCAP paths, runs analyze_pcap, appends results
    While chunk N is being analysed, chunk N+1 is already capturing.
    Reduces per-chunk wall time from (tshark + analyze) to max(tshark, analyze).
    """
    tshark = _find_tshark()
    from backend.services.pcap_service import analyze_pcap

    total_chunks = -(-duration // chunk_size)   # ceiling division
    pcap_queue   = queue.Queue()                 # transfers (Path|"empty", index) | None

    with _state_lock:
        _state.total_chunks = total_chunks

    logger.info(
        f"[capture] Starting pipelined chunked capture: interface={interface!r} "
        f"duration={duration}s chunk_size={chunk_size}s total_chunks={total_chunks}"
    )

    # ── Producer: runs tshark for each chunk, enqueues PCAP paths ────────────

    def _producer() -> None:
        elapsed     = 0
        chunk_index = 0

        while elapsed < duration:
            if _stop_event.is_set():
                logger.info("[capture/producer] Stop event — exiting.")
                break

            chunk_duration = min(chunk_size, duration - elapsed)
            chunk_index   += 1
            _t0            = _time.perf_counter()

            pcap_path = (
                Path(tempfile.gettempdir())
                / f"ids_chunk_{interface.replace(' ', '_')}_{chunk_index}.pcap"
            )

            logger.info(
                f"[capture/producer] Chunk {chunk_index}/{total_chunks} START: "
                f"duration={chunk_duration}s elapsed_so_far={elapsed}s"
            )

            cmd = [
                tshark,
                "-i", interface,
                "-a", f"duration:{chunk_duration}",
                "-w", str(pcap_path),
                "-q",
            ]

            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    timeout=chunk_duration + 30,
                )
            except FileNotFoundError:
                _set_error(f"tshark not found at: {tshark}")
                pcap_queue.put(None)
                return
            except subprocess.TimeoutExpired:
                _set_error(f"tshark hung on chunk {chunk_index} — timed out.")
                pcap_queue.put(None)
                return

            _tshark_elapsed = _time.perf_counter() - _t0
            pcap_size       = pcap_path.stat().st_size if pcap_path.exists() else 0
            logger.info(
                f"[capture/producer] Chunk {chunk_index} tshark done in "
                f"{_tshark_elapsed:.2f}s — pcap_size={pcap_size}B "
                f"returncode={proc.returncode}"
            )

            stderr = proc.stderr.decode(errors="replace").strip()

            if proc.returncode != 0:
                if "permission" in stderr.lower() or "access" in stderr.lower():
                    _set_error(
                        f"Permission denied on interface {interface!r}. "
                        "Run the backend as Administrator or enable non-admin capture in Npcap."
                    )
                else:
                    _set_error(
                        f"tshark error on chunk {chunk_index} "
                        f"(code {proc.returncode}): {stderr[:400]}"
                    )
                pcap_queue.put(None)
                return

            if not pcap_path.exists() or pcap_path.stat().st_size == 0:
                logger.warning(
                    f"[capture/producer] Chunk {chunk_index}: no output — "
                    "no traffic or wrong interface name."
                )
                # Push sentinel so consumer stays in sync with chunk count
                pcap_queue.put(("empty", chunk_index))
            else:
                pcap_queue.put((pcap_path, chunk_index))

            elapsed += chunk_duration

        # Signal consumer that production is done
        pcap_queue.put(None)
        logger.info("[capture/producer] All chunks captured — sentinel sent.")

    # ── Start producer in its own thread ─────────────────────────────────────

    producer_thread = threading.Thread(
        target=_producer,
        daemon=True,
        name="ids-capture-producer",
    )
    producer_thread.start()

    # ── Consumer: pulls from queue, runs analysis, appends results ────────────

    while True:
        item = pcap_queue.get()

        # None = producer finished or fatal error occurred
        if item is None:
            logger.info("[capture/consumer] Sentinel received — done.")
            break

        pcap_path, chunk_index = item
        _t0 = _time.perf_counter()

        if pcap_path == "empty":
            logger.info(
                f"[capture/consumer] Chunk {chunk_index}: skipping empty PCAP."
            )
            with _state_lock:
                _state.chunks_done = chunk_index
            continue

        size_kb = pcap_path.stat().st_size / 1024
        logger.info(
            f"[capture/consumer] Chunk {chunk_index} analyze_pcap START: "
            f"{size_kb:.1f} KB"
        )

        try:
            chunk_results = analyze_pcap(pcap_path)
            _analysis_elapsed = _time.perf_counter() - _t0
            logger.info(
                f"[capture/consumer] Chunk {chunk_index} analyze_pcap done in "
                f"{_analysis_elapsed:.2f}s — flows={len(chunk_results)}"
            )
        except RuntimeError as exc:
            _analysis_elapsed = _time.perf_counter() - _t0
            logger.warning(
                f"[capture/consumer] Chunk {chunk_index} no flows after "
                f"{_analysis_elapsed:.2f}s: {exc}"
            )
            chunk_results = []
        except Exception as exc:
            _set_error(f"Analysis pipeline failed on chunk {chunk_index}: {exc}")
            # Drain producer before exiting so its thread does not block
            producer_thread.join(timeout=60)
            return
        finally:
            try:
                pcap_path.unlink(missing_ok=True)
            except Exception:
                pass

        if chunk_results:
            new_rows = [
                r.dict() if hasattr(r, "dict") else r
                for r in chunk_results
            ]
            with _state_lock:
                _state.results.extend(new_rows)
                total_so_far = len(_state.results)

            attacks = sum(1 for r in new_rows if r.get("label") != "BENIGN")
            logger.info(
                f"[capture/consumer] Chunk {chunk_index} appended {len(new_rows)} rows "
                f"({attacks} threats) — total _state.results={total_so_far}"
            )
        else:
            with _state_lock:
                total_so_far = len(_state.results)
            logger.info(
                f"[capture/consumer] Chunk {chunk_index} done: 0 flows — "
                f"total _state.results={total_so_far}"
            )

        with _state_lock:
            _state.chunks_done = chunk_index

    # ── Wait for producer to fully exit before marking session done ───────────
    producer_thread.join(timeout=60)

    with _state_lock:
        _state.running = False

    total   = len(_state.results)
    attacks = sum(1 for r in _state.results if r.get("label") != "BENIGN")
    logger.info(
        f"[capture] Session complete — {total} flows total, {attacks} threats detected."
    )


def _set_error(msg: str) -> None:
    with _state_lock:
        _state.running = False
        _state.error   = msg
    logger.error(f"[capture] {msg}")


# ── Public API ────────────────────────────────────────────────────────────────

def start_capture(interface: str = DEFAULT_INTERFACE, duration: int = DEFAULT_DURATION) -> dict:
    """
    Start a background chunked capture + analysis session.
    Returns immediately; poll get_capture_status() for progress and results.
    """
    with _state_lock:
        if _state.running:
            return {"status": "already_running", "interface": _state.interface}

        _state.running       = True
        _state.interface     = interface
        _state.duration      = duration
        _state.started_at    = datetime.utcnow().isoformat()
        _state.error         = None
        _state.results       = []
        _state.chunks_done   = 0
        _state.total_chunks  = 0

    _stop_event.clear()

    threading.Thread(
        target=_capture_worker,
        args=(interface, duration, _CHUNK_SIZE),
        daemon=True,
        name="ids-capture",
    ).start()

    logger.info(
        f"[capture] Session started: interface={interface!r}, duration={duration}s, "
        f"chunk_size={_CHUNK_SIZE}s"
    )
    return {
        "status":     "started",
        "interface":  interface,
        "duration":   duration,
        "started_at": _state.started_at,
    }


def stop_capture() -> dict:
    """
    Signal the chunk loop to stop after the current tshark chunk completes.
    Any results already appended remain available via get_capture_status().
    Stop is not immediate — tshark runs to the end of its current chunk window.
    """
    with _state_lock:
        if not _state.running:
            return {"status": "not_running"}
        _state.running = False

    _stop_event.set()
    logger.info("[capture] Stop requested by user.")
    return {"status": "stopped"}


def get_capture_status() -> dict:
    """
    Return current capture state + all detection results accumulated so far.
    Frontend polls this every ~2 seconds from the Real-Time screen.
    chunks_done / total_chunks available for optional progress display.
    """
    with _state_lock:
        return {
            "running":      _state.running,
            "interface":    _state.interface,
            "duration":     _state.duration,
            "started_at":   _state.started_at,
            "error":        _state.error,
            "result_count": len(_state.results),
            "results":      list(_state.results),
            "chunks_done":  _state.chunks_done,
            "total_chunks": _state.total_chunks,
        }


# ── Blocking capture (used standalone / by PCAP analysis screen) ─────────────

def capture_live_traffic(
    interface:  str         = DEFAULT_INTERFACE,
    duration:   int         = DEFAULT_DURATION,
    output_dir: Path | None = None,
) -> Path:
    """
    Blocking capture: runs tshark for `duration` seconds and returns the PCAP path.
    Caller is responsible for threading if needed.
    """
    tshark  = _find_tshark()
    out_dir = Path(output_dir) if output_dir else Path(tempfile.gettempdir())
    out_dir.mkdir(parents=True, exist_ok=True)

    pcap_path = out_dir / f"capture_{interface.replace(' ', '_')}_{duration}s.pcap"

    cmd = [
        tshark,
        "-i", interface,
        "-a", f"duration:{duration}",
        "-w", str(pcap_path),
        "-q",
    ]

    logger.info(f"[capture_live_traffic] interface={interface!r} duration={duration}s")

    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=duration + 30)
    except FileNotFoundError:
        raise RuntimeError(f"tshark not found at: {tshark}")
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"tshark timed out after {duration + 30}s")

    stderr = proc.stderr.decode(errors="replace").strip()

    if proc.returncode != 0:
        if "permission" in stderr.lower() or "access" in stderr.lower():
            raise PermissionError(
                f"tshark denied access to {interface!r}. Run as Administrator."
            )
        raise RuntimeError(f"tshark exited {proc.returncode}: {stderr[:400]}")

    if not pcap_path.exists() or pcap_path.stat().st_size == 0:
        raise RuntimeError(
            f"tshark produced no output for interface {interface!r}. "
            "Check interface name with: tshark -D"
        )

    logger.info(
        f"[capture_live_traffic] Saved: {pcap_path.name} "
        f"({pcap_path.stat().st_size / 1024:.1f} KB)"
    )
    return pcap_path


def get_interfaces() -> list[dict]:
    """
    Return available tshark network interfaces as [{index, name}].
    Runs: tshark -D  and parses the output.
    """
    tshark = _find_tshark()
    try:
        proc = subprocess.run(
            [tshark, "-D"],
            capture_output=True,
            timeout=10,
        )
        lines = proc.stdout.decode(errors="replace").strip().splitlines()
        interfaces = []
        for line in lines:
            # Format: "1. \Device\NPF_{GUID} (Wi-Fi)"
            line = line.strip()
            if not line:
                continue
            parts = line.split(". ", 1)
            if len(parts) == 2:
                idx  = parts[0]
                rest = parts[1]
                # Extract friendly name from parentheses if present
                if "(" in rest and rest.endswith(")"):
                    name = rest[rest.rfind("(") + 1:-1]
                else:
                    name = rest
                interfaces.append({"index": idx, "name": name})
        return interfaces
    except Exception as exc:
        logger.warning(f"[capture] get_interfaces failed: {exc}")
        return []
