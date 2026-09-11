# frontend/utils/app_state.py
# ─────────────────────────────────────────────────────────────────────────────
# Shared application state singleton.
# Lives in utils/ so it can be imported by any module without circular imports.
# ─────────────────────────────────────────────────────────────────────────────
import threading


class _AppState:
    """Thread-safe shared state for cross-component communication."""

    def __init__(self):
        self._busy = False
        self._lock = threading.Lock()

    def set_busy(self, busy: bool):
        """Call with True when a long backend request starts, False when done."""
        with self._lock:
            self._busy = busy

    @property
    def is_busy(self) -> bool:
        with self._lock:
            return self._busy


# Single instance imported everywhere
app_state = _AppState()
