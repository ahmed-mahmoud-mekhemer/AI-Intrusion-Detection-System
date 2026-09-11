# frontend/utils/config.py
# ─────────────────────────────────────────────────────────────────────────────
# Frontend configuration — theme, colors, API URL.
# ─────────────────────────────────────────────────────────────────────────────

API_BASE_URL    = "http://127.0.0.1:8000"
REQUEST_TIMEOUT = 10  # seconds

# ── CustomTkinter theme ───────────────────────────────────────────────────────
APPEARANCE_MODE = "light"      # "dark" | "light" | "system"
COLOR_THEME     = "blue"       # "blue" | "green" | "dark-blue"

# ── Window ────────────────────────────────────────────────────────────────────
# Widened to 1300px to accommodate persistent metric card row and sidebar
APP_TITLE     = "AI Intrusion Detection System"
WINDOW_WIDTH  = 1360
WINDOW_HEIGHT = 800
MIN_WIDTH     = 1160
MIN_HEIGHT    = 690

# ── Severity colors (hex) ─────────────────────────────────────────────────────
# These are kept for backward compatibility with any code that still reads them.
# New code should import from frontend.utils.theme instead.
SEVERITY_COLORS = {
    "CRITICAL":           "#C1443B",
    "HIGH":               "#C1443B",
    "MEDIUM":             "#B8792A",
    "LOW":                "#3D6E96",
    "BENIGN":             "#66645D",
    "SUSPICIOUS_UNKNOWN": "#6F4E8C",
}

# ── Sidebar nav items: (display_name, screen_key) ────────────────────────────
NAV_ITEMS = [
    ("Dashboard",     "dashboard"),
    ("PCAP Analysis", "pcap"),
    ("Real-Time",     "realtime"),
    ("Alerts",        "alerts"),
]
