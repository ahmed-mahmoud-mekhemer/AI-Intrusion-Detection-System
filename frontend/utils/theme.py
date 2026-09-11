# frontend/utils/theme.py
# ─────────────────────────────────────────────────────────────────────────────
# Centralized design token system for the IDS desktop application.
# All colors, fonts, and spacing constants are defined here.
# Import from this module in every screen and component — never hardcode values.
#
# Design identity: warm gray + deep teal — a calm, professional light theme.
# Neutral warm-gray surfaces (never sandy, never stark white) paired with a
# single deep teal accent used only for active/interactive elements. Status
# colors are muted, editorial tones rather than saturated "alert" primaries.
#
# Usage:
#   from frontend.utils.theme import BG_PRIMARY, ACCENT_CYAN, FONT_METRIC
# ─────────────────────────────────────────────────────────────────────────────

# ── Colors ────────────────────────────────────────────────────────────────────

# Backgrounds
BG_PRIMARY   = "#F2F1ED"   # Root window background — warm light gray
BG_PANEL     = "#FFFFFF"   # Section card / panel background
BG_ELEVATED  = "#FAFAF8"   # Nested cards, hover rows, input fields
BG_SIDEBAR   = "#EAE9E4"   # Sidebar background — a touch deeper than root

# Borders
BORDER_SUBTLE = "#DEDDD6"   # Default card/panel border
BORDER_ACCENT = "#1D6B63"   # Active/focused element border

# Accent — deep teal, used sparingly for active/interactive state
ACCENT_CYAN      = "#1D6B63"   # Primary accent — headings, links, active state
ACCENT_CYAN_DIM  = "#155650"   # Hover/pressed
ACCENT_CYAN_GLOW = "#DCEBE8"   # Subtle tint bg behind accent elements

# Text
TEXT_PRIMARY   = "#2B2A27"   # Body text, values — soft black
TEXT_SECONDARY = "#66645D"   # Labels, subtitles, column headers
TEXT_MUTED     = "#9B988F"   # Timestamps, secondary metadata, placeholders

# Status — Critical (red)
STATUS_CRITICAL    = "#C1443B"
STATUS_CRITICAL_BG = "#F7E1DE"
STATUS_CRITICAL_BD = "#E5B8B1"

# Status — Warning (amber)
STATUS_WARNING    = "#B8792A"
STATUS_WARNING_BG = "#F3E7D3"
STATUS_WARNING_BD = "#E0C495"

# Status — OK / Secure (green)
STATUS_OK    = "#2E8B6B"
STATUS_OK_BG = "#DFEEE7"
STATUS_OK_BD = "#B4D8C8"

# Status — Info / Neutral (blue)
STATUS_INFO    = "#3D6E96"
STATUS_INFO_BG = "#E1E9F0"
STATUS_INFO_BD = "#B7CADA"

# Severity badge backgrounds (used in table cells)
BADGE_HIGH_BG     = "#F7E1DE"
BADGE_HIGH_FG     = "#C1443B"
BADGE_MEDIUM_BG   = "#F3E7D3"
BADGE_MEDIUM_FG   = "#B8792A"
BADGE_LOW_BG      = "#E1E9F0"
BADGE_LOW_FG      = "#3D6E96"
BADGE_CRITICAL_BG = "#EFCAC5"
BADGE_CRITICAL_FG = "#9C332B"

# Table
TABLE_HEADER_BG  = "#F2F1ED"   # matches root to create "floating header" look
TABLE_ROW_BG     = "#FFFFFF"
TABLE_ROW_ALT_BG = "#F5F4F0"   # alternating row tint
TABLE_ROW_HOVER  = "#ECEBE6"
TABLE_DIVIDER    = "#DEDDD6"

# Buttons
BTN_PRIMARY_BG      = "#1D6B63"   # Deep teal primary button
BTN_PRIMARY_HOVER   = "#155650"
BTN_DANGER_BG       = "#C1443B"   # Stop / destructive
BTN_DANGER_HOVER    = "#A5382F"
BTN_SECONDARY_BG    = "#E4E3DD"
BTN_SECONDARY_HOVER = "#DEDDD6"
BTN_DISABLED_BG     = "#DEDDD6"
BTN_DISABLED_FG     = "#9B988F"

# Sidebar
SIDEBAR_ITEM_ACTIVE_BG = "#E4E3DD"
SIDEBAR_ITEM_HOVER_BG  = "#F2F1ED"
SIDEBAR_INDICATOR      = ACCENT_CYAN   # Left border of active nav item


# ── Typography ────────────────────────────────────────────────────────────────
# Each token is a (family, size, weight) tuple for use with:
#   ctk.CTkFont(family=f, size=s, weight=w)
# or unpacked as:
#   ctk.CTkFont(*FONT_BODY)

_FAMILY       = "Segoe UI"   # Primary font (Windows — excellent on dark themes)
_FAMILY_MONO  = "Consolas"   # Monospace — IPs, ports, packet feed

FONT_HERO         = (_FAMILY,      26, "bold")    # "AI Intrusion Detection System"
FONT_HERO_SUB     = (_FAMILY,      12, "normal")  # Subtitle under hero
FONT_METRIC       = (_FAMILY,      30, "bold")    # Large numbers in metric cards
FONT_METRIC_LABEL = (_FAMILY,      10, "bold")    # Uppercase label above metric
FONT_METRIC_SUB   = (_FAMILY,      10, "normal")  # Subtitle below metric value
FONT_SECTION      = (_FAMILY,      14, "bold")    # Section panel titles
FONT_BODY         = (_FAMILY,      13, "normal")  # Default body text
FONT_BODY_BOLD    = (_FAMILY,      13, "bold")    # Emphasis body text
FONT_SMALL        = (_FAMILY,      11, "normal")  # Fine print, tooltips
FONT_BUTTON       = (_FAMILY,      13, "bold")    # Button labels
FONT_TABLE_HEADER = (_FAMILY,      10, "bold")    # Table column headers (uppercase)
FONT_TABLE_CELL   = (_FAMILY,      12, "normal")  # Table cell content
FONT_MONO         = (_FAMILY_MONO, 12, "normal")  # IPs, ports, packet feed
FONT_MONO_SMALL   = (_FAMILY_MONO, 10, "normal")  # Small mono (timestamps in feed)
FONT_BADGE        = (_FAMILY,      10, "bold")    # Severity badge text


# ── Spacing ───────────────────────────────────────────────────────────────────
# Base unit: 4px. Use multiples only.

SPACE_XS  = 4
SPACE_SM  = 8
SPACE_MD  = 12
SPACE_LG  = 16
SPACE_XL  = 20
SPACE_2XL = 24
SPACE_3XL = 32
SPACE_4XL = 48


# ── Component dimensions ──────────────────────────────────────────────────────

CARD_CORNER_RADIUS    = 12
CARD_BORDER_WIDTH     = 1
METRIC_CARD_HEIGHT    = 130
SECTION_CARD_PADDING  = 20   # inner padding of section cards

BTN_HEIGHT_PRIMARY    = 44
BTN_HEIGHT_SECONDARY  = 36
BTN_HEIGHT_SMALL      = 28
BTN_CORNER_RADIUS     = 8

TABLE_ROW_HEIGHT      = 44
TABLE_HEADER_HEIGHT   = 32

SIDEBAR_WIDTH         = 220


# ── Accent map (for MetricCard and StatusBadge) ───────────────────────────────
# Maps semantic accent name → (fg_color, bg_color, border_color)

ACCENT_MAP = {
    "critical": (STATUS_CRITICAL, STATUS_CRITICAL_BG, STATUS_CRITICAL_BD),
    "warning":  (STATUS_WARNING,  STATUS_WARNING_BG,  STATUS_WARNING_BD),
    "ok":       (STATUS_OK,       STATUS_OK_BG,       STATUS_OK_BD),
    "info":     (STATUS_INFO,     STATUS_INFO_BG,     STATUS_INFO_BD),
    "accent":   (ACCENT_CYAN,     ACCENT_CYAN_GLOW,   BORDER_ACCENT),
}

# Severity label → accent name (for table badge mapping)
SEVERITY_ACCENT = {
    "critical": "critical",
    "high":     "critical",
    "medium":   "warning",
    "low":      "info",
    "info":     "info",
    "benign":   "ok",
}


# ── Detection type badge tokens ───────────────────────────────────────────────
# Maps detection_type string → (fg_color, bg_color, display_text)

DT_RULE_FG      = "#66645D"   # neutral gray — pure rule, no AI involvement
DT_RULE_BG      = "#E4E3DD"
DT_HYBRID_FG    = "#6F4E8C"   # muted plum — rule confirmed by elevated IF score
DT_HYBRID_BG    = "#EAE1F0"
DT_AI_FG        = "#1D6B63"   # deep teal — AI identified a specific attack pattern
DT_AI_BG        = "#DCEBE8"
DT_UNKNOWN_FG   = "#B8792A"   # amber — anomaly confirmed, pattern unclassifiable
DT_UNKNOWN_BG   = "#F3E7D3"
DT_TRAP_FG      = "#A15A22"   # burnt umber — honeypot trap triggered
DT_TRAP_BG      = "#F1E0CC"

# Maps detection_type string → (fg_color, bg_color, badge_text)
#
# Five tiers of detection confidence:
#   RULE          — rule engine only, no AI involvement
#   HYBRID        — rule fired AND IF score elevated (highest confidence)
#   AI-CLASSIFIED — IF anomaly + pattern classifier matched ("Likely X")
#   AI-UNKNOWN    — IF anomaly confirmed but classifier cannot name it
#   TRAP          — honeypot layer; attacker contacted a decoy service
#
# AI-BEHAVIORAL kept as backward-compat alias for pre-migration DB rows.
DETECTION_TYPE_MAP: dict[str, tuple] = {
    "RULE":          (DT_RULE_FG,    DT_RULE_BG,    "RULE"),
    "HYBRID":        (DT_HYBRID_FG,  DT_HYBRID_BG,  "AI+RULE"),
    "AI-CLASSIFIED": (DT_AI_FG,      DT_AI_BG,      "AI"),
    "AI-UNKNOWN":    (DT_UNKNOWN_FG, DT_UNKNOWN_BG,  "AI?"),
    "AI-BEHAVIORAL": (DT_AI_FG,      DT_AI_BG,      "AI"),    # backward compat
    "TRAP":          (DT_TRAP_FG,    DT_TRAP_BG,    "TRAP"),
}


# ── Helper: build CTkFont from token tuple ────────────────────────────────────

def make_font(token: tuple) -> "ctk.CTkFont":
    """
    Convenience wrapper so callers don't need to import CTkFont separately.

    Usage:
        label = ctk.CTkLabel(..., font=make_font(FONT_BODY))
    """
    import customtkinter as ctk
    family, size, weight = token
    return ctk.CTkFont(family=family, size=size, weight=weight)
