# frontend/components/status_badge.py
# ─────────────────────────────────────────────────────────────────────────────
# Pill-shaped severity badge for use in table cells and status rows.
#
# Usage:
#   badge = StatusBadge(parent, text="HIGH", severity="high")
#   badge.grid(...)
#   badge.update("MEDIUM", "medium")
# ─────────────────────────────────────────────────────────────────────────────
import customtkinter as ctk
from frontend.utils.theme import (
    BADGE_HIGH_BG,     BADGE_HIGH_FG,
    BADGE_MEDIUM_BG,   BADGE_MEDIUM_FG,
    BADGE_LOW_BG,      BADGE_LOW_FG,
    BADGE_CRITICAL_BG, BADGE_CRITICAL_FG,
    STATUS_OK_BG,      STATUS_OK,
    BG_ELEVATED,       TEXT_SECONDARY,
    FONT_BADGE,
    SPACE_XS, SPACE_MD,
)

_SEVERITY_MAP = {
    "critical": (BADGE_CRITICAL_FG, BADGE_CRITICAL_BG),
    "high":     (BADGE_HIGH_FG,     BADGE_HIGH_BG),
    "medium":   (BADGE_MEDIUM_FG,   BADGE_MEDIUM_BG),
    "low":      (BADGE_LOW_FG,      BADGE_LOW_BG),
    "info":     (BADGE_LOW_FG,      BADGE_LOW_BG),
    "benign":   (STATUS_OK,         STATUS_OK_BG),
    "ok":       (STATUS_OK,         STATUS_OK_BG),
    "unknown":  (TEXT_SECONDARY,    BG_ELEVATED),
}


class StatusBadge(ctk.CTkLabel):
    """
    Pill-shaped label colored by severity.

    Parameters
    ----------
    text     : Display text (e.g. "HIGH", "MEDIUM", "LOW")
    severity : Semantic key — "critical" | "high" | "medium" | "low" |
               "info" | "benign" | "ok" | "unknown"
    """

    def __init__(
        self,
        master,
        text:     str = "",
        severity: str = "unknown",
        **kwargs,
    ):
        fg, bg = _SEVERITY_MAP.get(severity.lower(), _SEVERITY_MAP["unknown"])

        kwargs.setdefault("corner_radius", 6)
        kwargs.setdefault("width", 72)
        kwargs.setdefault("height", 24)
        kwargs.setdefault("anchor", "center")

        kwargs.setdefault("padx", SPACE_MD)
        kwargs.setdefault("pady", SPACE_XS)
        super().__init__(
            master,
            text=text,
            text_color=fg,
            fg_color=bg,
            font=ctk.CTkFont(
                family=FONT_BADGE[0],
                size=FONT_BADGE[1],
                weight=FONT_BADGE[2],
            ),
            **kwargs,
        )

    def update(self, text: str, severity: str) -> None:
        """Update badge text and color."""
        fg, bg = _SEVERITY_MAP.get(severity.lower(), _SEVERITY_MAP["unknown"])
        self.configure(text=text, text_color=fg, fg_color=bg)
