# frontend/components/metric_card.py
# ─────────────────────────────────────────────────────────────────────────────
# Reusable metric summary card for the persistent header row.
# Displays: uppercase label, large numeric value, subtitle, accent border.
#
# Usage:
#   card = MetricCard(parent, label="DETECTED ATTACKS", value="6",
#                     subtitle="Active threats", accent="critical")
#   card.grid(...)
#   card.update_value("7")
#   card.update_value("7", accent="critical")
# ─────────────────────────────────────────────────────────────────────────────
import customtkinter as ctk
from frontend.utils.theme import (
    TEXT_SECONDARY, ACCENT_MAP,
    FONT_METRIC, FONT_METRIC_LABEL, FONT_METRIC_SUB,
    CARD_CORNER_RADIUS, CARD_BORDER_WIDTH,
    SPACE_XL, SPACE_SM, SPACE_MD,
)


class MetricCard(ctk.CTkFrame):
    """
    Summary metric card with semantic accent coloring.

    Parameters
    ----------
    label    : Short uppercase label shown above the value
    value    : Main display value (e.g. "Critical", "238,139", "97.34%")
    subtitle : Small text shown below the value
    accent   : One of "critical" | "warning" | "ok" | "info" | "accent"
    """

    def __init__(
        self,
        master,
        label:    str = "",
        value:    str = "—",
        subtitle: str = "",
        accent:   str = "info",
        **kwargs,
    ):
        fg_color, bg_tint, border_color = ACCENT_MAP.get(accent, ACCENT_MAP["info"])

        # No fixed height — let content determine size
        super().__init__(
            master,
            fg_color=bg_tint,
            border_color=border_color,
            border_width=CARD_BORDER_WIDTH,
            corner_radius=CARD_CORNER_RADIUS,
            **kwargs,
        )
        self.grid_columnconfigure(0, weight=1)

        # ── Label ─────────────────────────────────────────────────────────────
        self._label_widget = ctk.CTkLabel(
            self,
            text=label.upper(),
            text_color=TEXT_SECONDARY,
            font=ctk.CTkFont(
                family=FONT_METRIC_LABEL[0],
                size=FONT_METRIC_LABEL[1],
                weight=FONT_METRIC_LABEL[2],
            ),
            anchor="w",
        )
        self._label_widget.grid(
            row=0, column=0,
            padx=SPACE_XL, pady=(SPACE_MD, 0),
            sticky="w",
        )

        # ── Value ─────────────────────────────────────────────────────────────
        self._value_widget = ctk.CTkLabel(
            self,
            text=value,
            text_color=fg_color,
            font=ctk.CTkFont(
                family=FONT_METRIC[0],
                size=FONT_METRIC[1],
                weight=FONT_METRIC[2],
            ),
            anchor="w",
        )
        self._value_widget.grid(
            row=1, column=0,
            padx=SPACE_XL, pady=(SPACE_SM, 0),
            sticky="w",
        )

        # ── Subtitle ──────────────────────────────────────────────────────────
        self._sub_widget = ctk.CTkLabel(
            self,
            text=subtitle,
            text_color=TEXT_SECONDARY,
            font=ctk.CTkFont(
                family=FONT_METRIC_SUB[0],
                size=FONT_METRIC_SUB[1],
                weight=FONT_METRIC_SUB[2],
            ),
            anchor="w",
        )
        self._sub_widget.grid(
            row=2, column=0,
            padx=SPACE_XL, pady=(SPACE_SM, SPACE_MD),
            sticky="w",
        )

        self._current_accent = accent

    # ── Public API ────────────────────────────────────────────────────────────

    def update_value(self, value: str, accent: str | None = None) -> None:
        self._value_widget.configure(text=value)
        if accent and accent != self._current_accent:
            fg_color, bg_tint, border_color = ACCENT_MAP.get(
                accent, ACCENT_MAP["info"]
            )
            self.configure(fg_color=bg_tint, border_color=border_color)
            self._value_widget.configure(text_color=fg_color)
            self._current_accent = accent

    def update_subtitle(self, subtitle: str) -> None:
        self._sub_widget.configure(text=subtitle)

    def update_label(self, label: str) -> None:
        self._label_widget.configure(text=label.upper())
