# frontend/components/stat_card.py
# ─────────────────────────────────────────────────────────────────────────────
# Reusable stat card widget used on the Dashboard screen.
# ─────────────────────────────────────────────────────────────────────────────
import customtkinter as ctk


class StatCard(ctk.CTkFrame):
    """
    A small card displaying a metric label and a numeric value.

    Args:
        master:      Parent widget.
        title:       Metric name (e.g., "Total Alerts").
        value:       Display value (str or int).
        color:       Accent color for the value label.
    """

    def __init__(self, master, title: str, value: str = "—", color: str = "white"):
        super().__init__(master, corner_radius=10)
        self._color = color
        self.configure(fg_color=("gray86", "gray20"))

        self._title_label = ctk.CTkLabel(
            self,
            text=title,
            font=ctk.CTkFont(size=12),
            text_color="gray",
        )
        self._title_label.grid(row=0, column=0, padx=16, pady=(14, 2), sticky="w")

        self._value_label = ctk.CTkLabel(
            self,
            text=str(value),
            font=ctk.CTkFont(size=28, weight="bold"),
            text_color=color,
        )
        self._value_label.grid(row=1, column=0, padx=16, pady=(0, 14), sticky="w")

    def update_value(self, value: str | int):
        """Refresh the displayed value."""
        self._value_label.configure(text=str(value))
