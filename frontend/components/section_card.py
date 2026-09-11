# frontend/components/section_card.py
# ─────────────────────────────────────────────────────────────────────────────
# Reusable dark panel card with optional title row.
# Wraps content in a consistently styled container matching the Figma design.
#
# Usage:
#   panel = SectionCard(parent, title="PCAP FILE ANALYSIS")
#   panel.grid(...)
#   # place children inside panel.body:
#   ctk.CTkLabel(panel.body, text="hello").pack(padx=16, pady=8)
# ─────────────────────────────────────────────────────────────────────────────
import customtkinter as ctk
from frontend.utils.theme import (
    BG_PANEL, BORDER_SUBTLE, ACCENT_CYAN, TEXT_SECONDARY,
    FONT_SECTION, FONT_SMALL,
    CARD_CORNER_RADIUS, CARD_BORDER_WIDTH,
    SPACE_XL, SPACE_LG, SPACE_MD,
)


class SectionCard(ctk.CTkFrame):
    """
    Dark navy panel with rounded corners and optional title row.

    Parameters
    ----------
    title       : Optional section title string (uppercase recommended).
                  If None or empty, no title row is rendered.
    title_right : Optional string shown right-aligned in the title row
                  (e.g. "● 6 threats detected"). Pass None to omit.
    accent_title: If True, renders title in ACCENT_CYAN. Default False (gray).
    padding     : Inner padding applied to self.body. Default SPACE_XL (20).
    """

    def __init__(
        self,
        master,
        title:        str | None = None,
        title_right:  str | None = None,
        accent_title: bool       = False,
        padding:      int        = SPACE_XL,
        **kwargs,
    ):
        # Pop body_fg before passing to super so CTkFrame doesn't choke
        kwargs.setdefault("fg_color",     BG_PANEL)
        kwargs.setdefault("border_color", BORDER_SUBTLE)
        kwargs.setdefault("border_width", CARD_BORDER_WIDTH)
        kwargs.setdefault("corner_radius", CARD_CORNER_RADIUS)

        super().__init__(master, **kwargs)

        self.grid_columnconfigure(0, weight=1)

        current_row = 0

        # ── Optional title row ────────────────────────────────────────────────
        if title:
            title_row = ctk.CTkFrame(self, fg_color="transparent")
            title_row.grid(
                row=current_row, column=0,
                padx=SPACE_XL, pady=(SPACE_LG, 0),
                sticky="ew",
            )
            title_row.grid_columnconfigure(0, weight=1)
            title_row.grid_columnconfigure(1, weight=0)

            ctk.CTkLabel(
                title_row,
                text=title,
                text_color=ACCENT_CYAN if accent_title else TEXT_SECONDARY,
                font=ctk.CTkFont(
                    family=FONT_SECTION[0],
                    size=FONT_SECTION[1],
                    weight=FONT_SECTION[2],
                ),
                anchor="w",
            ).grid(row=0, column=0, sticky="w")

            if title_right is not None:
                self._title_right_label = ctk.CTkLabel(
                    title_row,
                    text=title_right,
                    text_color=TEXT_SECONDARY,
                    font=ctk.CTkFont(
                        family=FONT_SMALL[0],
                        size=FONT_SMALL[1],
                        weight=FONT_SMALL[2],
                    ),
                    anchor="e",
                )
                self._title_right_label.grid(row=0, column=1, sticky="e")
            else:
                self._title_right_label = None

            current_row += 1

        # ── Divider (only when title present) ────────────────────────────────
        if title:
            divider = ctk.CTkFrame(
                self, height=1,
                fg_color=BORDER_SUBTLE,
                corner_radius=0,
            )
            divider.grid(
                row=current_row, column=0,
                padx=0, pady=(SPACE_MD, 0),
                sticky="ew",
            )
            current_row += 1

        # ── Body area (place children here) ───────────────────────────────────
        self.body = ctk.CTkFrame(self, fg_color="transparent")
        self.body.grid(
            row=current_row, column=0,
            padx=padding, pady=padding,
            sticky="nsew",
        )
        self.grid_rowconfigure(current_row, weight=1)
        self.body.grid_columnconfigure(0, weight=1)
        self.body.grid_rowconfigure(0, weight=1)

    # ── Public API ────────────────────────────────────────────────────────────

    def update_title_right(self, text: str, color: str | None = None) -> None:
        """Update the right-aligned title badge text (e.g. threat count)."""
        if self._title_right_label:
            kwargs = {"text": text}
            if color:
                kwargs["text_color"] = color
            self._title_right_label.configure(**kwargs)
