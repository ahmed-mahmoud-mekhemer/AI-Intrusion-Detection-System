# frontend/components/sidebar.py
# ─────────────────────────────────────────────────────────────────────────────
# Sidebar navigation with active-state indicator and backend status pill.
# ─────────────────────────────────────────────────────────────────────────────
import customtkinter as ctk
from typing import Callable

from frontend.utils.config import NAV_ITEMS
from frontend.utils.theme import (
    BG_SIDEBAR, BG_ELEVATED,
    ACCENT_CYAN, ACCENT_CYAN_DIM, ACCENT_CYAN_GLOW,
    TEXT_PRIMARY, TEXT_SECONDARY, TEXT_MUTED,
    STATUS_OK, STATUS_WARNING, STATUS_CRITICAL,
    STATUS_INFO,
    BORDER_SUBTLE,
    FONT_BODY, FONT_BODY_BOLD, FONT_SMALL,
    SPACE_SM, SPACE_MD, SPACE_LG, SPACE_XL,
    SIDEBAR_WIDTH,
    SIDEBAR_ITEM_ACTIVE_BG, SIDEBAR_ITEM_HOVER_BG,
    SIDEBAR_INDICATOR,
    BTN_CORNER_RADIUS,
)

_NAV_ICONS = {
    "dashboard": "⊞",
    "pcap":      "◈",
    "realtime":  "◉",
    "alerts":    "⚑",
}


class Sidebar(ctk.CTkFrame):

    def __init__(
        self,
        master,
        on_navigate: Callable[[str], None],
        active_screen: str = "dashboard",
    ):
        super().__init__(
            master,
            width=SIDEBAR_WIDTH,
            corner_radius=0,
            fg_color=BG_SIDEBAR,
            border_width=0,
        )
        self.grid_propagate(False)
        self.on_navigate  = on_navigate
        self._active      = active_screen
        self._buttons:    dict[str, ctk.CTkFrame] = {}
        self._btn_labels: dict[str, tuple]        = {}
        self._build()

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(len(NAV_ITEMS) + 3, weight=1)

        # ── Branding ──────────────────────────────────────────────────────────
        brand = ctk.CTkFrame(self, fg_color="transparent")
        brand.grid(row=0, column=0, padx=SPACE_XL, pady=(SPACE_XL, SPACE_LG),
                   sticky="ew")
        brand.grid_columnconfigure(1, weight=1)

        icon_box = ctk.CTkFrame(
            brand, width=36, height=36,
            fg_color=ACCENT_CYAN_GLOW, corner_radius=8,
        )
        icon_box.grid(row=0, column=0, rowspan=2, padx=(0, SPACE_MD))
        icon_box.grid_propagate(False)
        ctk.CTkLabel(
            icon_box, text="🛡",
            font=ctk.CTkFont(size=16),
            text_color=ACCENT_CYAN,
            fg_color="transparent",
        ).place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(
            brand, text="AI-IDS",
            font=ctk.CTkFont(
                family=FONT_BODY_BOLD[0], size=16, weight=FONT_BODY_BOLD[2],
            ),
            text_color=ACCENT_CYAN, anchor="w",
        ).grid(row=0, column=1, sticky="w")

        ctk.CTkLabel(
            brand, text="Intrusion Detection",
            font=ctk.CTkFont(family=FONT_SMALL[0], size=FONT_SMALL[1]),
            text_color=TEXT_MUTED, anchor="w",
        ).grid(row=1, column=1, sticky="w")

        # ── Divider ───────────────────────────────────────────────────────────
        ctk.CTkFrame(
            self, height=1, fg_color=BORDER_SUBTLE, corner_radius=0,
        ).grid(row=1, column=0, sticky="ew", padx=0, pady=(0, SPACE_MD))

        # ── Nav section label ─────────────────────────────────────────────────
        ctk.CTkLabel(
            self, text="NAVIGATION",
            text_color=TEXT_MUTED,
            font=ctk.CTkFont(family=FONT_SMALL[0], size=9, weight="bold"),
            anchor="w",
        ).grid(row=2, column=0, padx=SPACE_XL, pady=(0, SPACE_SM), sticky="w")

        # ── Nav items ─────────────────────────────────────────────────────────
        for i, (label, key) in enumerate(NAV_ITEMS):
            self._build_nav_item(row=i + 3, label=label, key=key)

        # ── Bottom status pill ────────────────────────────────────────────────
        self._status_frame = ctk.CTkFrame(
            self,
            fg_color=BG_ELEVATED,
            corner_radius=8,
            border_width=1,
            border_color=BORDER_SUBTLE,
        )
        self._status_frame.grid(
            row=len(NAV_ITEMS) + 4, column=0,
            padx=SPACE_XL, pady=SPACE_XL, sticky="sew",
        )
        self._status_frame.grid_columnconfigure(1, weight=1)

        self._status_dot = ctk.CTkLabel(
            self._status_frame, text="●",
            font=ctk.CTkFont(size=10),
            text_color=TEXT_MUTED,
        )
        self._status_dot.grid(row=0, column=0,
                              padx=(SPACE_MD, SPACE_SM), pady=SPACE_MD)

        self._status_text = ctk.CTkLabel(
            self._status_frame, text="Connecting…",
            font=ctk.CTkFont(family=FONT_SMALL[0], size=FONT_SMALL[1]),
            text_color=TEXT_MUTED, anchor="w",
        )
        self._status_text.grid(row=0, column=1,
                               padx=(0, SPACE_MD), pady=SPACE_MD, sticky="w")

        self._highlight(self._active)

    def _build_nav_item(self, row: int, label: str, key: str):
        item = ctk.CTkFrame(
            self,
            fg_color="transparent",
            corner_radius=BTN_CORNER_RADIUS,
            cursor="hand2",
        )
        item.grid(row=row, column=0, padx=SPACE_MD, pady=2, sticky="ew")
        item.grid_columnconfigure(2, weight=1)

        # Left accent indicator bar
        indicator = ctk.CTkFrame(
            item, width=3, height=28,
            fg_color="transparent",
            corner_radius=2,
        )
        indicator.grid(row=0, column=0, padx=(0, SPACE_SM), pady=SPACE_SM)
        indicator.grid_propagate(False)

        # Icon — no width constraint so emoji renders fully
        icon_lbl = ctk.CTkLabel(
            item,
            text=_NAV_ICONS.get(key, "·"),
            font=ctk.CTkFont(size=14),
            text_color=TEXT_MUTED,
            anchor="center",
        )
        icon_lbl.grid(row=0, column=1, padx=(0, SPACE_SM), pady=SPACE_SM)

        # Text label
        text_lbl = ctk.CTkLabel(
            item, text=label,
            font=ctk.CTkFont(family=FONT_BODY[0], size=FONT_BODY[1]),
            text_color=TEXT_SECONDARY,
            anchor="w",
        )
        text_lbl.grid(row=0, column=2, padx=(0, SPACE_MD), pady=SPACE_SM,
                      sticky="w")

        for widget in (item, icon_lbl, text_lbl):
            widget.bind("<Button-1>", lambda e, k=key: self._on_click(k))
        item.bind("<Enter>", lambda e, w=item: self._on_hover(w, True))
        item.bind("<Leave>", lambda e, w=item: self._on_hover(w, False))

        self._buttons[key]    = item
        self._btn_labels[key] = (indicator, icon_lbl, text_lbl)

    def _on_click(self, key: str):
        self._highlight(key)
        self.on_navigate(key)

    def _on_hover(self, widget: ctk.CTkFrame, entering: bool):
        key = next((k for k, v in self._buttons.items() if v is widget), None)
        if key and key != self._active:
            widget.configure(
                fg_color=SIDEBAR_ITEM_HOVER_BG if entering else "transparent"
            )

    def _highlight(self, key: str):
        for k, item in self._buttons.items():
            indicator, icon_lbl, text_lbl = self._btn_labels[k]
            if k == key:
                item.configure(fg_color=SIDEBAR_ITEM_ACTIVE_BG)
                indicator.configure(fg_color=SIDEBAR_INDICATOR)
                icon_lbl.configure(text_color=ACCENT_CYAN)
                text_lbl.configure(
                    text_color=TEXT_PRIMARY,
                    font=ctk.CTkFont(
                        family=FONT_BODY_BOLD[0],
                        size=FONT_BODY_BOLD[1],
                        weight=FONT_BODY_BOLD[2],
                    ),
                )
            else:
                item.configure(fg_color="transparent")
                indicator.configure(fg_color="transparent")
                icon_lbl.configure(text_color=TEXT_MUTED)
                text_lbl.configure(
                    text_color=TEXT_SECONDARY,
                    font=ctk.CTkFont(
                        family=FONT_BODY[0], size=FONT_BODY[1],
                    ),
                )
        self._active = key

    def set_backend_status(self, state: str):
        if state == "online":
            self._status_dot.configure(text_color=STATUS_OK)
            self._status_text.configure(
                text="Backend Online", text_color=STATUS_OK)
        elif state == "busy":
            self._status_dot.configure(text_color=STATUS_INFO)
            self._status_text.configure(
                text="Analyzing…", text_color=STATUS_INFO)
        else:
            self._status_dot.configure(text_color=STATUS_CRITICAL)
            self._status_text.configure(
                text="Backend Offline", text_color=STATUS_CRITICAL)
