# frontend/screens/pcap_analysis.py
# ─────────────────────────────────────────────────────────────────────────────
# PCAP Analysis screen — SOC dashboard layout with focus mode.
#
# Two view modes via a single toolbar button (top-right of the screen):
#   Normal View   — full PCAP File Analysis card visible
#   Focus Results — entire PCAP File Analysis card hidden;
#                   Detection Results gains all the freed space
#
# When the user clicks "Normal View", the file card returns intact.
# Auto-enters Focus mode after analysis completes so the user immediately
# sees the data. No PanedWindow, no place(), no overlays.
# ─────────────────────────────────────────────────────────────────────────────
import threading
from pathlib import Path
import customtkinter as ctk
from tkinter import filedialog

from frontend.components.traffic_table import TrafficTable
from frontend.components.section_card  import SectionCard
from frontend.utils.api_client         import analyze_pcap, APIError
from frontend.utils.app_state          import app_state
from frontend.utils.theme import (
    BG_PRIMARY, BG_ELEVATED,
    ACCENT_CYAN,
    TEXT_PRIMARY, TEXT_MUTED,
    STATUS_OK, STATUS_CRITICAL,
    BORDER_SUBTLE,
    FONT_BODY, FONT_BODY_BOLD, FONT_SMALL, FONT_MONO,
    SPACE_SM, SPACE_MD, SPACE_LG, SPACE_2XL,
    BTN_PRIMARY_BG, BTN_PRIMARY_HOVER,
    BTN_SECONDARY_BG, BTN_SECONDARY_HOVER,
    BTN_HEIGHT_PRIMARY, BTN_HEIGHT_SECONDARY, BTN_CORNER_RADIUS,
    CARD_CORNER_RADIUS,
)


class PCAPAnalysisScreen(ctk.CTkFrame):

    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color=BG_PRIMARY, **kwargs)
        self._selected_file: Path | None = None
        self._focus_mode  = False
        self._build_ui()

    # ─────────────────────────────────────────────────────────────────────────
    # UI construction
    # ─────────────────────────────────────────────────────────────────────────

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=0)
        self.grid_rowconfigure(1, weight=0)
        self.grid_rowconfigure(2, weight=1)

        self._build_toolbar()
        self._build_upper()
        self._build_lower()

    # ── Toolbar (row 0) ───────────────────────────────────────────────────────

    def _build_toolbar(self):
        toolbar = ctk.CTkFrame(self, fg_color="transparent")
        toolbar.grid(row=0, column=0, sticky="ew",
                     padx=SPACE_2XL, pady=(SPACE_SM, 0))
        toolbar.grid_columnconfigure(0, weight=1)

        self._focus_btn = ctk.CTkButton(
            toolbar,
            text="⤢  Focus Results",
            width=160, height=BTN_HEIGHT_SECONDARY,
            corner_radius=BTN_CORNER_RADIUS,
            fg_color=BTN_SECONDARY_BG, hover_color=BTN_SECONDARY_HOVER,
            text_color=TEXT_PRIMARY,
            font=ctk.CTkFont(family=FONT_SMALL[0], size=FONT_SMALL[1],
                             weight="bold"),
            command=self._toggle_focus,
        )
        self._focus_btn.grid(row=0, column=1, sticky="e")

    # ── Upper (row 1) — file picker card ──────────────────────────────────────

    def _build_upper(self):
        self._file_card = SectionCard(
            self,
            title="PCAP File Analysis",
            title_right="",
            accent_title=False,
            padding=SPACE_MD,
        )
        self._file_card.grid(
            row=1, column=0,
            padx=SPACE_2XL,
            pady=(SPACE_SM, SPACE_SM),
            sticky="ew",
        )
        self._file_card.body.grid_columnconfigure(0, weight=1)

        picker = ctk.CTkFrame(
            self._file_card.body,
            fg_color=BG_ELEVATED,
            corner_radius=CARD_CORNER_RADIUS,
            border_width=1,
            border_color=BORDER_SUBTLE,
        )
        picker.grid(row=0, column=0, sticky="ew", pady=(0, SPACE_SM))
        picker.grid_columnconfigure(1, weight=1)

        ctk.CTkButton(
            picker,
            text="📂  Browse…",
            width=120, height=BTN_HEIGHT_SECONDARY,
            corner_radius=BTN_CORNER_RADIUS,
            fg_color=BTN_SECONDARY_BG, hover_color=BTN_SECONDARY_HOVER,
            text_color=TEXT_PRIMARY,
            font=ctk.CTkFont(family=FONT_BODY[0], size=FONT_BODY[1]),
            command=self._browse_file,
        ).grid(row=0, column=0, padx=SPACE_SM, pady=SPACE_SM)

        self._file_label = ctk.CTkLabel(
            picker,
            text="No file selected.",
            text_color=TEXT_MUTED,
            font=ctk.CTkFont(family=FONT_MONO[0], size=FONT_MONO[1]),
            anchor="w",
        )
        self._file_label.grid(row=0, column=1,
                              padx=SPACE_SM, pady=SPACE_SM, sticky="w")

        self._file_size_label = ctk.CTkLabel(
            picker, text="",
            text_color=ACCENT_CYAN,
            font=ctk.CTkFont(family=FONT_MONO[0], size=FONT_MONO[1]),
            anchor="e",
        )
        self._file_size_label.grid(row=0, column=2,
                                   padx=(0, SPACE_MD), pady=SPACE_SM)

        self._analyze_btn = ctk.CTkButton(
            self._file_card.body,
            text="▷  Detect Intrusions",
            height=BTN_HEIGHT_PRIMARY,
            corner_radius=BTN_CORNER_RADIUS,
            fg_color=BTN_PRIMARY_BG, hover_color=BTN_PRIMARY_HOVER,
            text_color="white",
            font=ctk.CTkFont(family=FONT_BODY_BOLD[0], size=FONT_BODY_BOLD[1],
                             weight=FONT_BODY_BOLD[2]),
            state="disabled",
            command=self._run_analysis,
        )
        self._analyze_btn.grid(row=1, column=0, sticky="ew", pady=0)

    # ── Lower (row 2) — results table ─────────────────────────────────────────

    def _build_lower(self):
        self._results_section = SectionCard(
            self,
            title="Detection Results",
            title_right="",
            padding=0,
        )
        self._results_section.grid(
            row=2, column=0,
            padx=SPACE_2XL,
            pady=(0, SPACE_MD),
            sticky="nsew",
        )
        self._results_section.body.grid_columnconfigure(0, weight=1)
        self._results_section.body.grid_rowconfigure(0, weight=1)

        self._table = TrafficTable(self._results_section.body)
        self._table.grid(row=0, column=0,
                         padx=SPACE_LG, pady=SPACE_SM,
                         sticky="nsew")

    # ─────────────────────────────────────────────────────────────────────────
    # Focus mode
    # ─────────────────────────────────────────────────────────────────────────

    def _toggle_focus(self):
        if self._focus_mode:
            self._exit_focus()
        else:
            self._enter_focus()

    def _enter_focus(self):
        self._file_card.grid_remove()
        self._focus_btn.configure(text="⤡  Normal View")
        self._focus_mode = True

    def _exit_focus(self):
        self._file_card.grid(
            row=1, column=0,
            padx=SPACE_2XL,
            pady=(SPACE_SM, SPACE_SM),
            sticky="ew",
        )
        self._focus_btn.configure(text="⤢  Focus Results")
        self._focus_mode = False

    # ─────────────────────────────────────────────────────────────────────────
    # Actions
    # ─────────────────────────────────────────────────────────────────────────

    def _browse_file(self):
        path = filedialog.askopenfilename(
            title="Select a PCAP or CSV file",
            filetypes=[
                ("Supported files", "*.csv *.pcap"),
                ("CSV files",       "*.csv"),
                ("PCAP files",      "*.pcap"),
                ("All files",       "*.*"),
            ],
        )
        if path:
            self._selected_file = Path(path)
            size_kb  = self._selected_file.stat().st_size / 1024
            size_str = (f"{size_kb:.2f} KB" if size_kb < 1024
                        else f"{size_kb / 1024:.2f} MB")
            self._file_label.configure(
                text=self._selected_file.name, text_color=TEXT_PRIMARY)
            self._file_size_label.configure(text=size_str)
            self._analyze_btn.configure(state="normal")

    def _run_analysis(self):
        if not self._selected_file:
            return
        self._analyze_btn.configure(state="disabled", text="⏳  Analyzing…")
        self._results_section.update_title_right("")
        threading.Thread(target=self._do_analysis, daemon=True).start()

    def _do_analysis(self):
        app_state.set_busy(True)
        try:
            results = analyze_pcap(self._selected_file)
            self.after(0, lambda: self._on_success(results))
        except APIError as e:
            error_msg = str(e)
            self.after(0, lambda: self._on_error(error_msg))
        finally:
            app_state.set_busy(False)

    def _on_success(self, results: list):
        count   = len(results)
        attacks = sum(1 for r in results if r.get("label") != "BENIGN")

        self._results_section.update_title_right(
            f"● {count} flows · {attacks} detection{'s' if attacks != 1 else ''}",
            color=STATUS_CRITICAL if attacks > 0 else STATUS_OK,
        )
        self._table.load_results(results)
        self._analyze_btn.configure(state="normal", text="▷  Detect Intrusions")

        # Push flow count to the persistent Analyzed Flows metric card.
        # count = len(results) — total flow records processed by the ML pipeline.
        # Works for both CSV and PCAP-derived input, no capinfos needed.
        root = self.winfo_toplevel()
        if hasattr(root, "set_analyzed_flows"):
            root.set_analyzed_flows(count)

        if not self._focus_mode:
            self._enter_focus()

    def _on_error(self, msg: str):
        self._results_section.update_title_right(
            f"✗  {msg[:60]}", color=STATUS_CRITICAL)
        self._analyze_btn.configure(state="normal",
                                    text="▷  Detect Intrusions")

    def on_show(self):
        pass

    def on_hide(self):
        pass
