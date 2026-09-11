# frontend/screens/realtime_monitor.py
# ─────────────────────────────────────────────────────────────────────────────
# Real-Time Detection screen — live rule-based monitoring layer.
#
#   ┌─────────────────────────────────────────────────────────────┐
#   │  Real-Time Detection  (tshark stdout → rule engine → alerts) │
#   │  Controls: interface, Start/Stop                             │
#   │  Status: packets seen, alerts fired, recent events list      │
#   └─────────────────────────────────────────────────────────────┘
#
# Deep ML Analysis (tshark → CICFlowMeter → ML) belongs to the PCAP Analysis
# screen — it is offline/batch processing, not real-time.  The panel is
# preserved below but hidden (grid_remove) to keep the architecture clean.
# Re-enable by removing the grid_remove() call in _build_deep_panel().
#
# Backend routes:
#   Deep layer: /realtime/*   (hidden, still functional)
#   Live layer: /live/*       (active)
# ─────────────────────────────────────────────────────────────────────────────
import threading
import customtkinter as ctk

from frontend.components.traffic_table import TrafficTable
from frontend.components.section_card  import SectionCard
from frontend.components.status_badge  import StatusBadge
from frontend.utils.api_client import (
    start_capture, stop_capture, get_capture_status, get_interfaces,
    start_live_monitor, stop_live_monitor, get_live_status,
    start_honeypot, stop_honeypot,
    APIError,
)
from frontend.utils.theme import (
    BG_PRIMARY, BG_ELEVATED, BG_PANEL,
    ACCENT_CYAN,
    TEXT_PRIMARY, TEXT_SECONDARY, TEXT_MUTED,
    STATUS_OK, STATUS_CRITICAL, STATUS_WARNING, STATUS_INFO,
    BORDER_SUBTLE,
    FONT_BODY, FONT_BODY_BOLD, FONT_SMALL, FONT_MONO, FONT_BADGE,
    SPACE_XS, SPACE_SM, SPACE_MD, SPACE_LG, SPACE_XL, SPACE_2XL,
    BTN_PRIMARY_BG, BTN_PRIMARY_HOVER,
    BTN_DANGER_BG, BTN_DANGER_HOVER,
    BTN_SECONDARY_BG, BTN_SECONDARY_HOVER,
    BTN_HEIGHT_PRIMARY, BTN_HEIGHT_SECONDARY, BTN_CORNER_RADIUS,
    SEVERITY_ACCENT, ACCENT_MAP,
    DETECTION_TYPE_MAP,
)

# Poll interval shared by both layers
_DEEP_POLL_MS = 2500
_LIVE_POLL_MS = 2000

_PROTO_MAP = {"6": "TCP", "17": "UDP", "1": "ICMP"}


class RealtimeMonitorScreen(ctk.CTkFrame):
    """
    Real-Time Detection screen.

    Active panel:
      - Real-Time Detection: tshark stdout stream → rule engine → immediate alerts

    Hidden panel (preserved, re-enable via _build_deep_panel):
      - Deep ML Analysis: tshark chunks → CICFlowMeter → ML → DB
        (belongs architecturally to PCAP Analysis; kept here for reference)
    """

    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color=BG_PRIMARY, **kwargs)
        # ── Deep layer state ──────────────────────────────────────────────────
        self._deep_running    = False
        self._deep_after_id   = None
        self._deep_seen_count = 0
        # ── Live layer state ──────────────────────────────────────────────────
        self._live_running    = False
        self._live_after_id   = None
        # Incremented on every start/stop so stale _apply callbacks from a
        # previous session (queued via self.after(0,...)) silently discard
        # themselves instead of touching widgets that belong to the new session.
        self._live_poll_gen   = 0
        self._live_last_event_ts = None   # timestamp of newest event last rendered
        self._live_session_counts: dict[str, int] = {
            "RULE": 0, "HYBRID": 0, "AI-CLASSIFIED": 0, "AI-UNKNOWN": 0, "TRAP": 0
        }
        self._live_session_start   = None   # datetime when session started
        self._live_peak_score      = 0.0    # highest IF score seen this session
        self._live_session_pkts    = 0
        self._live_session_fired   = 0
        self._live_label_counts: dict[str, int] = {}
        self._live_last_event: dict  = {}

        self._build_ui()

    # ─────────────────────────────────────────────────────────────────────────
    # UI construction
    # ─────────────────────────────────────────────────────────────────────────

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        # row 0: deep ML controls card   (hidden — Deep ML belongs in PCAP Analysis)
        # row 1: deep ML results card    (hidden — same reason)
        # row 2: real-time detection     (expands to fill full space)
        self.grid_rowconfigure(0, weight=0)
        self.grid_rowconfigure(1, weight=0)
        self.grid_rowconfigure(2, weight=1)

        self._build_deep_panel()   # built but immediately hidden — see below
        self._build_live_panel()

    # ── Panel 1: Deep ML Analysis (HIDDEN) ───────────────────────────────────
    # This panel is architecturally part of offline/batch analysis.
    # It has been moved conceptually to PCAP Analysis.  All code is intact;
    # remove the grid_remove() calls below to restore it to this screen.

    def _build_deep_panel(self):
        deep_card = SectionCard(
            self,
            title="Deep ML Analysis  (tshark → CICFlowMeter → ML)",
            title_right="",
            padding=SPACE_XL,
        )
        deep_card.grid(row=0, column=0,
                       padx=SPACE_2XL, pady=(SPACE_LG, SPACE_SM),
                       sticky="ew")
        deep_card.body.grid_columnconfigure(0, weight=1)
        self._deep_card = deep_card

        # Inputs row
        inputs = ctk.CTkFrame(deep_card.body, fg_color="transparent")
        inputs.grid(row=0, column=0, sticky="ew", pady=(0, SPACE_MD))
        inputs.grid_columnconfigure(4, weight=1)

        ctk.CTkLabel(
            inputs, text="Interface",
            text_color=TEXT_SECONDARY,
            font=ctk.CTkFont(family=FONT_SMALL[0], size=FONT_SMALL[1],
                             weight="bold"),
            anchor="w",
        ).grid(row=0, column=0, padx=(0, SPACE_SM), sticky="w")

        self._deep_iface_var = ctk.StringVar(value="Wi-Fi")
        self._deep_iface_menu = ctk.CTkOptionMenu(
            inputs, variable=self._deep_iface_var, values=["Wi-Fi"],
            width=200, height=BTN_HEIGHT_SECONDARY,
            corner_radius=BTN_CORNER_RADIUS,
            fg_color=BG_ELEVATED,
            button_color=BTN_SECONDARY_BG,
            button_hover_color=BTN_SECONDARY_HOVER,
            text_color=TEXT_PRIMARY,
            font=ctk.CTkFont(family=FONT_BODY[0], size=FONT_BODY[1]),
        )
        self._deep_iface_menu.grid(row=0, column=1, padx=(0, SPACE_XL))

        ctk.CTkLabel(
            inputs, text="Duration (s)",
            text_color=TEXT_SECONDARY,
            font=ctk.CTkFont(family=FONT_SMALL[0], size=FONT_SMALL[1],
                             weight="bold"),
            anchor="w",
        ).grid(row=0, column=2, padx=(0, SPACE_SM), sticky="w")

        self._deep_duration_entry = ctk.CTkEntry(
            inputs, width=80, height=BTN_HEIGHT_SECONDARY,
            corner_radius=BTN_CORNER_RADIUS,
            fg_color=BG_ELEVATED, border_color=BORDER_SUBTLE,
            text_color=TEXT_PRIMARY, placeholder_text="15",
            font=ctk.CTkFont(family=FONT_BODY[0], size=FONT_BODY[1]),
        )
        self._deep_duration_entry.grid(row=0, column=3, padx=(0, SPACE_XL))

        self._deep_toggle_btn = ctk.CTkButton(
            deep_card.body,
            text="▶  Start Deep Analysis",
            height=BTN_HEIGHT_PRIMARY,
            corner_radius=BTN_CORNER_RADIUS,
            fg_color=BTN_PRIMARY_BG, hover_color=BTN_PRIMARY_HOVER,
            text_color="white",
            font=ctk.CTkFont(family=FONT_BODY_BOLD[0], size=FONT_BODY_BOLD[1],
                             weight=FONT_BODY_BOLD[2]),
            command=self._deep_toggle,
        )
        self._deep_toggle_btn.grid(row=1, column=0, sticky="ew",
                                   pady=(0, SPACE_SM))

        self._deep_status = ctk.CTkLabel(
            deep_card.body,
            text="Idle — no active deep capture.",
            text_color=TEXT_MUTED,
            font=ctk.CTkFont(family=FONT_SMALL[0], size=FONT_SMALL[1]),
            anchor="w",
        )
        self._deep_status.grid(row=2, column=0, sticky="w")

        # Results card lives in row 1 of self, hidden until capture starts.
        self._deep_results_section = SectionCard(
            self,
            title="ML Detection Results",
            title_right="",
            padding=0,
        )
        self._deep_results_section.grid(
            row=1, column=0,
            padx=SPACE_2XL, pady=(0, SPACE_SM),
            sticky="ew",
        )
        self._deep_results_section.grid_remove()   # hidden until capture starts

        # Hide the entire deep ML panel — it belongs in PCAP Analysis.
        # To restore: remove this grid_remove() call and the one above will
        # continue to work as before (results card hidden until capture starts).
        deep_card.grid_remove()

    # ── Panel 2: Real-Time Detection ─────────────────────────────────────────

    def _build_live_panel(self):
        outer = ctk.CTkFrame(self, fg_color=BG_PRIMARY)
        outer.grid(row=2, column=0, sticky="nsew", padx=0, pady=0)
        outer.grid_columnconfigure(0, weight=1)
        outer.grid_rowconfigure(0, weight=0)   # control card
        outer.grid_rowconfigure(1, weight=0)   # detection tier legend
        outer.grid_rowconfigure(2, weight=1)   # events card (expands)

        # ── Control card ──────────────────────────────────────────────────────
        live_ctrl = SectionCard(
            outer,
            title="Real-Time Detection",
            title_right="",
            accent_title=True,
            padding=SPACE_XL,
        )
        live_ctrl.grid(row=0, column=0,
                       padx=SPACE_2XL, pady=(0, SPACE_SM),
                       sticky="ew")
        live_ctrl.body.grid_columnconfigure(0, weight=1)
        self._live_ctrl_card = live_ctrl

        # Interface row
        iface_row = ctk.CTkFrame(live_ctrl.body, fg_color="transparent")
        iface_row.grid(row=0, column=0, sticky="ew", pady=(0, SPACE_MD))
        self._live_iface_row = iface_row

        ctk.CTkLabel(
            iface_row, text="Interface",
            text_color=TEXT_SECONDARY,
            font=ctk.CTkFont(family=FONT_SMALL[0], size=FONT_SMALL[1],
                             weight="bold"),
            anchor="w",
        ).grid(row=0, column=0, padx=(0, SPACE_SM), sticky="w")

        self._live_iface_var = ctk.StringVar(value="Wi-Fi")
        self._live_iface_menu = ctk.CTkOptionMenu(
            iface_row, variable=self._live_iface_var, values=["Wi-Fi"],
            width=200, height=BTN_HEIGHT_SECONDARY,
            corner_radius=BTN_CORNER_RADIUS,
            fg_color=BG_ELEVATED,
            button_color=BTN_SECONDARY_BG,
            button_hover_color=BTN_SECONDARY_HOVER,
            text_color=TEXT_PRIMARY,
            font=ctk.CTkFont(family=FONT_BODY[0], size=FONT_BODY[1]),
        )
        self._live_iface_menu.grid(row=0, column=1, padx=(0, SPACE_XL))

        # Counters row (packets seen + alerts fired)
        counters = ctk.CTkFrame(live_ctrl.body, fg_color="transparent")
        counters.grid(row=1, column=0, sticky="ew", pady=(0, SPACE_SM))
        counters.grid_columnconfigure(2, weight=1)

        self._live_toggle_btn = ctk.CTkButton(
            counters,
            text="▶  Start Detection",
            height=BTN_HEIGHT_PRIMARY,
            corner_radius=BTN_CORNER_RADIUS,
            fg_color=BTN_PRIMARY_BG, hover_color=BTN_PRIMARY_HOVER,
            text_color="white",
            font=ctk.CTkFont(family=FONT_BODY_BOLD[0], size=FONT_BODY_BOLD[1],
                             weight=FONT_BODY_BOLD[2]),
            command=self._live_toggle,
        )
        self._live_toggle_btn.grid(row=0, column=0, padx=(0, SPACE_LG))

        # Packet counter pill
        pkt_frame = ctk.CTkFrame(
            counters, fg_color=BG_ELEVATED,
            corner_radius=8, border_width=1, border_color=BORDER_SUBTLE,
        )
        pkt_frame.grid(row=0, column=1, padx=(0, SPACE_MD))
        ctk.CTkLabel(
            pkt_frame, text="Packets",
            text_color=TEXT_MUTED,
            font=ctk.CTkFont(family=FONT_SMALL[0], size=FONT_SMALL[1]),
        ).grid(row=0, column=0, padx=(SPACE_MD, SPACE_SM), pady=SPACE_SM)
        self._live_pkt_label = ctk.CTkLabel(
            pkt_frame, text="0",
            text_color=ACCENT_CYAN,
            font=ctk.CTkFont(family=FONT_BODY_BOLD[0], size=FONT_BODY_BOLD[1],
                             weight="bold"),
        )
        self._live_pkt_label.grid(row=0, column=1, padx=(0, SPACE_MD),
                                   pady=SPACE_SM)

        # Alert counter pill
        alert_frame = ctk.CTkFrame(
            counters, fg_color=BG_ELEVATED,
            corner_radius=8, border_width=1, border_color=BORDER_SUBTLE,
        )
        alert_frame.grid(row=0, column=2, padx=(0, SPACE_MD), sticky="w")
        ctk.CTkLabel(
            alert_frame, text="Alerts",
            text_color=TEXT_MUTED,
            font=ctk.CTkFont(family=FONT_SMALL[0], size=FONT_SMALL[1]),
        ).grid(row=0, column=0, padx=(SPACE_MD, SPACE_SM), pady=SPACE_SM)
        self._live_alert_label = ctk.CTkLabel(
            alert_frame, text="0",
            text_color=STATUS_OK,
            font=ctk.CTkFont(family=FONT_BODY_BOLD[0], size=FONT_BODY_BOLD[1],
                             weight="bold"),
        )
        self._live_alert_label.grid(row=0, column=1, padx=(0, SPACE_MD),
                                     pady=SPACE_SM)

        # IF Anomaly score pill
        anomaly_frame = ctk.CTkFrame(
            counters, fg_color=BG_ELEVATED,
            corner_radius=8, border_width=1, border_color=BORDER_SUBTLE,
        )
        anomaly_frame.grid(row=0, column=3, padx=(0, SPACE_MD), sticky="w")
        ctk.CTkLabel(
            anomaly_frame, text="IF Anomaly",
            text_color=TEXT_MUTED,
            font=ctk.CTkFont(family=FONT_SMALL[0], size=FONT_SMALL[1]),
        ).grid(row=0, column=0, padx=(SPACE_MD, SPACE_SM), pady=SPACE_SM)
        self._live_anomaly_label = ctk.CTkLabel(
            anomaly_frame, text="—",
            text_color=TEXT_MUTED,
            font=ctk.CTkFont(family=FONT_BODY_BOLD[0], size=FONT_BODY_BOLD[1],
                             weight="bold"),
        )
        self._live_anomaly_label.grid(row=0, column=1, padx=(0, SPACE_MD),
                                       pady=SPACE_SM)

        # IF Anomaly info button
        ctk.CTkButton(
            counters,
            text="?",
            width=22, height=22,
            corner_radius=11,
            fg_color=BG_PANEL, hover_color=BTN_SECONDARY_HOVER,
            text_color=TEXT_MUTED,
            border_width=1, border_color=BORDER_SUBTLE,
            font=ctk.CTkFont(family=FONT_SMALL[0], size=FONT_SMALL[1],
                             weight="bold"),
            command=self._show_if_anomaly_info,
        ).grid(row=0, column=4, padx=(0, SPACE_MD), sticky="w")

        # Focus toggle button
        self._live_focus_btn = ctk.CTkButton(
            counters,
            text="⛶  Focus",
            width=80, height=BTN_HEIGHT_SECONDARY,
            corner_radius=BTN_CORNER_RADIUS,
            fg_color=BTN_SECONDARY_BG, hover_color=BTN_SECONDARY_HOVER,
            text_color=TEXT_PRIMARY,
            font=ctk.CTkFont(family=FONT_SMALL[0], size=FONT_SMALL[1]),
            command=self._live_toggle_focus,
        )
        self._live_focus_btn.grid(row=0, column=5, padx=(0, 0), sticky="w")

        status_row = ctk.CTkFrame(live_ctrl.body, fg_color="transparent")
        status_row.grid(row=2, column=0, sticky="ew")
        status_row.grid_columnconfigure(0, weight=1)

        self._live_status = ctk.CTkLabel(
            status_row,
            text="Idle — real-time detection not started.",
            text_color=TEXT_MUTED,
            font=ctk.CTkFont(family=FONT_SMALL[0], size=FONT_SMALL[1]),
            anchor="w",
        )
        self._live_status.grid(row=0, column=0, sticky="w")

        self._summary_btn = ctk.CTkButton(
            status_row,
            text="▶  Session Summary",
            height=BTN_HEIGHT_SECONDARY,
            corner_radius=BTN_CORNER_RADIUS,
            fg_color=BTN_SECONDARY_BG, hover_color=BTN_SECONDARY_HOVER,
            text_color=TEXT_PRIMARY,
            font=ctk.CTkFont(family=FONT_SMALL[0], size=FONT_SMALL[1]),
            command=self._show_session_summary,
        )
        self._summary_btn.grid(row=0, column=1, padx=(SPACE_MD, 0))
        self._summary_btn.grid_remove()   # hidden until a session completes

        self._live_focus_mode = False

        # RF model status — checked once when screen loads
        self._rf_status = ctk.CTkLabel(
            live_ctrl.body,
            text="RF model: checking…",
            text_color=TEXT_MUTED,
            font=ctk.CTkFont(family=FONT_SMALL[0], size=9),
            anchor="w",
        )
        self._rf_status.grid(row=3, column=0, sticky="w", pady=(0, SPACE_XS))
        threading.Thread(target=self._check_rf_model, daemon=True).start()

        # ── Detection tier legend ──────────────────────────────────────────────
        from frontend.utils.theme import (
            DT_RULE_FG, DT_RULE_BG, DT_HYBRID_FG, DT_HYBRID_BG,
            DT_AI_FG, DT_AI_BG, DT_UNKNOWN_FG, DT_UNKNOWN_BG,
        )
        legend_frame = ctk.CTkFrame(
            outer, fg_color=BG_PANEL,
            corner_radius=8, border_width=1, border_color=BORDER_SUBTLE,
        )
        legend_frame.grid(row=1, column=0,
                          padx=SPACE_2XL, pady=(0, SPACE_SM),
                          sticky="ew")
        self._live_legend_frame = legend_frame

        ctk.CTkLabel(
            legend_frame, text="Detection Tiers:",
            font=ctk.CTkFont(family=FONT_SMALL[0], size=FONT_SMALL[1],
                             weight="bold"),
            text_color=TEXT_SECONDARY,
        ).grid(row=0, column=0, padx=(SPACE_LG, SPACE_MD), pady=SPACE_SM)

        _tiers = [
            ("RULE",    DT_RULE_FG,    DT_RULE_BG,    "Rule engine triggered — no AI involvement"),
            ("AI+RULE", DT_HYBRID_FG,  DT_HYBRID_BG,  "Rule + Isolation Forest elevated score"),
            ("AI",      DT_AI_FG,      DT_AI_BG,      "IF anomaly classified by RF model"),
            ("AI?",     DT_UNKNOWN_FG, DT_UNKNOWN_BG,  "IF anomaly — RF below confidence threshold"),
        ]
        for col, (badge, fg, bg, tip) in enumerate(_tiers, start=1):
            cell = ctk.CTkFrame(legend_frame, fg_color="transparent")
            cell.grid(row=0, column=col, padx=(0, SPACE_MD), pady=SPACE_SM)
            ctk.CTkLabel(
                cell, text=badge,
                font=ctk.CTkFont(family=FONT_BADGE[0], size=FONT_BADGE[1],
                                 weight=FONT_BADGE[2]),
                text_color=fg, fg_color=bg,
                corner_radius=4, width=52, height=20, anchor="center",
            ).grid(row=0, column=0, padx=(0, SPACE_XS))
            ctk.CTkLabel(
                cell, text=tip,
                font=ctk.CTkFont(family=FONT_SMALL[0], size=9),
                text_color=TEXT_MUTED,
            ).grid(row=0, column=1)

        # ── Recent live events card ────────────────────────────────────────────
        events_card = SectionCard(
            outer,
            title="Recent Alerts",
            title_right="",
            accent_title=True,
            padding=0,
        )
        events_card.grid(row=2, column=0,
                         padx=SPACE_2XL, pady=(0, SPACE_2XL),
                         sticky="nsew")
        events_card.body.grid_columnconfigure(0, weight=1)
        events_card.body.grid_rowconfigure(0, weight=1)
        self._live_events_card = events_card

        self._live_events_list = ctk.CTkScrollableFrame(
            events_card.body, fg_color="transparent",
        )
        self._live_events_list.grid(row=0, column=0,
                                     padx=SPACE_LG, pady=SPACE_SM,
                                     sticky="nsew")
        self._live_events_list.grid_columnconfigure(0, weight=1)

        # Placeholder shown before any events arrive
        self._live_empty_label = ctk.CTkLabel(
            self._live_events_list,
            text="No alerts yet — start real-time detection to begin.",
            text_color=TEXT_MUTED,
            font=ctk.CTkFont(family=FONT_BODY[0], size=FONT_BODY[1]),
        )
        self._live_empty_label.grid(row=0, column=0,
                                     padx=SPACE_XL, pady=SPACE_2XL)

    # ─────────────────────────────────────────────────────────────────────────
    # Deep ML layer — actions (unchanged logic from original)
    # ─────────────────────────────────────────────────────────────────────────

    def _deep_toggle(self):
        if not self._deep_running:
            self._deep_start()
        else:
            self._deep_stop()

    def _deep_start(self):
        iface    = self._deep_iface_var.get() or "Wi-Fi"
        duration = self._deep_duration_entry.get().strip()
        try:
            duration = int(duration) if duration else 15
        except ValueError:
            duration = 15

        try:
            resp   = start_capture(interface=iface, duration=duration)
            status = resp.get("status", "")
            if status == "already_running":
                self._deep_status.configure(
                    text=f"⚠  Capture already running on '{resp.get('interface')}'.",
                    text_color=STATUS_WARNING,
                )
                return

            self._deep_running    = True
            self._deep_seen_count = 0

            # Reveal the results card (was hidden with grid_remove)
            self._deep_results_section.grid()

            self._deep_toggle_btn.configure(
                text="⏹  Stop Deep Analysis",
                fg_color=BTN_DANGER_BG, hover_color=BTN_DANGER_HOVER,
            )
            self._deep_card.update_title_right("● RUNNING", color=STATUS_OK)
            started = resp.get("started_at", "")[:19].replace("T", " ")
            self._deep_status.configure(
                text=f"●  Capturing on '{iface}' for {duration}s — started {started}",
                text_color=STATUS_OK,
            )
            self._deep_poll()
        except APIError as e:
            self._deep_status.configure(
                text=f"✗  {e}", text_color=STATUS_CRITICAL)

    def _deep_stop(self):
        try:
            stop_capture()
        except APIError:
            pass
        finally:
            self._deep_running = False
            if self._deep_after_id:
                self.after_cancel(self._deep_after_id)
                self._deep_after_id = None
            self._deep_toggle_btn.configure(
                text="▶  Start Deep Analysis",
                fg_color=BTN_PRIMARY_BG, hover_color=BTN_PRIMARY_HOVER,
            )
            self._deep_card.update_title_right("")
            self._deep_status.configure(
                text="Capture stopped.", text_color=TEXT_MUTED)

    def _deep_poll(self):
        if not self._deep_running:
            return

        def _fetch():
            try:
                return get_capture_status(), None
            except APIError as e:
                return None, str(e)

        def _apply(status, err):
            if not self._deep_running:
                return
            if err:
                self._deep_status.configure(
                    text=f"Poll error: {err}", text_color=STATUS_WARNING)
                self._deep_after_id = self.after(_DEEP_POLL_MS, self._deep_poll)
                return

            running = status.get("running", False)
            results = status.get("results", [])
            error   = status.get("error")

            if not hasattr(self, "_deep_table"):
                self._deep_table = TrafficTable(self._deep_results_section.body)
                self._deep_table.grid(row=0, column=0,
                                      padx=SPACE_LG, pady=SPACE_SM,
                                      sticky="nsew")
                self._deep_results_section.body.grid_columnconfigure(0, weight=1)
                self._deep_results_section.body.grid_rowconfigure(0, weight=1)

            new_results = results[self._deep_seen_count:]
            for r in new_results:
                self._deep_table.append_result(r)
            self._deep_seen_count += len(new_results)

            if error:
                self._deep_status.configure(
                    text=f"✗  {error}", text_color=STATUS_CRITICAL)
                self._deep_on_finished()
                return

            if not running:
                total   = status.get("result_count", self._deep_seen_count)
                attacks = sum(1 for r in results if r.get("label") != "BENIGN")
                self._deep_status.configure(
                    text=f"✓  Complete — {total} flows, {attacks} threats detected.",
                    text_color=STATUS_OK if attacks == 0 else STATUS_WARNING,
                )
                self._deep_results_section.update_title_right(
                    f"● {attacks} threat{'s' if attacks != 1 else ''} detected",
                    color=STATUS_CRITICAL if attacks > 0 else STATUS_OK,
                )
                self._deep_on_finished()
                return

            chunks_done  = status.get("chunks_done", 0)
            total_chunks = status.get("total_chunks", 0)
            if total_chunks > 0:
                pct      = int((chunks_done / total_chunks) * 100)
                progress = f"{pct}% complete"
            else:
                progress = "starting…"
            self._deep_status.configure(
                text=f"●  Analyzing — {progress} — {self._deep_seen_count} flows",
                text_color=STATUS_OK,
            )
            self._deep_results_section.update_title_right(
                f"{self._deep_seen_count} flow{'s' if self._deep_seen_count != 1 else ''}",
                color=ACCENT_CYAN,
            )
            self._deep_after_id = self.after(_DEEP_POLL_MS, self._deep_poll)

        def _worker():
            status, err = _fetch()
            self.after(0, lambda: _apply(status, err))

        threading.Thread(target=_worker, daemon=True).start()

    def _deep_on_finished(self):
        self._deep_running  = False
        self._deep_after_id = None
        self._deep_toggle_btn.configure(
            text="▶  Start Deep Analysis",
            fg_color=BTN_PRIMARY_BG, hover_color=BTN_PRIMARY_HOVER,
        )
        self._deep_card.update_title_right("")

    # ─────────────────────────────────────────────────────────────────────────
    # Live Rule Monitor — actions
    # ─────────────────────────────────────────────────────────────────────────

    def _live_toggle(self):
        if not self._live_running:
            self._live_start()
        else:
            self._live_stop()

    def _live_start(self):
        iface = self._live_iface_var.get() or "Wi-Fi"
        try:
            resp   = start_live_monitor(interface=iface)
            status = resp.get("status", "")
            if status == "already_running":
                self._live_status.configure(
                    text=f"⚠  Already running on '{resp.get('interface')}'.",
                    text_color=STATUS_WARNING,
                )
                return

            self._live_poll_gen += 1      # invalidate any callbacks from previous session
            self._live_last_event_ts = None  # force event list rebuild for new session
            self._live_session_counts = {
                "RULE": 0, "HYBRID": 0, "AI-CLASSIFIED": 0, "AI-UNKNOWN": 0, "TRAP": 0
            }
            self._live_running = True
            self._summary_btn.grid_remove()
            from datetime import datetime as _dt
            self._live_session_start  = _dt.now()
            self._live_peak_score     = 0.0
            self._live_session_pkts   = 0
            self._live_session_fired  = 0
            self._live_label_counts   = {}
            self._live_last_event     = {}
            self._live_toggle_btn.configure(
                text="⏹  Stop Detection",
                fg_color=BTN_DANGER_BG, hover_color=BTN_DANGER_HOVER,
            )
            self._live_ctrl_card.update_title_right("● LIVE", color=STATUS_OK)
            started = resp.get("started_at", "")[:19].replace("T", " ")
            self._live_status.configure(
                text=f"●  Real-time detection active on '{iface}' since {started}",
                text_color=STATUS_OK,
            )
            self._live_alert_label.configure(text="0", text_color=STATUS_OK)
            self._live_pkt_label.configure(text="0")
            self._live_anomaly_label.configure(text="Pending", text_color=TEXT_MUTED)

            # Start honeypot alongside the rule monitor — unified lifecycle.
            # Non-fatal: if honeypot fails to bind (e.g. ports already in use),
            # rule-based detection continues normally.
            try:
                start_honeypot()
            except APIError:
                pass

            self._live_poll()
        except APIError as e:
            self._live_status.configure(
                text=f"✗  {e}", text_color=STATUS_CRITICAL)

    def _live_stop(self):
        try:
            stop_live_monitor()
        except APIError:
            pass
        try:
            stop_honeypot()
        except APIError:
            pass
        finally:
            self._live_poll_gen += 1   # invalidate any in-flight _apply callbacks
            self._live_running = False
            if self._live_after_id:
                self.after_cancel(self._live_after_id)
                self._live_after_id = None
            self._live_toggle_btn.configure(
                text="▶  Start Detection",
                fg_color=BTN_PRIMARY_BG, hover_color=BTN_PRIMARY_HOVER,
            )
            self._live_ctrl_card.update_title_right("")
            self._live_status.configure(
                text="Real-time detection stopped.", text_color=TEXT_MUTED)
            self._live_anomaly_label.configure(text="—", text_color=TEXT_MUTED)
            if self._live_session_start is not None or self._live_session_fired > 0:
                self._summary_btn.grid()

    def _live_poll(self):
        if not self._live_running:
            return

        gen = self._live_poll_gen   # snapshot: _apply discards itself if stale

        def _fetch():
            try:
                return get_live_status(), None
            except APIError as e:
                return None, str(e)

        def _apply(data, err):
            # Discard callback if session was stopped/restarted since we were queued
            if gen != self._live_poll_gen or not self._live_running:
                return
            if err:
                self._live_status.configure(
                    text=f"Poll error: {err}", text_color=STATUS_WARNING)
                self._live_after_id = self.after(_LIVE_POLL_MS, self._live_poll)
                return

            running = data.get("running", False)
            pkts    = data.get("packets_seen", 0)
            fired   = data.get("alerts_fired", 0)
            events  = data.get("recent_events", [])
            error   = data.get("error")
            score   = data.get("anomaly_score", 0.0)

            self._live_pkt_label.configure(text=f"{pkts:,}")
            if fired == 0:
                self._live_alert_label.configure(text="0", text_color=STATUS_OK)
            elif fired < 5:
                self._live_alert_label.configure(
                    text=str(fired), text_color=STATUS_WARNING)
            else:
                self._live_alert_label.configure(
                    text=str(fired), text_color=STATUS_CRITICAL)

            # Update AI anomaly score pill
            if score == 0.5 or not running:
                self._live_anomaly_label.configure(
                    text="Pending" if running else "—",
                    text_color=TEXT_MUTED)
            elif score < 0.35:
                self._live_anomaly_label.configure(
                    text=f"{score:.0%}", text_color=STATUS_OK)
            elif score < 0.55:
                self._live_anomaly_label.configure(
                    text=f"{score:.0%}", text_color=STATUS_INFO)
            elif score < 0.75:
                self._live_anomaly_label.configure(
                    text=f"{score:.0%}", text_color=STATUS_WARNING)
            else:
                self._live_anomaly_label.configure(
                    text=f"{score:.0%}", text_color=STATUS_CRITICAL)

            self._live_events_card.update_title_right(
                f"● {fired} alert{'s' if fired != 1 else ''}" if fired else "",
                color=STATUS_CRITICAL if fired > 0 else TEXT_MUTED,
            )

            # Tally per-tier and per-label counts from event snapshot.
            tier_counts: dict[str, int] = {
                "RULE": 0, "HYBRID": 0, "AI-CLASSIFIED": 0, "AI-UNKNOWN": 0, "TRAP": 0
            }
            label_counts: dict[str, int] = {}
            for e in events:
                dt = (e.get("detection_type") or "RULE").upper()
                if dt in tier_counts:
                    tier_counts[dt] += 1
                else:
                    tier_counts["RULE"] += 1
                lbl = e.get("label") or "Unknown"
                label_counts[lbl] = label_counts.get(lbl, 0) + 1
            self._live_session_counts = tier_counts
            self._live_label_counts   = label_counts
            self._live_session_pkts   = pkts
            self._live_session_fired  = fired
            if score > self._live_peak_score:
                self._live_peak_score = score
            if events:
                self._live_last_event = events[0]

            self._render_live_events(events)

            if error:
                self._live_status.configure(
                    text=f"✗  {error}", text_color=STATUS_CRITICAL)
                self._live_on_finished()
                return

            if not running:
                self._live_status.configure(
                    text=f"✓  Detection session complete — {pkts:,} packets, {fired} alerts.",
                    text_color=STATUS_OK if fired == 0 else STATUS_WARNING,
                )
                self._live_on_finished()
                return

            self._live_status.configure(
                text=f"●  Detecting — {pkts:,} packets seen, {fired} alerts fired",
                text_color=STATUS_OK,
            )
            self._live_after_id = self.after(_LIVE_POLL_MS, self._live_poll)

        def _worker():
            data, err = _fetch()
            self.after(0, lambda: _apply(data, err))

        threading.Thread(target=_worker, daemon=True).start()

    def _live_on_finished(self):
        self._live_running  = False
        self._live_after_id = None
        self._live_toggle_btn.configure(
            text="▶  Start Detection",
            fg_color=BTN_PRIMARY_BG, hover_color=BTN_PRIMARY_HOVER,
        )
        self._live_ctrl_card.update_title_right("")

        fired = self._live_session_fired
        self._live_events_card.update_title_right(
            f"● {fired} alert{'s' if fired != 1 else ''} — session ended" if fired
            else "Session ended — 0 alerts",
            color=STATUS_WARNING if fired else STATUS_OK,
        )
        self._summary_btn.grid()

    def _live_toggle_focus(self):
        self._live_focus_mode = not self._live_focus_mode
        if self._live_focus_mode:
            self._live_iface_row.grid_remove()
            self._live_status.grid_remove()
            self._rf_status.grid_remove()
            self._live_legend_frame.grid_remove()
            self._live_focus_btn.configure(text="⊠  Exit")
        else:
            self._live_iface_row.grid()
            self._live_status.grid()
            self._rf_status.grid()
            self._live_legend_frame.grid()
            self._live_focus_btn.configure(text="⛶  Focus")
            if not self._live_running and self._live_session_start:
                self._summary_btn.grid()

    def _show_if_anomaly_info(self):
        win = ctk.CTkToplevel(self)
        win.title("IF Anomaly Score — What does it mean?")
        win.geometry("420x280")
        win.resizable(False, False)
        win.grab_set()

        ctk.CTkLabel(
            win, text="Isolation Forest Anomaly Score",
            font=ctk.CTkFont(family=FONT_BODY_BOLD[0], size=14, weight="bold"),
            text_color=TEXT_PRIMARY,
        ).pack(pady=(SPACE_LG, SPACE_SM), padx=SPACE_XL)

        ctk.CTkLabel(
            win,
            text=(
                "The IF Anomaly score measures how unusual the current\n"
                "network window is compared to learned normal traffic.\n\n"
                "  0–34%   Normal traffic — no anomaly detected\n"
                "  35–54%  Slightly elevated — monitor closely\n"
                "  55–74%  Elevated anomaly — possible attack pattern\n"
                "  75–100% High anomaly — likely attack traffic\n\n"
                "The score alone does not trigger alerts — it is used\n"
                "alongside rule engine output to assign detection tiers."
            ),
            font=ctk.CTkFont(family=FONT_BODY[0], size=12),
            text_color=TEXT_SECONDARY,
            justify="left",
            anchor="w",
        ).pack(padx=SPACE_XL, pady=(0, SPACE_MD))

        ctk.CTkButton(
            win, text="Close", width=80,
            command=win.destroy,
            fg_color=BTN_SECONDARY_BG, hover_color=BTN_SECONDARY_HOVER,
            text_color=TEXT_PRIMARY,
        ).pack(pady=(0, SPACE_LG))

    def _show_session_summary(self):
        from datetime import datetime as _dt

        fired  = self._live_session_fired
        pkts   = self._live_session_pkts
        peak   = self._live_peak_score
        counts = self._live_session_counts
        labels = self._live_label_counts
        last_e = self._live_last_event
        start  = self._live_session_start

        # Duration
        if start:
            secs = int((_dt.now() - start).total_seconds())
            duration = f"{secs // 60}m {secs % 60}s"
        else:
            duration = "Prior session (duration unavailable)"

        # Assessment
        if peak >= 0.75 or fired >= 5:
            assessment, assess_color = "Suspicious", STATUS_CRITICAL
        elif peak >= 0.55 or fired >= 2:
            assessment, assess_color = "Mild Activity", STATUS_WARNING
        else:
            assessment, assess_color = "Benign", STATUS_OK

        # Peak IF interpretation
        if peak < 0.35:
            peak_text, peak_color = f"{peak:.0%}  (Normal)", STATUS_OK
        elif peak < 0.55:
            peak_text, peak_color = f"{peak:.0%}  (Elevated)", STATUS_INFO
        elif peak < 0.75:
            peak_text, peak_color = f"{peak:.0%}  (Suspicious)", STATUS_WARNING
        else:
            peak_text, peak_color = f"{peak:.0%}  (Critical)", STATUS_CRITICAL

        # Last alert
        last_str = "None"
        if last_e:
            last_str = (last_e.get("label") or "Unknown") + "  " + \
                       (last_e.get("timestamp") or "")[:19].replace("T", " ")

        win = ctk.CTkToplevel(self)
        win.title("Session Summary")
        win.geometry("460x420")
        win.resizable(False, False)
        win.grab_set()

        def _row(parent, label, value, value_color=None, r=0):
            ctk.CTkLabel(
                parent, text=label,
                font=ctk.CTkFont(family=FONT_SMALL[0], size=FONT_SMALL[1]),
                text_color=TEXT_MUTED, anchor="w", width=160,
            ).grid(row=r, column=0, padx=(SPACE_XL, SPACE_MD), pady=3, sticky="w")
            ctk.CTkLabel(
                parent, text=value,
                font=ctk.CTkFont(family=FONT_SMALL[0], size=FONT_SMALL[1],
                                 weight="bold"),
                text_color=value_color or TEXT_PRIMARY, anchor="w",
            ).grid(row=r, column=1, padx=(0, SPACE_XL), pady=3, sticky="w")

        # Header
        hdr = ctk.CTkFrame(win, fg_color=BG_ELEVATED, corner_radius=0)
        hdr.pack(fill="x")
        ctk.CTkLabel(
            hdr, text="Session Summary",
            font=ctk.CTkFont(family=FONT_BODY_BOLD[0], size=14, weight="bold"),
            text_color=TEXT_PRIMARY,
        ).pack(side="left", padx=SPACE_XL, pady=SPACE_MD)
        ctk.CTkLabel(
            hdr, text=assessment,
            font=ctk.CTkFont(family=FONT_BODY_BOLD[0], size=13, weight="bold"),
            text_color=assess_color,
        ).pack(side="right", padx=SPACE_XL, pady=SPACE_MD)

        body = ctk.CTkFrame(win, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=0, pady=SPACE_SM)
        body.grid_columnconfigure(1, weight=1)

        r = 0
        _row(body, "Duration",        duration,          r=r); r += 1
        _row(body, "Packets seen",    f"{pkts:,}",        r=r); r += 1
        _row(body, "Total alerts",    str(fired),
             STATUS_CRITICAL if fired >= 5 else STATUS_WARNING if fired else STATUS_OK,
             r=r); r += 1

        # Separator
        ctk.CTkFrame(body, height=1, fg_color=BORDER_SUBTLE).grid(
            row=r, column=0, columnspan=2, padx=SPACE_XL, pady=SPACE_SM, sticky="ew")
        r += 1

        # Tier breakdown
        _tier_map = {"RULE": "RULE", "HYBRID": "AI+RULE",
                     "AI-CLASSIFIED": "AI", "AI-UNKNOWN": "AI?", "TRAP": "TRAP"}
        tier_parts = "  ·  ".join(
            f"{_tier_map[k]}: {v}" for k, v in counts.items() if v > 0
        ) or "—"
        _row(body, "Alerts by tier",  tier_parts,        r=r); r += 1

        # Label breakdown
        label_parts = "  ·  ".join(
            f"{lbl}: {cnt}" for lbl, cnt in sorted(labels.items(),
                                                    key=lambda x: -x[1])
        ) or "—"
        _row(body, "Alerts by class", label_parts,       r=r); r += 1

        ctk.CTkFrame(body, height=1, fg_color=BORDER_SUBTLE).grid(
            row=r, column=0, columnspan=2, padx=SPACE_XL, pady=SPACE_SM, sticky="ew")
        r += 1

        _row(body, "Peak IF Anomaly", peak_text, peak_color, r=r); r += 1
        _row(body, "Last alert",      last_str,              r=r); r += 1

        ctk.CTkButton(
            win, text="Close", width=90,
            fg_color=BTN_SECONDARY_BG, hover_color=BTN_SECONDARY_HOVER,
            text_color=TEXT_PRIMARY, corner_radius=BTN_CORNER_RADIUS,
            command=win.destroy,
        ).pack(pady=(SPACE_SM, SPACE_LG))

    def _check_rf_model(self):
        """Query backend for RF model status and update the indicator label."""
        try:
            from frontend.utils.api_client import get_live_status
            data  = get_live_status()
            loaded = data.get("rf_model_loaded", None)
        except Exception:
            loaded = None

        def _apply():
            if loaded is True:
                self._rf_status.configure(
                    text="RF classifier: loaded  ✓  (AI-CLASSIFIED tier active)",
                    text_color=STATUS_OK,
                )
            elif loaded is False:
                self._rf_status.configure(
                    text="RF classifier: not loaded — run scripts/retrain_realtime_classifier.py  "
                         "(AI? tier only until trained)",
                    text_color=STATUS_WARNING,
                )
            else:
                self._rf_status.configure(
                    text="RF classifier: status unknown — start backend to check",
                    text_color=TEXT_MUTED,
                )
        self.after(0, _apply)

    # ── Recent live events rendering ──────────────────────────────────────────

    def _render_live_events(self, events: list):
        # Skip full rebuild if the newest event hasn't changed — avoids
        # destroying and recreating all widgets on every 2-second poll tick.
        newest_ts = events[0].get("timestamp") if events else None
        if newest_ts == self._live_last_event_ts:
            return
        self._live_last_event_ts = newest_ts

        for w in self._live_events_list.winfo_children():
            w.destroy()

        if not events:
            ctk.CTkLabel(
                self._live_events_list,
                text="No alerts yet — rules are watching…" if self._live_running
                     else "No alerts yet — start real-time detection to begin.",
                text_color=TEXT_MUTED,
                font=ctk.CTkFont(family=FONT_BODY[0], size=FONT_BODY[1]),
            ).grid(row=0, column=0, padx=SPACE_XL, pady=SPACE_2XL)
            return

        for idx, event in enumerate(events):
            self._render_live_row(idx, event)

    def _render_live_row(self, idx: int, event: dict):
        sev    = (event.get("severity") or "LOW").upper()
        label  = event.get("label") or "Unknown"
        src    = event.get("src_ip") or "N/A"
        dst    = event.get("dst_ip") or "N/A"
        dport  = event.get("dst_port") or 0
        proto  = event.get("protocol") or "N/A"
        detail = event.get("detail") or ""
        ts     = (event.get("timestamp") or "")[:19].replace("T", " ")
        conf   = event.get("confidence")
        dt_key = (event.get("detection_type") or "RULE").upper()

        accent          = SEVERITY_ACCENT.get(sev.lower(), "info")
        fg_color, _, bd = ACCENT_MAP.get(accent, ACCENT_MAP["info"])
        dt_entry        = DETECTION_TYPE_MAP.get(dt_key, DETECTION_TYPE_MAP["RULE"])

        row = ctk.CTkFrame(
            self._live_events_list,
            fg_color=BG_ELEVATED,
            corner_radius=6,
            border_width=1,
            border_color=bd,
            height=28,
            cursor="hand2",
        )
        row.grid(row=idx, column=0, padx=SPACE_SM, pady=1, sticky="ew")
        row.grid_propagate(False)
        row.grid_columnconfigure(3, weight=1)
        row.grid_rowconfigure(0, weight=1)

        _ev = event  # capture for lambda
        row.bind("<Button-1>", lambda e, ev=_ev: self._show_alert_explain(ev))

        # Left accent stripe
        stripe = ctk.CTkFrame(row, width=3, fg_color=fg_color, corner_radius=2)
        stripe.grid(row=0, column=0, sticky="ns", padx=(4, 0), pady=3)
        stripe.grid_propagate(False)

        # Severity badge
        StatusBadge(row, text=sev, severity=sev.lower(), height=18, width=52,
                    padx=0, pady=0).grid(
            row=0, column=1, padx=(5, 5), pady=3,
        )

        # Attack label
        ctk.CTkLabel(
            row, text=label,
            font=ctk.CTkFont(family=FONT_BODY_BOLD[0], size=11,
                             weight=FONT_BODY_BOLD[2]),
            text_color=fg_color, anchor="w", width=130,
        ).grid(row=0, column=2, padx=(0, SPACE_SM), pady=3, sticky="w")

        # Flow + optional truncated detail inline
        flow_str = (f"{src}  →  {dst}:{dport}  {proto}"
                    if src != "N/A" else f"Port {dport}  {proto}")
        if detail:
            short = detail[:50] + "…" if len(detail) > 50 else detail
            flow_str = f"{flow_str}  ·  {short}"
        ctk.CTkLabel(
            row, text=flow_str,
            font=ctk.CTkFont(family=FONT_MONO[0], size=10),
            text_color=TEXT_SECONDARY, anchor="w",
        ).grid(row=0, column=3, padx=(0, SPACE_SM), pady=3, sticky="ew")

        # Right pills: DT badge | confidence | timestamp
        pills = ctk.CTkFrame(row, fg_color="transparent")
        pills.grid(row=0, column=4, padx=(2, SPACE_SM), pady=3, sticky="e")

        dt_fg, dt_bg, dt_text = dt_entry
        ctk.CTkLabel(
            pills, text=dt_text,
            font=ctk.CTkFont(family=FONT_BADGE[0], size=FONT_BADGE[1],
                             weight=FONT_BADGE[2]),
            text_color=dt_fg, fg_color=dt_bg,
            corner_radius=4, width=48, height=18, anchor="center",
        ).grid(row=0, column=0, padx=(0, 3))

        if conf is not None:
            ctk.CTkLabel(
                pills, text=f"{conf:.0%}",
                font=ctk.CTkFont(family=FONT_BADGE[0], size=FONT_BADGE[1],
                                 weight=FONT_BADGE[2]),
                text_color=fg_color, fg_color="transparent",
                height=18, anchor="center",
            ).grid(row=0, column=1, padx=(0, 3))

        ctk.CTkLabel(
            pills, text=ts,
            font=ctk.CTkFont(family=FONT_SMALL[0], size=9),
            text_color=TEXT_MUTED, anchor="e",
        ).grid(row=0, column=2)

        # Propagate click to all children so any click on the row opens explainer
        def _bind_click(widget, ev=event):
            widget.bind("<Button-1>", lambda e: self._show_alert_explain(ev))
            for child in widget.winfo_children():
                _bind_click(child, ev)
        _bind_click(row)

    # ── Alert explainability popup ────────────────────────────────────────────

    def _show_alert_explain(self, event: dict):
        label    = event.get("label") or "Unknown"
        sev      = (event.get("severity") or "LOW").upper()
        src      = event.get("src_ip") or "N/A"
        dst      = event.get("dst_ip") or "N/A"
        dport    = str(event.get("dst_port") or "N/A")
        sport    = str(event.get("src_port") or "N/A")
        proto    = event.get("protocol") or "N/A"
        ts       = (event.get("timestamp") or "")[:19].replace("T", " ")
        detail   = event.get("detail") or ""
        conf     = event.get("confidence")
        dt_key   = (event.get("detection_type") or "RULE").upper()
        if_score = event.get("anomaly_score") or event.get("if_score")

        # Map DT key → human label
        _dt_label = {
            "RULE": "RULE — rule engine only, no AI involvement",
            "HYBRID": "AI+RULE — rule triggered AND IF anomaly score elevated",
            "AI-CLASSIFIED": "AI — Isolation Forest anomaly classified by RF model",
            "AI-UNKNOWN": "AI? — IF anomaly detected, RF confidence below threshold",
        }
        dt_desc = _dt_label.get(dt_key, dt_key)

        # Human-readable reason per label
        _reasons = {
            "SYN Flood":        "SYN packet rate was abnormally high, indicating a potential SYN flood DoS attack.",
            "Port Scan":        "Many distinct destination ports were contacted in a short window, characteristic of port scanning.",
            "UDP Flood":        "UDP packet rate was abnormally high, consistent with a UDP-based flood attack.",
            "ICMP Flood":       "ICMP packet rate exceeded threshold, indicating a potential ping flood.",
            "Connection Burst": "Total connection rate or packet rate was unusually high compared to the baseline.",
            "Brute Force":      "Repeated connection attempts to a single port detected — likely brute-force login activity.",
            "Honeypot Access":  "A connection was made to a honeypot port. No legitimate service runs there.",
            "FTP-Patator":      "Repeated FTP connection attempts detected — possible FTP brute-force.",
            "SSH-Patator":      "Repeated SSH connection attempts detected — possible SSH brute-force.",
            "DoS slowloris":    "Slow HTTP connection pattern detected — consistent with Slowloris DoS.",
            "DoS Hulk":         "High HTTP request rate detected — consistent with Hulk DoS.",
            "DoS GoldenEye":    "HTTP flood with keep-alive connections — consistent with GoldenEye DoS.",
            "DDoS":             "Distributed high-rate traffic from multiple sources detected.",
            "Heartbleed":       "OpenSSL Heartbleed exploit pattern detected in flow features.",
            "Web Attack":       "HTTP-based attack pattern detected (SQL injection, XSS, or brute-force path).",
            "Infiltration":     "Anomalous internal lateral movement or data exfiltration pattern.",
            "Bot":              "Traffic features consistent with botnet command-and-control communication.",
        }
        reason = _reasons.get(label)
        if reason is None:
            # Generic fallback: use detail if present, else derive from label
            if detail:
                reason = detail
            elif label == "BENIGN":
                reason = "Traffic classified as normal by the detection pipeline."
            else:
                reason = f"Traffic pattern matched detection rule or ML model for '{label}'."

        # Score interpretation
        if if_score is not None:
            if if_score < 0.35:
                score_interp = f"{if_score:.0%}  — Normal (no anomaly)"
                score_color  = STATUS_OK
            elif if_score < 0.55:
                score_interp = f"{if_score:.0%}  — Slightly elevated"
                score_color  = STATUS_INFO
            elif if_score < 0.75:
                score_interp = f"{if_score:.0%}  — Suspicious"
                score_color  = STATUS_WARNING
            else:
                score_interp = f"{if_score:.0%}  — Critical"
                score_color  = STATUS_CRITICAL
        else:
            score_interp = "N/A"
            score_color  = TEXT_MUTED

        accent          = SEVERITY_ACCENT.get(sev.lower(), "info")
        fg_color, _, _bd = ACCENT_MAP.get(accent, ACCENT_MAP["info"])

        win = ctk.CTkToplevel(self)
        win.title("Alert Explanation")
        win.geometry("500x480")
        win.resizable(False, False)
        win.grab_set()

        # Header bar
        hdr = ctk.CTkFrame(win, fg_color=BG_ELEVATED, corner_radius=0)
        hdr.pack(fill="x")
        ctk.CTkLabel(
            hdr, text=label,
            font=ctk.CTkFont(family=FONT_BODY_BOLD[0], size=14, weight="bold"),
            text_color=fg_color,
        ).pack(side="left", padx=SPACE_XL, pady=SPACE_MD)
        StatusBadge(hdr, text=sev, severity=sev.lower()).pack(
            side="right", padx=SPACE_XL, pady=SPACE_MD)

        body = ctk.CTkFrame(win, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=0, pady=SPACE_SM)
        body.grid_columnconfigure(1, weight=1)

        def _row(label_txt, value_txt, value_color=None, r=0):
            ctk.CTkLabel(
                body, text=label_txt,
                font=ctk.CTkFont(family=FONT_SMALL[0], size=FONT_SMALL[1]),
                text_color=TEXT_MUTED, anchor="w", width=150,
            ).grid(row=r, column=0, padx=(SPACE_XL, SPACE_MD), pady=2, sticky="w")
            ctk.CTkLabel(
                body, text=value_txt,
                font=ctk.CTkFont(family=FONT_SMALL[0], size=FONT_SMALL[1],
                                 weight="bold"),
                text_color=value_color or TEXT_PRIMARY, anchor="w",
                wraplength=280,
            ).grid(row=r, column=1, padx=(0, SPACE_XL), pady=2, sticky="w")

        r = 0
        _row("Detection tier",   dt_desc,                  fg_color, r=r); r += 1
        _row("Severity",         sev,                      fg_color, r=r); r += 1

        ctk.CTkFrame(body, height=1, fg_color=BORDER_SUBTLE).grid(
            row=r, column=0, columnspan=2, padx=SPACE_XL, pady=SPACE_SM, sticky="ew"); r += 1

        _row("Source IP",        src,                      None,     r=r); r += 1
        _row("Source port",      sport,                    None,     r=r); r += 1
        _row("Destination IP",   dst,                      None,     r=r); r += 1
        _row("Destination port", dport,                    None,     r=r); r += 1
        _row("Protocol",         proto,                    None,     r=r); r += 1

        ctk.CTkFrame(body, height=1, fg_color=BORDER_SUBTLE).grid(
            row=r, column=0, columnspan=2, padx=SPACE_XL, pady=SPACE_SM, sticky="ew"); r += 1

        if if_score is not None:
            _row("IF Anomaly score",  score_interp, score_color, r=r); r += 1
        if conf is not None:
            _row("RF confidence",     f"{conf:.0%}", fg_color,   r=r); r += 1
        _row("Timestamp",         ts or "N/A",    TEXT_MUTED,   r=r); r += 1

        ctk.CTkFrame(body, height=1, fg_color=BORDER_SUBTLE).grid(
            row=r, column=0, columnspan=2, padx=SPACE_XL, pady=SPACE_SM, sticky="ew"); r += 1

        # Why section
        ctk.CTkLabel(
            body, text="Why was this flagged?",
            font=ctk.CTkFont(family=FONT_SMALL[0], size=FONT_SMALL[1]),
            text_color=TEXT_MUTED, anchor="w",
        ).grid(row=r, column=0, padx=(SPACE_XL, SPACE_MD), pady=2, sticky="w"); r += 1
        ctk.CTkLabel(
            body, text=reason,
            font=ctk.CTkFont(family=FONT_BODY[0], size=FONT_BODY[1]),
            text_color=TEXT_PRIMARY, anchor="w",
            wraplength=380, justify="left",
        ).grid(row=r, column=0, columnspan=2,
               padx=SPACE_XL, pady=(0, SPACE_SM), sticky="w"); r += 1

        ctk.CTkButton(
            win, text="Close", width=90,
            fg_color=BTN_SECONDARY_BG, hover_color=BTN_SECONDARY_HOVER,
            text_color=TEXT_PRIMARY, corner_radius=BTN_CORNER_RADIUS,
            command=win.destroy,
        ).pack(pady=(0, SPACE_LG))

    # ─────────────────────────────────────────────────────────────────────────
    # Lifecycle
    # ─────────────────────────────────────────────────────────────────────────

    def on_show(self):
        # Load interfaces in background so navigation is instant.
        threading.Thread(target=self._load_interfaces, daemon=True).start()
        # Resume polling if either layer was running when we navigated away.
        if self._deep_running and self._deep_after_id is None:
            self._deep_poll()
        if self._live_running and self._live_after_id is None:
            self._live_poll()
        # Check backend state once — if a session ended before this app launch,
        # populate session data from the backend snapshot and show the button.
        if not self._live_running and self._live_session_start is None:
            threading.Thread(target=self._probe_last_session, daemon=True).start()

    def _probe_last_session(self):
        try:
            data   = get_live_status()
            fired  = data.get("alerts_fired", 0)
            pkts   = data.get("packets_seen", 0)
            events = data.get("recent_events", [])
            score  = data.get("anomaly_score", 0.0)
            if fired == 0 and pkts == 0:
                return   # no prior session data worth showing
        except Exception:
            return

        # Reconstruct minimal session state from backend snapshot
        def _apply():
            if self._live_running:
                return   # user already started a new session
            self._live_session_pkts  = pkts
            self._live_session_fired = fired
            self._live_peak_score    = score
            self._live_last_event    = events[0] if events else {}
            # Tally tiers and labels from event snapshot
            tier_counts = {"RULE": 0, "HYBRID": 0, "AI-CLASSIFIED": 0, "AI-UNKNOWN": 0, "TRAP": 0}
            label_counts: dict[str, int] = {}
            for e in events:
                dt = (e.get("detection_type") or "RULE").upper()
                if dt in tier_counts:
                    tier_counts[dt] += 1
                else:
                    tier_counts["RULE"] += 1
                lbl = e.get("label") or "Unknown"
                label_counts[lbl] = label_counts.get(lbl, 0) + 1
            self._live_session_counts = tier_counts
            self._live_label_counts   = label_counts
            self._live_session_start  = None   # duration unknown after restart
            self._summary_btn.grid()
        self.after(0, _apply)

    def _load_interfaces(self):
        try:
            ifaces = get_interfaces()
            names  = [i["name"] for i in ifaces if i.get("name")]
            if not names:
                return
            default = next(
                (n for n in names if "wi-fi" in n.lower()), names[0]
            )
            def _apply():
                self._deep_iface_menu.configure(values=names)
                self._live_iface_menu.configure(values=names)
                self._deep_iface_var.set(default)
                self._live_iface_var.set(default)
            self.after(0, _apply)
        except APIError:
            pass

    def on_hide(self):
        # Cancel timers when leaving the screen — they resume on on_show()
        if self._deep_after_id:
            self.after_cancel(self._deep_after_id)
            self._deep_after_id = None
        if self._live_after_id:
            self.after_cancel(self._live_after_id)
            self._live_after_id = None
