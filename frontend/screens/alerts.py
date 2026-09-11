# frontend/screens/alerts.py
# ─────────────────────────────────────────────────────────────────────────────
# Alerts screen — SOC dashboard layout with focus mode.
#
# Two rows:
#   row 0: combined header bar (filters + action buttons + focus toggle) — weight=0
#   row 1: SectionCard with alerts list                                  — weight=1
#
# Focus mode hides only the filter widgets inside row 0 (grid_remove per widget),
# keeping the action buttons and focus toggle always visible.
# ─────────────────────────────────────────────────────────────────────────────
import csv
import io
import threading
import customtkinter as ctk
from tkinter import messagebox, filedialog

from frontend.components.section_card import SectionCard
from frontend.components.status_badge import StatusBadge
from frontend.utils.api_client        import get_alerts, delete_alert, APIError
from frontend.utils.config            import API_BASE_URL
from frontend.utils.theme import (
    BG_PRIMARY, BG_ELEVATED, BG_PANEL,
    TEXT_PRIMARY, TEXT_SECONDARY, TEXT_MUTED,
    STATUS_OK, STATUS_OK_BG, STATUS_CRITICAL, STATUS_WARNING, STATUS_WARNING_BG,
    STATUS_INFO, STATUS_INFO_BG,
    BORDER_SUBTLE,
    FONT_BODY, FONT_BODY_BOLD, FONT_SMALL, FONT_MONO, FONT_BADGE,
    SEVERITY_ACCENT, ACCENT_MAP,
    DETECTION_TYPE_MAP,
    DT_RULE_FG, DT_RULE_BG, DT_HYBRID_FG, DT_HYBRID_BG,
    DT_AI_FG, DT_AI_BG, DT_UNKNOWN_FG, DT_UNKNOWN_BG,
    SPACE_XS, SPACE_SM, SPACE_MD, SPACE_LG, SPACE_XL, SPACE_2XL,
    BTN_PRIMARY_BG, BTN_PRIMARY_HOVER,
    BTN_SECONDARY_BG, BTN_SECONDARY_HOVER,
    BTN_DANGER_BG, BTN_DANGER_HOVER,
    BTN_HEIGHT_SECONDARY, BTN_CORNER_RADIUS,
    CARD_CORNER_RADIUS, CARD_BORDER_WIDTH,
)

SEVERITY_OPTIONS = ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"]
SOURCE_OPTIONS   = ["All", "live", "honeypot", "pcap"]


class AlertsScreen(ctk.CTkFrame):

    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color=BG_PRIMARY, **kwargs)
        self._alerts: list = []
        self._focus_mode  = False
        self._build_ui()
        self.refresh()

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=0)   # combined header bar
        self.grid_rowconfigure(1, weight=0)   # detection tier legend
        self.grid_rowconfigure(2, weight=1)   # alerts card

        self._build_header_bar()
        self._build_legend()
        self._build_list()

    def _build_legend(self):
        legend = ctk.CTkFrame(
            self, fg_color=BG_PANEL,
            corner_radius=8, border_width=1, border_color=BORDER_SUBTLE,
        )
        legend.grid(row=1, column=0, padx=SPACE_2XL, pady=(0, SPACE_SM),
                    sticky="ew")

        ctk.CTkLabel(
            legend, text="Detection Tiers:",
            font=ctk.CTkFont(family=FONT_SMALL[0], size=FONT_SMALL[1],
                             weight="bold"),
            text_color=TEXT_SECONDARY,
        ).grid(row=0, column=0, padx=(SPACE_LG, SPACE_MD), pady=SPACE_SM)

        for col, (badge, fg, bg, tip) in enumerate([
            ("RULE",    DT_RULE_FG,    DT_RULE_BG,    "Rule engine only"),
            ("AI+RULE", DT_HYBRID_FG,  DT_HYBRID_BG,  "Rule + IF elevated score"),
            ("AI",      DT_AI_FG,      DT_AI_BG,      "IF anomaly → RF classified"),
            ("AI?",     DT_UNKNOWN_FG, DT_UNKNOWN_BG,  "IF anomaly → RF uncertain"),
        ], start=1):
            cell = ctk.CTkFrame(legend, fg_color="transparent")
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

    # ── Combined header bar (row 0): filters on left, focus button on right ───

    def _build_header_bar(self):
        # Single row — eliminates the two-row gap that pushed the card down.
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew",
                    padx=SPACE_2XL, pady=(SPACE_SM, SPACE_XS))
        header.grid_columnconfigure(4, weight=1)   # spacer between filters and buttons

        # Severity label + dropdown
        ctk.CTkLabel(
            header, text="Severity",
            text_color=TEXT_SECONDARY,
            font=ctk.CTkFont(family=FONT_SMALL[0], size=FONT_SMALL[1],
                             weight="bold"),
            anchor="w",
        ).grid(row=0, column=0, padx=(0, SPACE_SM), sticky="w")

        self._sev_var = ctk.StringVar(value="All")
        ctk.CTkOptionMenu(
            header,
            values=SEVERITY_OPTIONS, variable=self._sev_var,
            width=110, height=BTN_HEIGHT_SECONDARY,
            corner_radius=BTN_CORNER_RADIUS,
            fg_color=BG_ELEVATED,
            button_color=BTN_SECONDARY_BG,
            button_hover_color=BTN_SECONDARY_HOVER,
            text_color=TEXT_PRIMARY,
            font=ctk.CTkFont(family=FONT_BODY[0], size=FONT_BODY[1]),
        ).grid(row=0, column=1, padx=(0, SPACE_LG))

        # Source label + dropdown
        ctk.CTkLabel(
            header, text="Source",
            text_color=TEXT_SECONDARY,
            font=ctk.CTkFont(family=FONT_SMALL[0], size=FONT_SMALL[1],
                             weight="bold"),
            anchor="w",
        ).grid(row=0, column=2, padx=(0, SPACE_SM), sticky="w")

        self._src_var = ctk.StringVar(value="All")
        ctk.CTkOptionMenu(
            header,
            values=SOURCE_OPTIONS, variable=self._src_var,
            width=100, height=BTN_HEIGHT_SECONDARY,
            corner_radius=BTN_CORNER_RADIUS,
            fg_color=BG_ELEVATED,
            button_color=BTN_SECONDARY_BG,
            button_hover_color=BTN_SECONDARY_HOVER,
            text_color=TEXT_PRIMARY,
            font=ctk.CTkFont(family=FONT_BODY[0], size=FONT_BODY[1]),
        ).grid(row=0, column=3, padx=(0, SPACE_LG))

        # Spacer
        ctk.CTkFrame(header, fg_color="transparent").grid(
            row=0, column=4, sticky="ew")

        # Action buttons
        ctk.CTkButton(
            header, text="Apply",
            width=72, height=BTN_HEIGHT_SECONDARY,
            corner_radius=BTN_CORNER_RADIUS,
            fg_color=BTN_PRIMARY_BG, hover_color=BTN_PRIMARY_HOVER,
            font=ctk.CTkFont(family=FONT_BODY[0], size=FONT_BODY[1]),
            command=self.refresh,
        ).grid(row=0, column=5, padx=(0, SPACE_SM))

        ctk.CTkButton(
            header, text="↻",
            width=36, height=BTN_HEIGHT_SECONDARY,
            corner_radius=BTN_CORNER_RADIUS,
            fg_color=BTN_SECONDARY_BG, hover_color=BTN_SECONDARY_HOVER,
            text_color=TEXT_PRIMARY,
            font=ctk.CTkFont(family=FONT_BODY[0], size=FONT_BODY[1]),
            command=self.refresh,
        ).grid(row=0, column=6, padx=(0, SPACE_SM))

        ctk.CTkButton(
            header, text="🗑",
            width=36, height=BTN_HEIGHT_SECONDARY,
            corner_radius=BTN_CORNER_RADIUS,
            fg_color=BTN_DANGER_BG, hover_color=BTN_DANGER_HOVER,
            font=ctk.CTkFont(family=FONT_BODY[0], size=FONT_BODY[1]),
            command=self._confirm_clear,
        ).grid(row=0, column=7, padx=(0, SPACE_SM))

        ctk.CTkButton(
            header, text="⬇ CSV",
            width=68, height=BTN_HEIGHT_SECONDARY,
            corner_radius=BTN_CORNER_RADIUS,
            fg_color=BTN_SECONDARY_BG, hover_color=BTN_SECONDARY_HOVER,
            text_color=TEXT_PRIMARY,
            font=ctk.CTkFont(family=FONT_BODY[0], size=FONT_BODY[1]),
            command=self._export_csv,
        ).grid(row=0, column=8, padx=(0, SPACE_SM))

        # Focus button — rightmost
        self._focus_btn = ctk.CTkButton(
            header,
            text="⤢  Focus",
            width=90, height=BTN_HEIGHT_SECONDARY,
            corner_radius=BTN_CORNER_RADIUS,
            fg_color=BTN_SECONDARY_BG, hover_color=BTN_SECONDARY_HOVER,
            text_color=TEXT_PRIMARY,
            font=ctk.CTkFont(family=FONT_SMALL[0], size=FONT_SMALL[1],
                             weight="bold"),
            command=self._toggle_focus,
        )
        self._focus_btn.grid(row=0, column=9, padx=(SPACE_MD, 0))

        # Keep a reference to the filter widgets for focus mode hide/show
        self._header_bar    = header
        self._filter_widgets = [
            header.grid_slaves(row=0, column=c)[0]
            for c in range(5)   # columns 0-4: labels, dropdowns, spacer
            if header.grid_slaves(row=0, column=c)
        ]

    # ── Alerts section card (row 2) ───────────────────────────────────────────

    def _build_list(self):
        self._card = SectionCard(
            self,
            title="Alerts",
            title_right="",
            accent_title=True,
            padding=0,
        )
        self._card.grid(
            row=2, column=0,
            padx=SPACE_2XL,
            pady=(0, SPACE_SM),
            sticky="nsew",
        )
        self._card.body.grid_columnconfigure(0, weight=1)
        self._card.body.grid_rowconfigure(0, weight=1)

        self._list_frame = ctk.CTkScrollableFrame(
            self._card.body, fg_color="transparent",
        )
        self._list_frame.grid(row=0, column=0,
                              padx=SPACE_LG, pady=SPACE_SM,
                              sticky="nsew")
        self._list_frame.grid_columnconfigure(0, weight=1)

    # ── Focus mode ────────────────────────────────────────────────────────────

    def _toggle_focus(self):
        if self._focus_mode:
            self._exit_focus()
        else:
            self._enter_focus()

    def _enter_focus(self):
        for w in self._filter_widgets:
            w.grid_remove()
        self._focus_btn.configure(text="⤡  Normal View")
        self._focus_mode = True

    def _exit_focus(self):
        for w in self._filter_widgets:
            w.grid()
        self._focus_btn.configure(text="⤢  Focus")
        self._focus_mode = False

    # ── Data loading ──────────────────────────────────────────────────────────

    def refresh(self):
        sev = self._sev_var.get() if self._sev_var.get() != "All" else None
        src = self._src_var.get() if self._src_var.get() != "All" else None
        self._card.update_title_right("Loading…", color=TEXT_MUTED)
        threading.Thread(
            target=lambda: self._fetch(sev, src), daemon=True
        ).start()

    def _fetch(self, severity, source):
        try:
            alerts = get_alerts(limit=200, severity=severity, source=source)
            self.after(0, lambda: self._render(alerts))
        except APIError as e:
            _msg = f"Error: {e}"
            self.after(0, lambda: self._card.update_title_right(
                _msg, color=STATUS_CRITICAL))

    def _render(self, alerts: list):
        for w in self._list_frame.winfo_children():
            w.destroy()
        self._alerts = alerts

        count = len(alerts)
        self._card.update_title_right(
            f"● {count} alert{'s' if count != 1 else ''} found",
            color=STATUS_CRITICAL if count > 0 else TEXT_MUTED,
        )

        if not alerts:
            ctk.CTkLabel(
                self._list_frame,
                text="No alerts found.",
                text_color=TEXT_MUTED,
                font=ctk.CTkFont(family=FONT_BODY[0], size=FONT_BODY[1]),
            ).grid(row=0, column=0, padx=SPACE_XL, pady=SPACE_2XL)
            return

        for i, alert in enumerate(alerts):
            self._render_row(i, alert)

    def _render_row(self, idx: int, alert: dict):
        sev      = (alert.get("severity") or "LOW").upper()
        ts       = (alert.get("timestamp") or "")[:19].replace("T", " ")
        src      = alert.get("src_ip") or "N/A"
        dst      = alert.get("dst_ip") or "N/A"
        sp       = alert.get("src_port") or 0
        dp       = alert.get("dst_port") or 0
        proto    = alert.get("protocol") or "N/A"
        label    = alert.get("label") or "Unknown"
        source   = (alert.get("source") or "pcap").lower()
        conf     = alert.get("confidence")
        conf_str = f"{conf:.0%}" if conf is not None else None
        detail   = alert.get("detail") or ""
        dt_key   = (alert.get("detection_type") or "RULE").upper()

        accent             = SEVERITY_ACCENT.get(sev.lower(), "info")
        fg_color, _, bd    = ACCENT_MAP.get(accent, ACCENT_MAP["info"])

        flow_str = (f"{src}:{sp}  →  {dst}:{dp}   {proto}"
                    if src != "N/A" or dst != "N/A"
                    else (f"Port {dp}   {proto}" if dp else "N/A"))

        # Source pill metadata
        _src_map = {
            "live":     ("LIVE",  STATUS_OK,      STATUS_OK_BG),
            "honeypot": ("TRAP",  STATUS_WARNING, STATUS_WARNING_BG),
            "pcap":     ("PCAP",  STATUS_INFO,    STATUS_INFO_BG),
        }
        s_text, s_fg, s_bg = _src_map.get(source, _src_map["pcap"])

        dt_entry = DETECTION_TYPE_MAP.get(dt_key, DETECTION_TYPE_MAP["RULE"])

        row = ctk.CTkFrame(
            self._list_frame,
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
        row.bind("<Button-1>", lambda e, a=alert: self._show_alert_explain(a))

        # Left accent stripe
        stripe = ctk.CTkFrame(row, width=3, fg_color=fg_color, corner_radius=2)
        stripe.grid(row=0, column=0, sticky="ns", padx=(4, 0), pady=3)
        stripe.grid_propagate(False)

        StatusBadge(row, text=sev, severity=sev.lower(), height=18, width=52,
                    padx=0, pady=0).grid(
            row=0, column=1, padx=(5, 5), pady=3,
        )

        ctk.CTkLabel(
            row, text=label,
            font=ctk.CTkFont(family=FONT_BODY_BOLD[0], size=11,
                             weight=FONT_BODY_BOLD[2]),
            text_color=fg_color, anchor="w", width=130,
        ).grid(row=0, column=2, padx=(0, SPACE_SM), pady=3, sticky="w")

        # Flow + optional truncated detail inline
        display_flow = flow_str
        if detail:
            short = detail[:50] + "…" if len(detail) > 50 else detail
            display_flow = f"{flow_str}  ·  {short}"
        ctk.CTkLabel(
            row, text=display_flow,
            font=ctk.CTkFont(family=FONT_MONO[0], size=10),
            text_color=TEXT_SECONDARY, anchor="w",
        ).grid(row=0, column=3, padx=(0, SPACE_SM), pady=3, sticky="ew")

        # Pills: source, detection type, confidence, timestamp, delete
        pills = ctk.CTkFrame(row, fg_color="transparent")
        pills.grid(row=0, column=4, padx=(2, SPACE_SM), pady=3, sticky="e")

        ctk.CTkLabel(
            pills, text=s_text,
            font=ctk.CTkFont(family=FONT_BADGE[0], size=FONT_BADGE[1],
                             weight=FONT_BADGE[2]),
            text_color=s_fg, fg_color=s_bg,
            corner_radius=4, width=42, height=18, anchor="center",
        ).grid(row=0, column=0, padx=(0, 3))

        dt_fg, dt_bg, dt_text_val = dt_entry
        ctk.CTkLabel(
            pills, text=dt_text_val,
            font=ctk.CTkFont(family=FONT_BADGE[0], size=FONT_BADGE[1],
                             weight=FONT_BADGE[2]),
            text_color=dt_fg, fg_color=dt_bg,
            corner_radius=4, width=48, height=18, anchor="center",
        ).grid(row=0, column=1, padx=(0, 3))

        if conf_str:
            ctk.CTkLabel(
                pills, text=conf_str,
                font=ctk.CTkFont(family=FONT_BADGE[0], size=FONT_BADGE[1],
                                 weight=FONT_BADGE[2]),
                text_color=fg_color, fg_color="transparent",
                height=18, anchor="center",
            ).grid(row=0, column=2, padx=(0, 3))

        ctk.CTkLabel(
            pills, text=ts,
            font=ctk.CTkFont(family=FONT_SMALL[0], size=9),
            text_color=TEXT_MUTED, anchor="e",
        ).grid(row=0, column=3, padx=(0, 3))

        alert_id = alert.get("id")
        if alert_id is not None:
            ctk.CTkButton(
                pills, text="✕",
                width=22, height=18, corner_radius=4,
                fg_color="transparent", hover_color=BTN_DANGER_BG,
                text_color=TEXT_MUTED,
                command=lambda aid=alert_id: self._delete(aid),
            ).grid(row=0, column=4)

        # Bind click to row and all children except the delete button (column 4 of pills)
        def _bind_click(widget, a=alert, skip=None):
            if widget is skip:
                return
            widget.bind("<Button-1>", lambda e: self._show_alert_explain(a))
            for child in widget.winfo_children():
                _bind_click(child, a, skip)
        delete_btn = pills.grid_slaves(row=0, column=4)
        _bind_click(row, skip=delete_btn[0] if delete_btn else None)

    # ── Alert explainability popup ────────────────────────────────────────────

    def _show_alert_explain(self, alert: dict):
        label    = alert.get("label") or "Unknown"
        sev      = (alert.get("severity") or "LOW").upper()
        src      = alert.get("src_ip") or "N/A"
        dst      = alert.get("dst_ip") or "N/A"
        dport    = str(alert.get("dst_port") or "N/A")
        sport    = str(alert.get("src_port") or "N/A")
        proto    = alert.get("protocol") or "N/A"
        ts       = (alert.get("timestamp") or "")[:19].replace("T", " ")
        conf     = alert.get("confidence")
        dt_key   = (alert.get("detection_type") or "RULE").upper()
        if_score = alert.get("anomaly_score") or alert.get("if_score")
        detail   = alert.get("detail") or ""

        _dt_label = {
            "RULE": "RULE — rule engine only, no AI involvement",
            "HYBRID": "AI+RULE — rule triggered AND IF anomaly score elevated",
            "AI-CLASSIFIED": "AI — Isolation Forest anomaly classified by RF model",
            "AI-UNKNOWN": "AI? — IF anomaly detected, RF confidence below threshold",
        }
        dt_desc = _dt_label.get(dt_key, dt_key)

        _reasons = {
            "SYN Flood":        "SYN packet rate was abnormally high, indicating a potential SYN flood DoS attack.",
            "Live Port Scan":   "Many distinct destination ports were contacted in a short window, characteristic of port scanning.",
            "Port Scan":        "Many distinct destination ports were contacted in a short window, characteristic of port scanning.",
            "UDP Flood":        "UDP packet rate was abnormally high, consistent with a UDP-based flood attack.",
            "UDP Burst":        "High variety of UDP destination ports detected in a short window.",
            "ICMP Flood":       "ICMP packet rate exceeded threshold, indicating a potential ping flood.",
            "Connection Burst": "Total packet rate from this source was unusually high compared to the baseline.",
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
            "BENIGN":           "Traffic classified as normal — no attack detected.",
        }
        reason = _reasons.get(label)
        if reason is None:
            reason = detail if detail else f"Traffic pattern matched detection rule or ML model for '{label}'."

        if if_score is not None:
            if if_score < 0.35:
                score_interp, score_color = f"{if_score:.0%}  — Normal", STATUS_OK
            elif if_score < 0.55:
                score_interp, score_color = f"{if_score:.0%}  — Slightly elevated", STATUS_INFO
            elif if_score < 0.75:
                score_interp, score_color = f"{if_score:.0%}  — Suspicious", STATUS_WARNING
            else:
                score_interp, score_color = f"{if_score:.0%}  — Critical", STATUS_CRITICAL
        else:
            score_interp, score_color = "N/A", TEXT_MUTED

        accent = SEVERITY_ACCENT.get(sev.lower(), "info")
        fg_color, _, _ = ACCENT_MAP.get(accent, ACCENT_MAP["info"])

        win = ctk.CTkToplevel(self)
        win.title("Alert Explanation")
        win.geometry("500x460")
        win.resizable(False, False)
        win.grab_set()

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
        body.pack(fill="both", expand=True)
        body.grid_columnconfigure(1, weight=1)

        def _row(lbl, val, val_color=None, r=0):
            ctk.CTkLabel(
                body, text=lbl,
                font=ctk.CTkFont(family=FONT_SMALL[0], size=FONT_SMALL[1]),
                text_color=TEXT_MUTED, anchor="w", width=150,
            ).grid(row=r, column=0, padx=(SPACE_XL, SPACE_MD), pady=2, sticky="w")
            ctk.CTkLabel(
                body, text=val,
                font=ctk.CTkFont(family=FONT_SMALL[0], size=FONT_SMALL[1],
                                 weight="bold"),
                text_color=val_color or TEXT_PRIMARY, anchor="w",
                wraplength=280,
            ).grid(row=r, column=1, padx=(0, SPACE_XL), pady=2, sticky="w")

        r = 0
        _row("Detection tier",    dt_desc,        fg_color,   r=r); r += 1
        _row("Severity",          sev,            fg_color,   r=r); r += 1

        ctk.CTkFrame(body, height=1, fg_color=BORDER_SUBTLE).grid(
            row=r, column=0, columnspan=2, padx=SPACE_XL, pady=SPACE_SM, sticky="ew"); r += 1

        _row("Source IP",         src,                        r=r); r += 1
        _row("Source port",       sport,                      r=r); r += 1
        _row("Destination IP",    dst,                        r=r); r += 1
        _row("Destination port",  dport,                      r=r); r += 1
        _row("Protocol",          proto,                      r=r); r += 1

        ctk.CTkFrame(body, height=1, fg_color=BORDER_SUBTLE).grid(
            row=r, column=0, columnspan=2, padx=SPACE_XL, pady=SPACE_SM, sticky="ew"); r += 1

        if if_score is not None:
            _row("IF Anomaly score", score_interp, score_color, r=r); r += 1
        if conf is not None:
            _row("RF confidence",  f"{conf:.0%}",  fg_color,   r=r); r += 1
        _row("Timestamp",         ts or "N/A",    TEXT_MUTED,  r=r); r += 1

        ctk.CTkFrame(body, height=1, fg_color=BORDER_SUBTLE).grid(
            row=r, column=0, columnspan=2, padx=SPACE_XL, pady=SPACE_SM, sticky="ew"); r += 1

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
               padx=SPACE_XL, pady=(0, SPACE_MD), sticky="w"); r += 1

        ctk.CTkButton(
            win, text="Close", width=90,
            fg_color=BTN_SECONDARY_BG, hover_color=BTN_SECONDARY_HOVER,
            text_color=TEXT_PRIMARY, corner_radius=BTN_CORNER_RADIUS,
            command=win.destroy,
        ).pack(pady=(0, SPACE_LG))

    # ── Actions ───────────────────────────────────────────────────────────────

    def _delete(self, alert_id: int):
        try:
            delete_alert(alert_id)
            self.refresh()
        except APIError as e:
            self._card.update_title_right(
                f"Delete failed: {e}", color=STATUS_CRITICAL)

    def _confirm_clear(self):
        confirmed = messagebox.askyesno(
            title="Clear All Alerts",
            message="This will permanently delete ALL alerts from the database.\n\nAre you sure?",
        )
        if confirmed:
            threading.Thread(target=self._do_clear, daemon=True).start()

    def _do_clear(self):
        try:
            import httpx
            r = httpx.delete(f"{API_BASE_URL}/alerts/clear", timeout=10)
            r.raise_for_status()
            deleted = r.json().get("deleted", "?")
            self.after(0, lambda: self._card.update_title_right(
                f"Cleared {deleted} alerts.", color=STATUS_OK))
            self.after(0, self.refresh)
        except Exception as e:
            _msg = f"Clear failed: {e}"
            self.after(0, lambda: self._card.update_title_right(
                _msg, color=STATUS_CRITICAL))

    def _export_csv(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            title="Export Alerts as CSV",
            initialfile="ids_alerts.csv",
        )
        if not path:
            return
        self._card.update_title_right("Exporting…", color=TEXT_MUTED)
        sev = self._sev_var.get() if self._sev_var.get() != "All" else None
        src = self._src_var.get() if self._src_var.get() != "All" else None
        threading.Thread(
            target=lambda: self._do_export(path, sev, src), daemon=True
        ).start()

    def _do_export(self, path: str, severity, source):
        _FIELDS = [
            "id", "timestamp", "label", "severity", "detection_type",
            "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
            "confidence", "source", "detail",
        ]
        try:
            alerts = get_alerts(limit=5000, severity=severity, source=source)
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=_FIELDS, extrasaction="ignore")
                writer.writeheader()
                writer.writerows(alerts)
            count = len(alerts)
            self.after(0, lambda: self._card.update_title_right(
                f"Exported {count} alert{'s' if count != 1 else ''} → {path}",
                color=STATUS_OK,
            ))
        except Exception as e:
            _msg = f"Export failed: {e}"
            self.after(0, lambda: self._card.update_title_right(
                _msg, color=STATUS_CRITICAL))

    def on_show(self):
        self.refresh()

    def on_hide(self):
        pass
