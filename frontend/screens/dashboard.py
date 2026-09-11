# frontend/screens/dashboard.py
# ─────────────────────────────────────────────────────────────────────────────
# Dashboard screen — overview of system stats and recent alerts.
# ─────────────────────────────────────────────────────────────────────────────
import threading
import customtkinter as ctk
from tkinter import messagebox

from frontend.components.section_card import SectionCard
from frontend.components.status_badge import StatusBadge
from frontend.utils.api_client        import get_alerts, APIError
from frontend.utils.config            import API_BASE_URL
from frontend.utils.theme import (
    BG_PRIMARY, BG_ELEVATED, BG_PANEL,
    TEXT_PRIMARY, TEXT_SECONDARY, TEXT_MUTED,
    STATUS_CRITICAL, STATUS_WARNING, STATUS_OK,
    STATUS_OK_BG, STATUS_WARNING_BG, STATUS_INFO, STATUS_INFO_BG,
    BORDER_SUBTLE,
    FONT_BODY, FONT_BODY_BOLD, FONT_SMALL, FONT_MONO, FONT_BADGE,
    SPACE_XS, SPACE_SM, SPACE_MD, SPACE_LG, SPACE_XL, SPACE_2XL,
    SEVERITY_ACCENT, ACCENT_MAP,
    DETECTION_TYPE_MAP,
    DT_RULE_FG, DT_RULE_BG, DT_HYBRID_FG, DT_HYBRID_BG,
    DT_AI_FG, DT_AI_BG, DT_UNKNOWN_FG, DT_UNKNOWN_BG,
    BTN_DANGER_BG, BTN_DANGER_HOVER,
    BTN_SECONDARY_BG, BTN_SECONDARY_HOVER,
    BTN_HEIGHT_SECONDARY, BTN_CORNER_RADIUS,
)


class DashboardScreen(ctk.CTkFrame):
    """
    Main dashboard showing recent alerts list (last 10).
    Summary metric cards are in the persistent app header (app.py).
    """

    REFRESH_INTERVAL_MS = 10_000

    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color=BG_PRIMARY, **kwargs)
        self._after_id  = None
        self._fetching  = False   # guard: prevents concurrent fetch threads
        self._build_ui()
        self.refresh()

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=0)   # action row
        self.grid_rowconfigure(1, weight=0)   # legend bar
        self.grid_rowconfigure(2, weight=1)   # alerts card

        # ── Top action row ────────────────────────────────────────────────────
        top = ctk.CTkFrame(self, fg_color="transparent")
        top.grid(row=0, column=0, padx=SPACE_2XL, pady=(SPACE_LG, SPACE_SM),
                 sticky="ew")
        top.grid_columnconfigure(0, weight=1)

        self._last_updated = ctk.CTkLabel(
            top, text="",
            font=ctk.CTkFont(family=FONT_SMALL[0], size=FONT_SMALL[1]),
            text_color=TEXT_MUTED, anchor="w",
        )
        self._last_updated.grid(row=0, column=0, sticky="w")

        btn_row = ctk.CTkFrame(top, fg_color="transparent")
        btn_row.grid(row=0, column=1, sticky="e")

        ctk.CTkButton(
            btn_row, text="↻  Refresh",
            width=100, height=BTN_HEIGHT_SECONDARY,
            corner_radius=BTN_CORNER_RADIUS,
            fg_color=BTN_SECONDARY_BG, hover_color=BTN_SECONDARY_HOVER,
            text_color=TEXT_PRIMARY,
            font=ctk.CTkFont(family=FONT_BODY[0], size=FONT_BODY[1]),
            command=self.refresh,
        ).grid(row=0, column=0, padx=(0, SPACE_SM))

        ctk.CTkButton(
            btn_row, text="🗑  Clear All",
            width=110, height=BTN_HEIGHT_SECONDARY,
            corner_radius=BTN_CORNER_RADIUS,
            fg_color=BTN_DANGER_BG, hover_color=BTN_DANGER_HOVER,
            font=ctk.CTkFont(family=FONT_BODY[0], size=FONT_BODY[1]),
            command=self._confirm_clear,
        ).grid(row=0, column=1)

        # ── Detection tier legend bar ─────────────────────────────────────────
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

        # ── Recent alerts section card ────────────────────────────────────────
        self._section = SectionCard(
            self,
            title="Recent Alerts",
            title_right="",
            accent_title=True,
            padding=0,
        )
        self._section.grid(row=2, column=0,
                           padx=SPACE_2XL, pady=(0, SPACE_2XL),
                           sticky="nsew")
        self._section.body.grid_columnconfigure(0, weight=1)
        self._section.body.grid_rowconfigure(0, weight=1)

        self._list_frame = ctk.CTkScrollableFrame(
            self._section.body,
            fg_color="transparent",
        )
        self._list_frame.grid(row=0, column=0,
                              padx=SPACE_LG, pady=SPACE_MD,
                              sticky="nsew")
        self._list_frame.grid_columnconfigure(0, weight=1)

    # ── Data loading ──────────────────────────────────────────────────────────

    def refresh(self):
        """
        Schedule a data fetch. If a fetch is already in-flight, skip —
        the result from the current fetch will update the UI when it lands.
        This prevents concurrent threads from racing to rebuild the list.
        """
        # Reschedule the auto-refresh timer regardless
        if self._after_id:
            self.after_cancel(self._after_id)
        self._after_id = self.after(self.REFRESH_INTERVAL_MS, self.refresh)

        if self._fetching:
            return   # already fetching — don't spawn a second thread

        self._fetching = True
        threading.Thread(target=self._fetch_data, daemon=True).start()

    def _fetch_data(self):
        try:
            alerts = get_alerts(limit=10)
            self.after(0, lambda: self._update_ui(alerts))
        except APIError as e:
            _msg = str(e)
            self.after(0, lambda: self._show_error(_msg))
        except Exception as e:
            _msg = f"Connection error: {e}"
            self.after(0, lambda: self._show_error(_msg))
        finally:
            self._fetching = False

    def _update_ui(self, alerts: list):
        from datetime import datetime
        count = len(alerts)
        self._last_updated.configure(
            text=f"Last updated: {datetime.now().strftime('%H:%M:%S')}",
            text_color=TEXT_MUTED,
        )
        self._section.update_title_right(
            f"● {count} recent alert{'s' if count != 1 else ''}",
            color=STATUS_CRITICAL if count > 0 else TEXT_MUTED,
        )
        self._render_recent_alerts(alerts)

    def _render_recent_alerts(self, alerts: list):
        # Destroy all existing child widgets before rebuilding
        for widget in self._list_frame.winfo_children():
            widget.destroy()

        if not alerts:
            _empty = ctk.CTkFrame(self._list_frame, fg_color="transparent")
            _empty.grid(row=0, column=0, padx=SPACE_XL, pady=SPACE_2XL)
            ctk.CTkLabel(
                _empty, text="✓",
                font=ctk.CTkFont(family=FONT_BODY_BOLD[0], size=40,
                                 weight="bold"),
                text_color=STATUS_OK,
            ).grid(row=0, column=0, pady=(0, SPACE_MD))
            ctk.CTkLabel(
                _empty, text="All Clear — No Threats Detected",
                font=ctk.CTkFont(family=FONT_BODY_BOLD[0], size=15,
                                 weight="bold"),
                text_color=TEXT_PRIMARY,
            ).grid(row=1, column=0)
            ctk.CTkLabel(
                _empty, text="The system is actively monitoring all network layers.",
                font=ctk.CTkFont(family=FONT_SMALL[0], size=FONT_SMALL[1]),
                text_color=TEXT_MUTED,
            ).grid(row=2, column=0, pady=(SPACE_SM, 0))
            return

        rendered = 0
        for alert in alerts:
            # Skip any alert that has no meaningful content.
            # Alerts with None/empty label are stale DB rows from before the
            # severity fix — they render as blank cards. Skip them cleanly.
            label = alert.get("label") or ""
            if not label.strip():
                continue
            self._render_row(rendered, alert)
            rendered += 1

        # If all alerts were skipped (all had empty labels), show empty state
        if rendered == 0:
            _empty = ctk.CTkFrame(self._list_frame, fg_color="transparent")
            _empty.grid(row=0, column=0, padx=SPACE_XL, pady=SPACE_2XL)
            ctk.CTkLabel(
                _empty, text="✓",
                font=ctk.CTkFont(family=FONT_BODY_BOLD[0], size=40,
                                 weight="bold"),
                text_color=STATUS_OK,
            ).grid(row=0, column=0, pady=(0, SPACE_MD))
            ctk.CTkLabel(
                _empty, text="All Clear — No Threats Detected",
                font=ctk.CTkFont(family=FONT_BODY_BOLD[0], size=15,
                                 weight="bold"),
                text_color=TEXT_PRIMARY,
            ).grid(row=1, column=0)
            ctk.CTkLabel(
                _empty, text="The system is actively monitoring all network layers.",
                font=ctk.CTkFont(family=FONT_SMALL[0], size=FONT_SMALL[1]),
                text_color=TEXT_MUTED,
            ).grid(row=2, column=0, pady=(SPACE_SM, 0))

    def _render_row(self, idx: int, alert: dict):
        # Defensive defaults — every field falls back gracefully
        sev      = (alert.get("severity") or "LOW").upper()
        ts       = (alert.get("timestamp") or "")[:19].replace("T", " ")
        src      = alert.get("src_ip") or "N/A"
        dst      = alert.get("dst_ip") or "N/A"
        label    = alert.get("label") or "Unknown"
        source   = (alert.get("source") or "pcap").lower()
        conf     = alert.get("confidence")
        conf_str = f"{conf:.0%}" if conf is not None else None
        detail   = alert.get("detail") or ""
        dt_key   = (alert.get("detection_type") or "RULE").upper()

        accent             = SEVERITY_ACCENT.get(sev.lower(), "info")
        fg_color, _, bd    = ACCENT_MAP.get(accent, ACCENT_MAP["info"])

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
        flow_str = f"{src}  →  {dst}"
        if detail:
            short = detail[:50] + "…" if len(detail) > 50 else detail
            flow_str = f"{flow_str}  ·  {short}"
        ctk.CTkLabel(
            row, text=flow_str,
            font=ctk.CTkFont(family=FONT_MONO[0], size=10),
            text_color=TEXT_SECONDARY, anchor="w",
        ).grid(row=0, column=3, padx=(0, SPACE_SM), pady=3, sticky="ew")

        # Pills: source, detection type, confidence, timestamp
        pills = ctk.CTkFrame(row, fg_color="transparent")
        pills.grid(row=0, column=4, padx=(2, SPACE_SM), pady=3, sticky="e")

        ctk.CTkLabel(
            pills, text=s_text,
            font=ctk.CTkFont(family=FONT_BADGE[0], size=FONT_BADGE[1],
                             weight=FONT_BADGE[2]),
            text_color=s_fg, fg_color=s_bg,
            corner_radius=4, width=42, height=18, anchor="center",
        ).grid(row=0, column=0, padx=(0, 3))

        dt_fg, dt_bg, dt_text = dt_entry
        ctk.CTkLabel(
            pills, text=dt_text,
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
        ).grid(row=0, column=3)

        def _bind_click(widget, a=alert):
            widget.bind("<Button-1>", lambda e: self._show_alert_explain(a))
            for child in widget.winfo_children():
                _bind_click(child, a)
        _bind_click(row)

    # ── Alert explainability popup ────────────────────────────────────────────

    def _show_alert_explain(self, alert: dict):
        from frontend.utils.theme import (
            ACCENT_CYAN, FONT_BODY, FONT_BODY_BOLD,
            BTN_SECONDARY_BG, BTN_SECONDARY_HOVER, BTN_CORNER_RADIUS,
            SPACE_XL, SPACE_LG, SPACE_MD,
            STATUS_OK, STATUS_INFO, STATUS_WARNING, STATUS_CRITICAL,
        )
        from frontend.components.status_badge import StatusBadge as _SB

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
            "Port Scan":        "Many distinct destination ports were contacted in a short window, characteristic of port scanning.",
            "Live Port Scan":   "Many distinct destination ports were contacted in a short window, characteristic of port scanning.",
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
        _SB(hdr, text=sev, severity=sev.lower()).pack(
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

    # ── Error state ───────────────────────────────────────────────────────────

    def _show_error(self, msg: str):
        self._last_updated.configure(
            text="Could not reach backend — retrying…",
            text_color=STATUS_WARNING,
        )

    # ── Clear all ─────────────────────────────────────────────────────────────

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
            self.after(0, lambda: self._last_updated.configure(
                text=f"Cleared {deleted} alerts.", text_color=STATUS_OK,
            ))
            self.after(500, self.refresh)
        except Exception as e:
            _msg = f"Clear failed: {e}"
            self.after(0, lambda: self._last_updated.configure(
                text=_msg, text_color=STATUS_CRITICAL,
            ))

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def on_show(self):
        """Called when navigating to this screen. Trigger a fresh fetch."""
        self.refresh()

    def on_hide(self):
        """Called when leaving this screen. Cancel the polling timer."""
        if self._after_id:
            self.after_cancel(self._after_id)
            self._after_id = None
