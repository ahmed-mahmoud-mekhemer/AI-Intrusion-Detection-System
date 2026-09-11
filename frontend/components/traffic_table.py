# frontend/components/traffic_table.py
# ─────────────────────────────────────────────────────────────────────────────
# Scrollable table for displaying detection results.
# Used in PCAP Analysis and Real-Time Monitor screens.
# ─────────────────────────────────────────────────────────────────────────────
import customtkinter as ctk
from typing import List, Dict

from frontend.components.status_badge import StatusBadge
from frontend.utils.config import SEVERITY_COLORS
from frontend.utils.theme import (
    BG_PANEL, BG_ELEVATED, TABLE_ROW_ALT_BG,
    ACCENT_CYAN,
    TEXT_PRIMARY, TEXT_SECONDARY, TEXT_MUTED,
    STATUS_OK, STATUS_INFO, STATUS_WARNING, STATUS_CRITICAL,
    BORDER_SUBTLE,
    FONT_BODY, FONT_BODY_BOLD, FONT_TABLE_HEADER, FONT_TABLE_CELL, FONT_MONO, FONT_SMALL,
    SPACE_SM, SPACE_MD, SPACE_XL, SPACE_LG,
    BTN_SECONDARY_BG, BTN_SECONDARY_HOVER, BTN_CORNER_RADIUS,
    SEVERITY_ACCENT, ACCENT_MAP,
    DETECTION_TYPE_MAP,
)
from shared.attack_labels import LABEL_SEVERITY_MAP


COLUMNS    = ["Source IP", "Dest IP", "Port", "Protocol", "Label", "Confidence", "Time"]
COL_WIDTHS = [140, 140, 60, 80, 170, 95, 160]

_PROTO_MAP = {"6": "TCP", "17": "UDP", "1": "ICMP"}


class TrafficTable(ctk.CTkScrollableFrame):
    """
    Scrollable table that displays network flow detection results.

    Usage:
        table = TrafficTable(master)
        table.load_results(list_of_result_dicts)   # PCAP mode
        table.append_result(result_dict)            # Real-time streaming
    """

    def __init__(self, master, **kwargs):
        kwargs.setdefault("fg_color", BG_PANEL)
        super().__init__(master, **kwargs)
        self._rows: List[List] = []
        self._build_header()

    def _build_header(self):
        # Subtle bottom border under header
        for col_idx, (col_name, width) in enumerate(zip(COLUMNS, COL_WIDTHS)):
            lbl = ctk.CTkLabel(
                self,
                text=col_name.upper(),
                font=ctk.CTkFont(
                    family=FONT_TABLE_HEADER[0],
                    size=FONT_TABLE_HEADER[1],
                    weight=FONT_TABLE_HEADER[2],
                ),
                width=width,
                anchor="w",
                text_color=TEXT_MUTED,
            )
            lbl.grid(
                row=0, column=col_idx,
                padx=(SPACE_SM, SPACE_MD), pady=(SPACE_SM, SPACE_MD),
                sticky="w",
            )

        # Divider below header
        divider = ctk.CTkFrame(
            self, height=1,
            fg_color=BORDER_SUBTLE,
            corner_radius=0,
        )
        divider.grid(
            row=1, column=0, columnspan=len(COLUMNS),
            sticky="ew", padx=0, pady=(0, SPACE_SM),
        )

    def load_results(self, results: List[Dict]):
        """Clear current rows and display new results."""
        self._clear_rows()
        for row_idx, result in enumerate(results):
            self._add_row(row_idx + 2, result, alt=row_idx % 2 == 1)

    def append_result(self, result: Dict):
        """Append a single result row (used for real-time streaming)."""
        row_idx = len(self._rows)
        self._add_row(row_idx + 2, result, alt=row_idx % 2 == 1)

    def _add_row(self, row_idx: int, result: Dict, alt: bool = False):
        label      = result.get("label", "")
        severity   = LABEL_SEVERITY_MAP.get(label, "LOW") or "LOW"
        accent     = SEVERITY_ACCENT.get(severity.lower(), "info")
        fg_color, _, _ = ACCENT_MAP.get(accent, ACCENT_MAP["info"])
        is_benign  = label == "BENIGN"

        confidence = result.get("confidence")
        conf_str   = f"{confidence:.0%}" if confidence is not None else "—"
        timestamp  = result.get("timestamp", "")[:19].replace("T", " ")
        proto_raw  = str(result.get("protocol", ""))
        proto      = _PROTO_MAP.get(proto_raw, proto_raw)

        row_bg = TABLE_ROW_ALT_BG if alt else "transparent"

        # Row container frame (gives us hover + alternating bg)
        row_frame = ctk.CTkFrame(
            self,
            fg_color=row_bg,
            corner_radius=6,
            cursor="hand2",
        )
        row_frame.grid(
            row=row_idx, column=0, columnspan=len(COLUMNS),
            padx=SPACE_SM, pady=1, sticky="ew",
        )
        row_frame.grid_columnconfigure(list(range(len(COLUMNS))), weight=0)
        row_frame.bind("<Button-1>", lambda e, r=result: self._show_result_explain(r))

        row_widgets = [row_frame]

        values = [
            result.get("src_ip",  ""),
            result.get("dst_ip",  ""),
            str(result.get("dst_port", "")),
            proto,
            label,
            conf_str,
            timestamp,
        ]

        for col_idx, (val, width) in enumerate(zip(values, COL_WIDTHS)):
            if col_idx == 4:
                # Label column — use StatusBadge for attack labels
                if not is_benign and label:
                    widget = StatusBadge(
                        row_frame,
                        text=label[:18] + ("…" if len(label) > 18 else ""),
                        severity=severity.lower(),
                        width=width - SPACE_MD,
                        anchor="w",
                    )
                else:
                    widget = ctk.CTkLabel(
                        row_frame,
                        text="BENIGN",
                        width=width - SPACE_MD,
                        anchor="w",
                        font=ctk.CTkFont(
                            family=FONT_TABLE_CELL[0],
                            size=FONT_TABLE_CELL[1],
                        ),
                        text_color=TEXT_MUTED,
                    )
            elif col_idx in (0, 1):
                # IP columns — monospace
                widget = ctk.CTkLabel(
                    row_frame,
                    text=val,
                    width=width,
                    anchor="w",
                    font=ctk.CTkFont(
                        family=FONT_MONO[0], size=FONT_MONO[1],
                    ),
                    text_color=ACCENT_CYAN if not is_benign else TEXT_SECONDARY,
                )
            elif col_idx == 5:
                # Confidence column
                conf_color = fg_color if not is_benign else TEXT_MUTED
                widget = ctk.CTkLabel(
                    row_frame,
                    text=val,
                    width=width,
                    anchor="w",
                    font=ctk.CTkFont(
                        family=FONT_TABLE_CELL[0],
                        size=FONT_TABLE_CELL[1],
                        weight="bold",
                    ),
                    text_color=conf_color,
                )
            elif col_idx == 6:
                # Timestamp column
                widget = ctk.CTkLabel(
                    row_frame,
                    text=val,
                    width=width,
                    anchor="w",
                    font=ctk.CTkFont(
                        family=FONT_SMALL[0], size=FONT_SMALL[1],
                    ),
                    text_color=TEXT_MUTED,
                )
            else:
                # Port, Protocol
                widget = ctk.CTkLabel(
                    row_frame,
                    text=val,
                    width=width,
                    anchor="w",
                    font=ctk.CTkFont(
                        family=FONT_TABLE_CELL[0],
                        size=FONT_TABLE_CELL[1],
                    ),
                    text_color=TEXT_SECONDARY,
                )

            widget.grid(
                row=0, column=col_idx,
                padx=(SPACE_SM, SPACE_MD), pady=SPACE_SM,
                sticky="w",
            )
            widget.bind("<Button-1>", lambda e, r=result: self._show_result_explain(r))
            row_widgets.append(widget)

        self._rows.append(row_widgets)

    def _show_result_explain(self, result: Dict):
        label    = result.get("label") or "Unknown"
        severity = LABEL_SEVERITY_MAP.get(label, "LOW") or "LOW"
        sev      = severity.upper()
        src      = result.get("src_ip") or "N/A"
        dst      = result.get("dst_ip") or "N/A"
        dport    = str(result.get("dst_port") or "N/A")
        sport    = str(result.get("src_port") or "N/A")
        proto_raw= str(result.get("protocol") or "N/A")
        _PROTO   = {"6": "TCP", "17": "UDP", "1": "ICMP"}
        proto    = _PROTO.get(proto_raw, proto_raw)
        ts       = (result.get("timestamp") or "")[:19].replace("T", " ")
        conf     = result.get("confidence")
        dt_key   = (result.get("detection_type") or "RULE").upper()

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
            "BENIGN":           "Traffic classified as normal by the ML pipeline — no attack detected.",
        }
        reason = _reasons.get(label, f"Traffic pattern matched detection model for '{label}'.")

        accent = SEVERITY_ACCENT.get(sev.lower(), "info")
        fg_color, _, _ = ACCENT_MAP.get(accent, ACCENT_MAP["info"])

        win = ctk.CTkToplevel(self)
        win.title("Alert Explanation")
        win.geometry("500x420")
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
        _row("Detection tier",    dt_desc,     fg_color, r=r); r += 1
        _row("Severity",          sev,         fg_color, r=r); r += 1

        ctk.CTkFrame(body, height=1, fg_color=BORDER_SUBTLE).grid(
            row=r, column=0, columnspan=2, padx=SPACE_XL, pady=SPACE_MD, sticky="ew"); r += 1

        _row("Source IP",         src,                   r=r); r += 1
        _row("Source port",       sport,                 r=r); r += 1
        _row("Destination IP",    dst,                   r=r); r += 1
        _row("Destination port",  dport,                 r=r); r += 1
        _row("Protocol",          proto,                 r=r); r += 1
        if conf is not None:
            _row("RF confidence", f"{conf:.0%}", fg_color, r=r); r += 1
        _row("Timestamp",         ts or "N/A", TEXT_MUTED, r=r); r += 1

        ctk.CTkFrame(body, height=1, fg_color=BORDER_SUBTLE).grid(
            row=r, column=0, columnspan=2, padx=SPACE_XL, pady=SPACE_MD, sticky="ew"); r += 1

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

    def _clear_rows(self):
        for row in self._rows:
            for widget in row:
                widget.destroy()
        self._rows.clear()
