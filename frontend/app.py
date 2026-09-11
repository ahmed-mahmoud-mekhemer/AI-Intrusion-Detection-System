# frontend/app.py
# ─────────────────────────────────────────────────────────────────────────────
# Root application class.
# Manages the main window, sidebar, screen switching, and backend health state.
#
# Layout:
#   ┌──────────┬────────────────────────────────────────────┐
#   │          │  HeroHeader                                 │
#   │ Sidebar  │  MetricCardRow (4 cards, always visible)    │
#   │ (220px)  ├────────────────────────────────────────────┤
#   │          │  Active Screen (fills remainder)            │
#   └──────────┴────────────────────────────────────────────┘
#
# Metric card data sources:
#   Network Status   — derived from threat count (poll-driven, /stats/summary)
#   Analyzed Flows   — set by PCAPAnalysisScreen after analysis (session-driven)
#                      shows count of flow records from the latest analysis run
#                      works for both CSV and PCAP-derived input
#   Stored Threats   — total_threats from /stats/summary (poll-driven, DB global)
#   Model Accuracy   — hardcoded 97.34%
# ─────────────────────────────────────────────────────────────────────────────
import threading
import customtkinter as ctk

from frontend.components.sidebar       import Sidebar
from frontend.components.metric_card   import MetricCard
from frontend.screens.dashboard        import DashboardScreen
from frontend.screens.pcap_analysis    import PCAPAnalysisScreen
from frontend.screens.realtime_monitor import RealtimeMonitorScreen
from frontend.screens.alerts           import AlertsScreen

from frontend.utils.config import (
    APPEARANCE_MODE, COLOR_THEME,
    APP_TITLE, WINDOW_WIDTH, WINDOW_HEIGHT, MIN_WIDTH, MIN_HEIGHT,
)
from frontend.utils.api_client import check_health, get_summary, get_live_status
from frontend.utils.app_state  import app_state
from frontend.utils.theme import (
    BG_PRIMARY, BG_PANEL,
    ACCENT_CYAN, ACCENT_CYAN_GLOW, TEXT_MUTED,
    BORDER_SUBTLE,
    FONT_HERO, FONT_HERO_SUB,
    SPACE_SM, SPACE_MD, SPACE_LG, SPACE_2XL,
)

BACKEND_CHECK_INTERVAL_MS  = 8_000
METRIC_REFRESH_INTERVAL_MS = 5_000


class IDSApp(ctk.CTk):
    """
    Main application window with persistent hero header and metric card row.
    """

    def __init__(self):
        ctk.set_appearance_mode(APPEARANCE_MODE)
        ctk.set_default_color_theme(COLOR_THEME)
        super().__init__()

        self.configure(fg_color=BG_PRIMARY)
        self.title(APP_TITLE)
        self.geometry(f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}")
        self.minsize(MIN_WIDTH, MIN_HEIGHT)

        self._screens: dict[str, ctk.CTkFrame] = {}
        self._active_screen_key: str = "dashboard"
        self._health_after_id   = None
        self._metric_after_id   = None
        self._consecutive_fails  = 0

        self._build_layout()
        self._build_screens()
        self._show_screen("dashboard")
        self._start_health_check()
        self._schedule_metric_refresh()

    # ── Layout ────────────────────────────────────────────────────────────────

    def _build_layout(self):
        self.grid_columnconfigure(0, weight=0)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._sidebar = Sidebar(
            self,
            on_navigate=self._show_screen,
            active_screen="dashboard",
        )
        self._sidebar.grid(row=0, column=0, sticky="nsew")

        right = ctk.CTkFrame(self, fg_color=BG_PRIMARY, corner_radius=0)
        right.grid(row=0, column=1, sticky="nsew")
        right.grid_columnconfigure(0, weight=1)
        right.grid_rowconfigure(0, weight=0)
        right.grid_rowconfigure(1, weight=0)
        right.grid_rowconfigure(2, weight=1)

        self._build_hero(right)
        self._build_metric_row(right)
        self._build_content_area(right)

    def _build_hero(self, parent):
        """Persistent hero header: shield icon + title + subtitle."""
        hero = ctk.CTkFrame(parent, fg_color=BG_PANEL, corner_radius=0,
                            border_width=0)
        hero.grid(row=0, column=0, sticky="ew", padx=0, pady=0)
        hero.grid_columnconfigure(1, weight=1)

        icon_box = ctk.CTkFrame(
            hero, width=48, height=48,
            fg_color=ACCENT_CYAN_GLOW, corner_radius=10,
        )
        icon_box.grid(row=0, column=0, rowspan=2,
                      padx=(SPACE_2XL, SPACE_LG), pady=SPACE_LG)
        icon_box.grid_propagate(False)
        ctk.CTkLabel(
            icon_box, text="🛡", font=ctk.CTkFont(size=22),
            text_color=ACCENT_CYAN, fg_color="transparent",
        ).place(relx=0.5, rely=0.5, anchor="center")

        ctk.CTkLabel(
            hero,
            text="AI Intrusion Detection System",
            text_color=ACCENT_CYAN,
            font=ctk.CTkFont(
                family=FONT_HERO[0], size=FONT_HERO[1], weight=FONT_HERO[2]),
            anchor="w",
        ).grid(row=0, column=1, padx=0, pady=(SPACE_LG, 0), sticky="w")

        ctk.CTkLabel(
            hero,
            text="Security Operations Center",
            text_color=TEXT_MUTED,
            font=ctk.CTkFont(
                family=FONT_HERO_SUB[0],
                size=FONT_HERO_SUB[1],
                weight=FONT_HERO_SUB[2]),
            anchor="w",
        ).grid(row=1, column=1, padx=0, pady=(0, SPACE_LG), sticky="w")

        ctk.CTkFrame(
            parent, height=1, fg_color=BORDER_SUBTLE, corner_radius=0
        ).grid(row=0, column=0, sticky="sew", padx=0, pady=0)

    def _build_metric_row(self, parent):
        """Five persistent metric cards always visible above screen content."""
        row = ctk.CTkFrame(parent, fg_color=BG_PRIMARY, corner_radius=0)
        row.grid(row=1, column=0, sticky="ew",
                 padx=SPACE_2XL, pady=(SPACE_SM, SPACE_SM))
        row.grid_columnconfigure((0, 1, 2, 3, 4), weight=1)

        self._card_status = MetricCard(
            row,
            label="Network Status",
            value="Checking…",
            subtitle="Real-time protection layer",
            accent="info",
        )
        self._card_status.grid(row=0, column=0, sticky="nsew", padx=(0, SPACE_MD))

        self._card_flows = MetricCard(
            row,
            label="Analyzed Flows",
            value="—",
            subtitle="PCAP / ML pipeline",
            accent="info",
        )
        self._card_flows.grid(row=0, column=1, sticky="nsew", padx=(0, SPACE_MD))

        self._card_attacks = MetricCard(
            row,
            label="Stored Threats",
            value="—",
            subtitle="All sessions · DB total",
            accent="ok",
        )
        self._card_attacks.grid(row=0, column=2, sticky="nsew", padx=(0, SPACE_MD))

        self._card_accuracy = MetricCard(
            row,
            label="PCAP Model Acc.",
            value="97.34%",
            subtitle="CICFlowMeter + RF · offline",
            accent="ok",
        )
        self._card_accuracy.grid(row=0, column=3, sticky="nsew", padx=(0, SPACE_MD))

        self._card_anomaly = MetricCard(
            row,
            label="IF Anomaly Score",
            value="—",
            subtitle="Isolation Forest · live layer",
            accent="info",
        )
        self._card_anomaly.grid(row=0, column=4, sticky="nsew")

    def _build_content_area(self, parent):
        self._content = ctk.CTkFrame(parent, fg_color="transparent")
        self._content.grid(row=2, column=0, sticky="nsew", padx=0, pady=0)
        self._content.grid_columnconfigure(0, weight=1)
        self._content.grid_rowconfigure(0, weight=1)

    def _build_screens(self):
        screen_classes = {
            "dashboard": DashboardScreen,
            "pcap":      PCAPAnalysisScreen,
            "realtime":  RealtimeMonitorScreen,
            "alerts":    AlertsScreen,
        }
        for key, cls in screen_classes.items():
            screen = cls(self._content)
            screen.grid(row=0, column=0, sticky="nsew")
            self._screens[key] = screen

    # ── Navigation ────────────────────────────────────────────────────────────

    def _show_screen(self, key: str):
        current = self._screens.get(self._active_screen_key)
        if current and hasattr(current, "on_hide"):
            current.on_hide()

        screen = self._screens.get(key)
        if screen:
            screen.tkraise()
            self._active_screen_key = key
            if hasattr(screen, "on_show"):
                screen.on_show()

    # ── Analyzed Flows (session-driven) ───────────────────────────────────────

    def set_analyzed_flows(self, count: int):
        """
        Called by PCAPAnalysisScreen after analysis completes.
        count = len(results) — total flow records processed by the ML pipeline.
        Works identically for CSV and PCAP-derived input.
        """
        self._card_flows.update_value(
            f"{count:,}" if count > 0 else "—",
            accent="info",
        )

    # ── Metric card refresh (poll-driven) ─────────────────────────────────────

    def _schedule_metric_refresh(self):
        threading.Thread(target=self._fetch_metrics, daemon=True).start()

    def _fetch_metrics(self):
        # Run both HTTP calls in parallel so combined wait = max(t1, t2), not t1+t2.
        # If backend is slow or down, sequential calls would block for up to 20 s
        # (2 × 10 s timeout), freezing the startup event loop on Windows.
        results: dict = {}

        def _do_summary():
            try:
                results["summary"] = get_summary()
            except Exception:
                pass

        def _do_live():
            try:
                results["live"] = get_live_status()
            except Exception:
                pass

        t1 = threading.Thread(target=_do_summary, daemon=True)
        t2 = threading.Thread(target=_do_live, daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        if "summary" in results:
            _d = results["summary"]
            self.after(0, lambda: self._update_metric_cards(_d))
        if "live" in results:
            _l = results["live"]
            self.after(0, lambda: self._update_anomaly_card(_l))

        self._metric_after_id = self.after(
            METRIC_REFRESH_INTERVAL_MS, self._schedule_metric_refresh
        )

    def _update_metric_cards(self, data: dict):
        """
        Apply /stats/summary data to poll-driven metric cards.

        _card_flows (Analyzed Flows) is intentionally NOT updated here —
        it is session-driven and set only by set_analyzed_flows() after analysis.

        Network Status uses a risk-scoring model:
          - Any CRITICAL alert               → Critical
          - 5+ HIGH alerts                   → Critical  (sustained high threat)
          - 1–4 HIGH alerts                  → High
          - MEDIUM alerts only               → Warning
          - LOW alerts only                  → Low
          - No alerts                        → Secure
        """
        total    = data.get("total_alerts", data.get("total_threats", 0))
        critical = data.get("critical", 0)
        high     = data.get("high", 0)
        medium   = data.get("medium", 0)

        # Stored Threats card — raw total, coloured by worst severity present
        if total == 0:
            self._card_attacks.update_value("0", accent="ok")
        elif critical > 0 or high >= 5:
            self._card_attacks.update_value(str(total), accent="critical")
        elif high > 0:
            self._card_attacks.update_value(str(total), accent="warning")
        else:
            self._card_attacks.update_value(str(total), accent="info")

        # Network Status card — risk-scoring model
        if total == 0:
            self._card_status.update_value("Secure", accent="ok")
        elif critical > 0 or high >= 5:
            self._card_status.update_value("Critical", accent="critical")
        elif high > 0:
            self._card_status.update_value("High", accent="warning")
        elif medium > 0:
            self._card_status.update_value("Warning", accent="warning")
        else:
            self._card_status.update_value("Low", accent="info")

    def _update_anomaly_card(self, live: dict):
        """
        Update the AI Anomaly Score card from /live/status data.

        Score interpretation (Isolation Forest, 0=normal, 1=anomalous):
          < 0.35  → Normal    (ok)
          < 0.55  → Low Risk  (info)
          < 0.75  → Elevated  (warning)
          ≥ 0.75  → Anomalous (critical)

        Shows '—' when the live monitor is not running or model is absent (score=0.5 neutral).
        """
        if not live.get("running", False):
            self._card_anomaly.update_value("—", accent="info")
            self._card_anomaly.update_subtitle("Live monitor off")
            return

        score = live.get("anomaly_score", 0.5)

        if score == 0.5:
            # Neutral sentinel — model not loaded yet or no packets scored
            self._card_anomaly.update_value("Pending", accent="info")
            self._card_anomaly.update_subtitle("Waiting for baseline")
        elif score < 0.35:
            self._card_anomaly.update_value(f"{score:.0%}", accent="ok")
            self._card_anomaly.update_subtitle("Normal traffic")
        elif score < 0.55:
            self._card_anomaly.update_value(f"{score:.0%}", accent="info")
            self._card_anomaly.update_subtitle("Low anomaly risk")
        elif score < 0.75:
            self._card_anomaly.update_value(f"{score:.0%}", accent="warning")
            self._card_anomaly.update_subtitle("Elevated anomaly")
        else:
            self._card_anomaly.update_value(f"{score:.0%}", accent="critical")
            self._card_anomaly.update_subtitle("Anomalous traffic!")

    # ── Backend health check ──────────────────────────────────────────────────

    def _start_health_check(self):
        if self._health_after_id:
            self.after_cancel(self._health_after_id)
            self._health_after_id = None
        threading.Thread(target=self._check_backend, daemon=True).start()

    def _check_backend(self):
        online = check_health()

        if online:
            self._consecutive_fails = 0
            self.after(0, lambda: self._sidebar.set_backend_status("online"))
        else:
            if app_state.is_busy:
                self._consecutive_fails = 0
                self.after(0, lambda: self._sidebar.set_backend_status("busy"))
            else:
                self._consecutive_fails += 1
                if self._consecutive_fails >= 2:
                    self.after(0, lambda: self._sidebar.set_backend_status("offline"))

        self._health_after_id = self.after(
            BACKEND_CHECK_INTERVAL_MS, self._start_health_check
        )
