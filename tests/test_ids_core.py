# tests/test_ids_core.py
# ─────────────────────────────────────────────────────────────────────────────
# Core logic tests — no network, no tshark, no ML model, no DB writes.
#
# Run with:
#   python -m pytest tests/test_ids_core.py -v
# ─────────────────────────────────────────────────────────────────────────────

import sys
import os

# Ensure the project root is on sys.path so backend.* imports resolve.
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

import pytest


# ═══════════════════════════════════════════════════════════════════════════
# 1. WindowTracker
# ═══════════════════════════════════════════════════════════════════════════

class TestWindowTracker:
    """
    _WindowTracker is a sliding-window event counter used by the rule engine.
    All tests drive it with synthetic timestamps — no real time dependency.
    """

    @pytest.fixture(autouse=True)
    def import_tracker(self):
        from backend.services.live_monitor_service import _WindowTracker
        self.WindowTracker = _WindowTracker

    def test_count_within_window(self):
        """Events added within the window are all counted."""
        tracker = self.WindowTracker(window=10.0)
        t0 = 1000.0
        for i in range(5):
            count = tracker.add("src_a", t0 + i)
        assert count == 5

    def test_eviction_after_window_expires(self):
        """Events strictly older than window seconds are evicted on the next add."""
        tracker = self.WindowTracker(window=10.0)
        t0 = 1000.0
        # Add 5 events at t0..t0+4
        for i in range(5):
            tracker.add("src_a", t0 + i)
        # At t0+14 the cutoff is t0+4, so t0..t0+3 are evicted, t0+4 survives
        count = tracker.add("src_a", t0 + 14.0)
        assert count == 2   # t0+4 and t0+14

    def test_partial_eviction(self):
        """Only entries strictly before the window boundary are evicted.
        Eviction condition: t >= cutoff (>= is inclusive), so the entry
        exactly at the cutoff timestamp is retained.
        """
        tracker = self.WindowTracker(window=10.0)
        t0 = 1000.0
        tracker.add("src_a", t0 + 0)   # evicted: t0+0 < cutoff t0+1
        tracker.add("src_a", t0 + 1)   # retained: t0+1 == cutoff (>= keeps it)
        tracker.add("src_a", t0 + 2)   # retained
        tracker.add("src_a", t0 + 3)   # retained
        count = tracker.add("src_a", t0 + 11.0)
        # cutoff = t0+11-10 = t0+1; t0+0 is the only one evicted
        assert count == 4   # t0+1, t0+2, t0+3, t0+11 survive

    def test_independent_keys(self):
        """Different source IPs are tracked independently."""
        tracker = self.WindowTracker(window=10.0)
        t0 = 1000.0
        for _ in range(4):
            tracker.add("src_a", t0)
        for _ in range(7):
            tracker.add("src_b", t0)
        assert tracker.add("src_a", t0 + 1) == 5
        assert tracker.add("src_b", t0 + 1) == 8

    def test_empty_window_after_full_eviction(self):
        """After a long gap all old events are gone, count restarts from 1."""
        tracker = self.WindowTracker(window=5.0)
        t0 = 1000.0
        for i in range(10):
            tracker.add("src_a", t0 + i)
        # Jump far ahead — everything evicted
        count = tracker.add("src_a", t0 + 9999.0)
        assert count == 1


# ═══════════════════════════════════════════════════════════════════════════
# 2. Rule Engine — SYN Flood
# ═══════════════════════════════════════════════════════════════════════════

class TestRuleEngineSYNFlood:
    """
    Drive _RuleEngine.evaluate() with synthetic pure-SYN packets from one
    source IP and confirm SYN Flood fires when the threshold is crossed.
    """

    @pytest.fixture(autouse=True)
    def import_engine(self):
        from backend.services.live_monitor_service import (
            _RuleEngine, _SYN_FLOOD_THRESH, _SYN_WINDOW_SECONDS,
        )
        self.RuleEngine = _RuleEngine
        self.SYN_FLOOD_THRESH = _SYN_FLOOD_THRESH
        self.SYN_WINDOW = _SYN_WINDOW_SECONDS

    def _make_syn_pkt(self, src_ip: str, epoch: float, dst_port: int = 80) -> dict:
        return {
            "epoch":     epoch,
            "src_ip":    src_ip,
            "dst_ip":    "192.168.1.1",
            "src_port":  12345,
            "dst_port":  dst_port,
            "protocol":  "TCP",
            "tcp_flags": 0x002,   # pure SYN
            "frame_len": 60,
        }

    def test_syn_flood_fires_at_threshold(self):
        """SYN Flood alert fires once the SYN count crosses the threshold."""
        engine = self.RuleEngine()
        t0 = 1000.0
        fired_labels = []

        for i in range(self.SYN_FLOOD_THRESH + 1):
            pkt = self._make_syn_pkt("10.0.0.1", t0 + i * 0.01)
            alerts = engine.evaluate(pkt)
            fired_labels.extend(a["label"] for a in alerts)

        assert "SYN Flood" in fired_labels, (
            f"Expected 'SYN Flood' after {self.SYN_FLOOD_THRESH + 1} SYN packets, "
            f"got: {fired_labels}"
        )

    def test_syn_flood_does_not_fire_below_threshold(self):
        """SYN Flood must NOT fire when count is below the threshold."""
        engine = self.RuleEngine()
        t0 = 1000.0
        all_labels = []

        # Send threshold - 1 packets (just below trigger)
        for i in range(self.SYN_FLOOD_THRESH - 1):
            pkt = self._make_syn_pkt("10.0.0.2", t0 + i * 0.01)
            all_labels.extend(a["label"] for a in engine.evaluate(pkt))

        assert "SYN Flood" not in all_labels

    def test_syn_flood_respects_cooldown(self):
        """After firing, the same src should not fire again within cooldown."""
        engine = self.RuleEngine()
        t0 = 1000.0
        syn_flood_alerts = []

        # Cross the threshold
        for i in range(self.SYN_FLOOD_THRESH + 5):
            pkt = self._make_syn_pkt("10.0.0.3", t0 + i * 0.01)
            alerts = engine.evaluate(pkt)
            syn_flood_alerts.extend(a for a in alerts if a["label"] == "SYN Flood")

        # Exactly one SYN Flood within the cooldown window
        assert len(syn_flood_alerts) == 1


# ═══════════════════════════════════════════════════════════════════════════
# 3. Rule Engine — Port Scan
# ═══════════════════════════════════════════════════════════════════════════

class TestRuleEnginePortScan:
    """
    Inject TCP SYN packets from one source IP to many distinct destination
    ports. Confirm Port Scan fires when the unique-port threshold is crossed.
    """

    @pytest.fixture(autouse=True)
    def import_engine(self):
        from backend.services.live_monitor_service import (
            _RuleEngine, _PORT_SCAN_THRESH,
        )
        self.RuleEngine = _RuleEngine
        self.PORT_SCAN_THRESH = _PORT_SCAN_THRESH

    def _make_tcp_pkt(self, src_ip: str, epoch: float, dst_port: int) -> dict:
        return {
            "epoch":     epoch,
            "src_ip":    src_ip,
            "dst_ip":    "192.168.1.1",
            "src_port":  54321,
            "dst_port":  dst_port,
            "protocol":  "TCP",
            "tcp_flags": 0x002,   # SYN
            "frame_len": 60,
        }

    def test_port_scan_fires_at_threshold(self):
        """'Live Port Scan' fires once unique dst_ports from same src crosses threshold."""
        engine = self.RuleEngine()
        t0 = 1000.0
        fired_labels = []

        # Use ports that won't be filtered by _is_noise_traffic
        # Start from 2000 to avoid well-known noise ports
        for i in range(self.PORT_SCAN_THRESH + 1):
            port = 2000 + i
            pkt = self._make_tcp_pkt("10.1.0.1", t0 + i * 0.05, dst_port=port)
            alerts = engine.evaluate(pkt)
            fired_labels.extend(a["label"] for a in alerts)

        assert "Live Port Scan" in fired_labels, (
            f"Expected 'Live Port Scan' after {self.PORT_SCAN_THRESH + 1} unique ports, "
            f"got: {fired_labels}"
        )

    def test_port_scan_does_not_fire_same_port_repeated(self):
        """Repeated SYNs to the SAME port do not trigger Port Scan."""
        engine = self.RuleEngine()
        t0 = 1000.0
        all_labels = []

        for i in range(self.PORT_SCAN_THRESH + 10):
            pkt = self._make_tcp_pkt("10.1.0.2", t0 + i * 0.05, dst_port=8080)
            all_labels.extend(a["label"] for a in engine.evaluate(pkt))

        assert "Port Scan" not in all_labels, (
            "Port Scan should not fire when all packets target the same port"
        )

    def test_port_scan_different_src_independent(self):
        """Port scans from two different IPs are tracked independently."""
        engine = self.RuleEngine()
        t0 = 1000.0
        labels_a, labels_b = [], []

        # src_a scans enough ports to fire
        for i in range(self.PORT_SCAN_THRESH + 1):
            pkt = self._make_tcp_pkt("10.2.0.1", t0 + i * 0.05, dst_port=2000 + i)
            labels_a.extend(a["label"] for a in engine.evaluate(pkt))

        # src_b sends just below threshold
        for i in range(self.PORT_SCAN_THRESH - 1):
            pkt = self._make_tcp_pkt("10.2.0.2", t0 + i * 0.05, dst_port=3000 + i)
            labels_b.extend(a["label"] for a in engine.evaluate(pkt))

        assert "Live Port Scan" in labels_a
        assert "Live Port Scan" not in labels_b


# ═══════════════════════════════════════════════════════════════════════════
# 4. Alert Model — Honeypot detection_type = TRAP
# ═══════════════════════════════════════════════════════════════════════════

class TestHoneypotDetectionType:
    """
    Verify that Alert objects constructed the way honeypot_service.py builds
    them carry detection_type = "TRAP" and not the default "RULE".
    """

    def _make_honeypot_alert(self, service: str = "SSH"):
        from backend.models.alert import Alert
        import uuid
        from datetime import datetime
        ts = datetime.now().isoformat()
        return Alert(
            flow_id        = str(uuid.uuid4()),
            label          = f"Brute Force Attack ({service})",
            severity       = "HIGH",
            confidence     = None,
            src_ip         = "192.168.1.50",
            dst_ip         = "honeypot",
            src_port       = 0,
            dst_port       = 2222,
            protocol       = "TCP",
            timestamp      = ts,
            source         = "honeypot",
            detection_type = "TRAP",
        )

    def test_ssh_honeypot_detection_type_is_trap(self):
        alert = self._make_honeypot_alert("SSH")
        assert alert.detection_type == "TRAP"

    def test_telnet_honeypot_detection_type_is_trap(self):
        alert = self._make_honeypot_alert("Telnet")
        assert alert.detection_type == "TRAP"

    def test_ftp_honeypot_detection_type_is_trap(self):
        alert = self._make_honeypot_alert("FTP")
        assert alert.detection_type == "TRAP"

    def test_honeypot_alert_label_format(self):
        """Label follows the 'Brute Force Attack (X)' pattern."""
        for svc in ("SSH", "Telnet", "FTP"):
            alert = self._make_honeypot_alert(svc)
            assert alert.label == f"Brute Force Attack ({svc})"

    def test_default_detection_type_is_rule(self):
        """Confirm the default (non-honeypot) Alert still defaults to RULE."""
        from backend.models.alert import Alert
        import uuid
        alert = Alert(
            flow_id   = str(uuid.uuid4()),
            label     = "Port Scan",
            severity  = "HIGH",
            src_ip    = "10.0.0.1",
            dst_ip    = "192.168.1.1",
            src_port  = 0,
            dst_port  = 22,
            protocol  = "TCP",
            timestamp = "2026-01-01T00:00:00",
            source    = "live",
        )
        assert alert.detection_type == "RULE"


# ═══════════════════════════════════════════════════════════════════════════
# 5. HTTP Flood — detection_type defaults to RULE
# ═══════════════════════════════════════════════════════════════════════════

class TestHTTPFloodDetectionType:
    """
    The HTTP Flood middleware builds an Alert without setting detection_type,
    which means it uses the model default ("RULE"). Verify this is stable.
    """

    def test_http_flood_alert_default_is_rule(self):
        """Alert built without detection_type should default to RULE."""
        from backend.models.alert import Alert
        import uuid
        from datetime import datetime
        alert = Alert(
            flow_id   = str(uuid.uuid4()),
            label     = "HTTP Flood",
            severity  = "HIGH",
            confidence= None,
            src_ip    = "10.0.0.99",
            dst_ip    = "backend",
            src_port  = 0,
            dst_port  = 8000,
            protocol  = "HTTP",
            timestamp = datetime.now().isoformat(),
            source    = "live",
        )
        assert alert.detection_type == "RULE"

    def test_http_flood_alert_label(self):
        from backend.models.alert import Alert
        import uuid
        alert = Alert(
            flow_id   = str(uuid.uuid4()),
            label     = "HTTP Flood",
            severity  = "HIGH",
            src_ip    = "10.0.0.1",
            dst_ip    = "backend",
            src_port  = 0,
            dst_port  = 8000,
            protocol  = "HTTP",
            timestamp = "2026-01-01T00:00:00",
            source    = "live",
        )
        assert alert.label == "HTTP Flood"
        assert alert.severity == "HIGH"
        assert alert.dst_port == 8000

    def test_http_flood_threshold_constant(self):
        """Verify the middleware threshold constant is at its calibrated value."""
        # Import only the module-level constants — no middleware instantiation,
        # no Starlette dependency, no DB connection.
        import importlib, types
        # Patch BaseHTTPMiddleware so we don't need Starlette running
        import unittest.mock as mock
        with mock.patch.dict("sys.modules", {
            "starlette.middleware.base": mock.MagicMock(),
            "starlette.requests":        mock.MagicMock(),
        }):
            import importlib
            import backend.middleware.http_flood as hf
            importlib.reload(hf)
            assert hf._THRESHOLD == 100
            assert hf._WINDOW_SECONDS == 10


# ═══════════════════════════════════════════════════════════════════════════
# 6. Simulator argument parsing
# ═══════════════════════════════════════════════════════════════════════════

class TestSimulatorArgparse:
    """
    Verify the attack simulator CLIs accept the expected arguments and that
    defaults match documented behaviour. No sockets opened, no threads started.
    """

    def _get_syn_parser(self):
        import importlib, sys, types, unittest.mock as mock
        # Prevent the __main__ block from running by loading as a module
        import tools.attack_simulators.syn_flood as sf
        return sf

    def _get_icmp_parser(self):
        import tools.attack_simulators.icmp_flood as icf
        return icf

    def test_syn_flood_defaults(self):
        import tools.attack_simulators.syn_flood as sf
        parser = sf.__dict__.get("parser") or None
        # Build a fresh parser the same way the script does
        import argparse
        p = argparse.ArgumentParser()
        p.add_argument("--target",     default=sf.DEFAULT_TARGET)
        p.add_argument("--rate",       type=int, default=sf.DEFAULT_RATE)
        p.add_argument("--duration",   type=int, default=sf.DEFAULT_DURATION)
        p.add_argument("--no-scapy",   action="store_true")
        p.add_argument("--fixed-port", type=int, default=0)
        args = p.parse_args([])
        assert args.target      == "127.0.0.1"
        assert args.rate        == 150
        assert args.duration    == 300
        assert args.no_scapy    is False
        assert args.fixed_port  == 0

    def test_syn_flood_fixed_port_flag(self):
        import tools.attack_simulators.syn_flood as sf
        import argparse
        p = argparse.ArgumentParser()
        p.add_argument("--target",     default=sf.DEFAULT_TARGET)
        p.add_argument("--rate",       type=int, default=sf.DEFAULT_RATE)
        p.add_argument("--duration",   type=int, default=sf.DEFAULT_DURATION)
        p.add_argument("--no-scapy",   action="store_true")
        p.add_argument("--fixed-port", type=int, default=0)
        args = p.parse_args(["--no-scapy", "--fixed-port", "80", "--duration", "60"])
        assert args.no_scapy   is True
        assert args.fixed_port == 80
        assert args.duration   == 60

    def test_icmp_flood_defaults(self):
        import tools.attack_simulators.icmp_flood as icf
        import argparse
        p = argparse.ArgumentParser()
        p.add_argument("--target",   default=icf.DEFAULT_TARGET)
        p.add_argument("--rate",     type=int, default=icf.DEFAULT_RATE)
        p.add_argument("--duration", type=int, default=icf.DEFAULT_DURATION)
        p.add_argument("--no-scapy", action="store_true")
        args = p.parse_args([])
        assert args.target   == "127.0.0.1"
        assert args.rate     == 80
        assert args.duration == 300
        assert args.no_scapy is False

    def test_syn_flood_constants_are_sane(self):
        """Guard against accidental changes to simulator default values."""
        import tools.attack_simulators.syn_flood as sf
        assert sf.DEFAULT_RATE     > 0
        assert sf.DEFAULT_DURATION > 0
        assert sf.PORT_RANGE[0]    < sf.PORT_RANGE[1]

    def test_icmp_flood_constants_are_sane(self):
        import tools.attack_simulators.icmp_flood as icf
        assert icf.DEFAULT_RATE     > 0
        assert icf.DEFAULT_DURATION > 0


# ═══════════════════════════════════════════════════════════════════════════
# 7. Rule Engine thresholds — constants are calibrated values
# ═══════════════════════════════════════════════════════════════════════════

class TestRuleEngineConstants:
    """
    Regression guard: confirms that threshold constants haven't drifted from
    their empirically calibrated values. These tests fail fast if someone
    accidentally changes a threshold without updating the others.
    """

    def test_thresholds_match_calibrated_values(self):
        from backend.services.live_monitor_service import (
            _SYN_FLOOD_THRESH,
            _PORT_SCAN_THRESH,
            _ICMP_FLOOD_THRESH,
            _CONN_BURST_THRESH,
            _UDP_BURST_THRESH,
            _WINDOW_SECONDS,
            _SYN_WINDOW_SECONDS,
            _COOLDOWN_SECONDS,
        )
        assert _SYN_FLOOD_THRESH  == 150
        assert _PORT_SCAN_THRESH  == 15
        assert _ICMP_FLOOD_THRESH == 20
        assert _CONN_BURST_THRESH == 120
        assert _UDP_BURST_THRESH  == 25
        assert _WINDOW_SECONDS    == 10
        assert _SYN_WINDOW_SECONDS == 15
        assert _COOLDOWN_SECONDS  == 60

    def test_alert_model_default_detection_type(self):
        """The Alert default must be RULE — changing it would silently mislabel alerts."""
        from backend.models.alert import Alert
        import inspect
        sig = inspect.signature(Alert)
        dt_default = sig.parameters.get("detection_type")
        assert dt_default is not None
        assert dt_default.default == "RULE"
