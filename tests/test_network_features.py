"""Focused regression tests for the scanner's local-network safety features."""

from __future__ import annotations

import os
import struct
import subprocess
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from config_backup import build_backup_payload, load_backup, save_backup, validate_backup_payload
import mac_randomizer
from network_discovery import _build_dns_query, _read_dns_name, assess_visibility
from network_history import NetworkHistory
from scanner import NetworkScanner
from security_audit import check_smb_guest, evaluate_security_audit, run_security_dashboard
from spy_camera_detector import analyze_spy_camera_risk

if os.name == "nt":
    from ping_monitor import (
        LOAD_TEST_DEFAULT_DURATION_S,
        LOAD_TEST_DEFAULT_RATE_PPS,
        LOAD_TEST_MAX_DURATION_S,
        LOAD_TEST_MAX_RATE_PPS,
        LoadTestSession,
        PingSession,
        PING_DEFAULT_IN_FLIGHT,
        PING_MAX_COUNT,
        PING_MAX_DURATION_S,
        PING_MAX_IN_FLIGHT,
        PING_MAX_INTERVAL_S,
        PING_MAX_TIMEOUT_MS,
        PING_MIN_INTERVAL_S,
        PING_MIN_TIMEOUT_MS,
        UDP_PAYLOAD_DEFAULT_BYTES,
        UDP_PAYLOAD_MAX_BYTES,
        UDP_PAYLOAD_MIN_BYTES,
        _build_udp_dns_query,
        smart_ping,
        udp_ping,
        validate_load_test_config,
        validate_ping_session_config,
    )
else:  # Keep the non-Windows test collection path importable.
    LOAD_TEST_DEFAULT_DURATION_S = None
    LOAD_TEST_DEFAULT_RATE_PPS = None
    LOAD_TEST_MAX_DURATION_S = None
    LOAD_TEST_MAX_RATE_PPS = None
    LoadTestSession = None
    PingSession = None
    PING_DEFAULT_IN_FLIGHT = None
    PING_MAX_COUNT = None
    PING_MAX_DURATION_S = None
    PING_MAX_IN_FLIGHT = None
    PING_MAX_INTERVAL_S = None
    PING_MAX_TIMEOUT_MS = None
    PING_MIN_INTERVAL_S = None
    PING_MIN_TIMEOUT_MS = None
    UDP_PAYLOAD_DEFAULT_BYTES = None
    UDP_PAYLOAD_MAX_BYTES = None
    UDP_PAYLOAD_MIN_BYTES = None
    _build_udp_dns_query = None
    smart_ping = None
    udp_ping = None
    validate_load_test_config = None
    validate_ping_session_config = None


def _scanner_for_test() -> NetworkScanner:
    scanner = object.__new__(NetworkScanner)
    scanner.should_stop = False
    scanner.is_scanning = False
    scanner.local_ip = "10.0.0.10"
    scanner.subnet_mask = "255.255.255.0"
    scanner.network_cidr = "10.0.0.0/24"
    scanner.gateway_ip = "10.0.0.1"
    scanner.wifi_ssid = None
    scanner.machine_name = "test-host"
    scanner.adapters = []
    scanner.selected_adapter_indices = []
    scanner.refresh_network_info = lambda: None
    return scanner


class ScannerTargetTests(unittest.TestCase):
    def test_adapter_targets_are_interleaved(self) -> None:
        scanner = _scanner_for_test()
        probed = []
        with patch("scanner.send_arp_ping", side_effect=lambda ip: probed.append(ip)):
            scanner.scan_subnet(
                max_threads=1,
                max_hosts=6,
                retries=1,
                adapter_configs=[
                    {"index": 1, "ipv4": ["10.0.0.10/24"], "gateway": "10.0.0.1"},
                    {"index": 2, "ipv4": ["10.0.1.10/24"], "gateway": "10.0.1.1"},
                ],
            )
        self.assertEqual(probed[:4], ["10.0.0.10", "10.0.0.1", "10.0.1.10", "10.0.1.1"])
        self.assertEqual(len(probed), 6)

    def test_large_cidr_is_bounded_before_submission(self) -> None:
        scanner = _scanner_for_test()
        probed = []
        with patch("scanner.send_arp_ping", side_effect=lambda ip: probed.append(ip)):
            scanner.scan_subnet("10.0.0.0/8", max_threads=1, max_hosts=5, retries=1)
        self.assertEqual(len(probed), 5)
        self.assertEqual(probed[0], "10.0.0.1")


class DiscoveryTests(unittest.TestCase):
    def test_mdns_query_is_non_recursive_and_requests_unicast_reply(self) -> None:
        packet = _build_dns_query("_http._tcp.local", unicast_response=True)
        self.assertEqual(packet[0:4], b"\x00\x00\x00\x00")
        self.assertEqual(packet[-2:], b"\x80\x01")

    def test_dns_name_pointer_cycle_is_bounded(self) -> None:
        self.assertEqual(_read_dns_name(b"\xc0\x00", 0)[0], "")

    def test_no_gateway_does_not_claim_ap_isolation(self) -> None:
        visibility = assess_visibility(expected_hosts=16, devices=[], gateway_reachable=False)
        self.assertFalse(visibility["ap_isolation_suspected"])


class HistoryTests(unittest.TestCase):
    def test_metadata_survives_ip_change(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            history = NetworkHistory(os.path.join(folder, "history.db"))
            original = {"ip": "192.168.1.2", "mac": "AA:BB:CC:DD:EE:FF", "name": "phone"}
            history.set_device_metadata(original, alias="Phone", room="Living", trusted=True)
            history.record_scan([original])
            result = history.record_scan([
                {"ip": "192.168.1.3", "mac": "AA:BB:CC:DD:EE:FF", "name": "phone"}
            ])
            self.assertEqual(result["changed"][0]["event_type"], "ip_changed")
            device = history.latest_devices()[0]
            self.assertEqual(device["alias"], "Phone")
            self.assertTrue(device["trusted"])

    def test_device_history_follows_ip_and_mac_changes(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            history = NetworkHistory(os.path.join(folder, "history.db"))
            history.record_scan([{"ip": "192.168.1.2", "mac": "AA:BB:CC:DD:EE:01", "name": "phone"}])
            history.record_scan([{"ip": "192.168.1.3", "mac": "AA:BB:CC:DD:EE:01", "name": "phone"}])
            history.record_scan([{"ip": "192.168.1.3", "mac": "AA:BB:CC:DD:EE:02", "name": "phone"}])
            history.set_device_metadata(
                {"ip": "192.168.1.3", "mac": "AA:BB:CC:DD:EE:02"},
                alias="Phone",
                room="Living",
                trusted=True,
            )

            detail = history.get_device_history({"ip": "192.168.1.3", "mac": "AA:BB:CC:DD:EE:02"})
            self.assertEqual(detail["alias"], "Phone")
            self.assertEqual(detail["room"], "Living")
            self.assertTrue(detail["trusted"])
            self.assertEqual(detail["observation_count"], 3)
            self.assertEqual({item["value"] for item in detail["ip_history"]}, {"192.168.1.2", "192.168.1.3"})
            self.assertEqual(
                {item["value"] for item in detail["mac_history"]},
                {"AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"},
            )
            self.assertEqual(detail["events"][0]["event_type"], "mac_changed")

    def test_restore_devices_creates_a_baseline_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            history = NetworkHistory(os.path.join(folder, "history.db"))
            result = history.restore_devices(
                [
                    {
                        "ip": "192.168.1.20",
                        "mac": "AA:BB:CC:DD:EE:20",
                        "name": "tablet",
                        "alias": "Tablet",
                        "room": "Bedroom",
                        "trusted": True,
                    }
                ],
                restored_at="2026-09-11T10:00:00+00:00",
            )
            self.assertEqual(result["device_count"], 1)
            devices = history.latest_devices()
            self.assertEqual(devices[0]["alias"], "Tablet")
            self.assertEqual(devices[0]["room"], "Bedroom")
            self.assertTrue(devices[0]["trusted"])

    def test_restore_empty_list_replaces_latest_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            history = NetworkHistory(os.path.join(folder, "history.db"))
            history.record_scan([{"ip": "192.168.1.2", "mac": "AA:BB:CC:DD:EE:02"}])
            result = history.restore_devices([], restored_at="2026-09-11T10:00:00+00:00")
            self.assertIsNotNone(result["scan_id"])
            self.assertEqual(history.latest_devices(), [])


class BackupTests(unittest.TestCase):
    def test_backup_round_trip_and_safe_defaults(self) -> None:
        payload = build_backup_payload(
            [{
                "ip": "192.168.1.2",
                "mac": "AA:BB:CC:DD:EE:FF",
                "alias": "TV",
                "password": "must-not-be-copied",
            }],
            {"scan_mode": "not-valid", "search_query": "TV"},
            [{"ssid": "Home", "mode": "daily", "password": "must-not-be-copied"}],
            created_at="2026-09-11T10:00:00+00:00",
        )
        self.assertEqual(payload["settings"]["scan_mode"], "full")
        self.assertEqual(payload["settings"]["search_query"], "TV")
        self.assertEqual(payload["mac_profiles"], [{"ssid": "Home", "mode": "daily"}])
        self.assertNotIn("password", payload["devices"][0])
        self.assertNotIn("password", payload["mac_profiles"][0])

        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "config.json")
            save_backup(path, payload)
            loaded = load_backup(path)
            self.assertEqual(loaded, payload)

    def test_invalid_backup_format_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            validate_backup_payload({"format": "other", "version": 1})


class SecurityTests(unittest.TestCase):
    def test_smb_guest_uses_one_connection_for_negotiate_and_session(self) -> None:
        def smb_frame(status: int, session_flags: int = 0) -> bytes:
            payload = bytearray(72)
            payload[0:4] = b"\xfeSMB"
            struct.pack_into("<I", payload, 8, status)
            struct.pack_into("<H", payload, 66, session_flags)
            return b"\x00" + len(payload).to_bytes(3, "big") + bytes(payload)

        class FakeSocket:
            def __init__(self) -> None:
                self.data = bytearray(smb_frame(0) + smb_frame(0, 1))
                self.sent = []

            def settimeout(self, _timeout) -> None:
                return None

            def sendall(self, payload: bytes) -> None:
                self.sent.append(payload)

            def recv(self, size: int) -> bytes:
                chunk = bytes(self.data[:size])
                del self.data[:size]
                return chunk

            def close(self) -> None:
                return None

        fake = FakeSocket()
        with patch("security_audit.socket.create_connection", return_value=fake):
            result = check_smb_guest("192.168.1.2", timeout=0.1)
        self.assertEqual(result["status"], "guest_confirmed")
        self.assertEqual(len(fake.sent), 2)

    def test_gateway_upnp_is_not_deducted_twice(self) -> None:
        result = evaluate_security_audit(
            {"security_level": "excellent"},
            [{"port": 5000, "is_open": True, "risk": "medium", "name": "UPnP"}],
            {"canary_test_ok": True, "dns_configuration_available": True, "is_router_relay": False},
            {
                "findings": [
                    {
                        "check": "upnp",
                        "role": "gateway",
                        "host": "192.168.1.1",
                        "port": 5000,
                        "status": "endpoint_reachable",
                        "risk": "medium",
                    }
                ]
            },
        )
        self.assertEqual(result["score"], 90)

    def test_unknown_dns_configuration_is_not_a_failure(self) -> None:
        result = evaluate_security_audit(
            {"security_level": "excellent"},
            [],
            {"canary_test_ok": False, "dns_configuration_available": False},
        )
        self.assertEqual(result["score"], 100)

    def test_dashboard_uses_one_shared_ssdp_discovery(self) -> None:
        ssdp = [{"ip": "192.168.1.1", "status": "HTTP/1.1 200 OK"}]
        with (
            patch("network_discovery.discover_ssdp", return_value=ssdp) as discover,
            patch("security_audit.check_smb_guest", return_value={"check": "smb_guest", "status": "unreachable"}),
            patch("security_audit.check_telnet", return_value={"check": "telnet", "status": "closed"}),
            patch("security_audit.check_upnp", return_value={"check": "upnp", "status": "not_observed"}) as upnp,
            patch("security_audit.check_http_admin", return_value=[]),
        ):
            dashboard = run_security_dashboard(
                "192.168.1.1",
                [{"ip": "192.168.1.2"}],
                timeout=0.1,
                dns_info={},
            )
        self.assertEqual(discover.call_count, 1)
        self.assertEqual(upnp.call_count, 2)
        self.assertEqual(dashboard["ssdp_records"], ssdp)


class CameraTests(unittest.TestCase):
    def test_open_rtsp_without_protocol_evidence_stays_suspicious(self) -> None:
        with (
            patch("spy_camera_detector.check_camera_video_ports", return_value=[{"port": 554, "name": "RTSP", "desc": ""}]),
            patch("spy_camera_detector.verify_rtsp_service", return_value={"verified": False}),
        ):
            result = analyze_spy_camera_risk({"ip": "192.168.1.50", "mac": "AA:BB:CC:DD:EE:FF"})
        self.assertEqual(result["risk_level"], "suspicious")


@unittest.skipUnless(os.name == "nt", "Windows-only ping engine")
class PingSessionTests(unittest.TestCase):
    def test_safe_session_limits_are_restored(self) -> None:
        self.assertEqual(PING_MAX_COUNT, 10000)
        self.assertEqual(PING_MAX_DURATION_S, 24 * 60 * 60)
        self.assertEqual(PING_MIN_INTERVAL_S, 0.05)
        self.assertEqual(PING_MAX_INTERVAL_S, 3600.0)
        self.assertEqual(PING_MIN_TIMEOUT_MS, 100)
        self.assertEqual(PING_MAX_TIMEOUT_MS, 10000)
        self.assertEqual(PING_DEFAULT_IN_FLIGHT, 4)
        self.assertEqual(PING_MAX_IN_FLIGHT, 32)

    def test_load_config_is_private_and_bounded(self) -> None:
        config = validate_load_test_config(
            "192.168.1.1",
            10,
            2,
            800,
            protocol="udp",
            udp_payload_size=256,
            max_in_flight=4,
        )
        self.assertEqual(config["planned_count"], 20)
        self.assertEqual(config["udp_payload_size"], 256)
        self.assertEqual(LOAD_TEST_DEFAULT_RATE_PPS, 10.0)
        self.assertEqual(LOAD_TEST_DEFAULT_DURATION_S, 60.0)
        with self.assertRaises(ValueError):
            validate_load_test_config("8.8.8.8", 10, 2, 800)
        with self.assertRaises(ValueError):
            validate_load_test_config("192.0.2.1", 10, 2, 800)
        with self.assertRaises(ValueError):
            validate_load_test_config("192.168.1.255", 10, 2, 800)
        with self.assertRaises(ValueError):
            validate_load_test_config(
                "192.168.1.1", LOAD_TEST_MAX_RATE_PPS + 1, 2, 800
            )
        with self.assertRaises(ValueError):
            validate_load_test_config(
                "192.168.1.1", 10, LOAD_TEST_MAX_DURATION_S + 1, 800
            )
        with self.assertRaises(ValueError):
            validate_load_test_config("192.168.1.1", 10, 2, 800, protocol="auto")

    def test_load_session_sends_bounded_udp_probes(self) -> None:
        summaries = []
        results = []
        with patch("ping_monitor.udp_ping", return_value=1) as udp_probe:
            session = LoadTestSession(
                "192.168.1.1",
                rate_pps=5,
                duration_s=1,
                timeout_ms=800,
                protocol="udp",
                udp_payload_size=256,
                max_in_flight=2,
                on_result=results.append,
                on_complete=summaries.append,
            )
            self.assertTrue(session.start())
            session.wait(3)

        self.assertFalse(session.is_running)
        self.assertEqual(session.sent_count, 5)
        self.assertEqual(len(results), 5)
        self.assertEqual(len(summaries), 1)
        self.assertEqual(summaries[0]["stop_reason"], "duration")
        self.assertGreaterEqual(summaries[0]["elapsed_s"], 0.9)
        self.assertEqual(udp_probe.call_count, 5)
        self.assertTrue(all(call.kwargs["payload_size"] == 256 for call in udp_probe.call_args_list))

    def test_config_normalizes_zero_duration(self) -> None:
        config = validate_ping_session_config(
            "192.168.1.1", 3, 0, 0.05, 800
        )
        self.assertIsNone(config["duration_s"])
        self.assertEqual(config["count"], 3)

    def test_config_rejects_non_finite_timing_values(self) -> None:
        with self.assertRaises(ValueError):
            validate_ping_session_config("192.168.1.1", 3, float("nan"), 1, 800)
        with self.assertRaises(ValueError):
            validate_ping_session_config("192.168.1.1", 3, 30, float("nan"), 800)

    def test_config_accepts_async_mode_and_bounded_concurrency(self) -> None:
        config = validate_ping_session_config(
            "192.168.1.1",
            3,
            5,
            0.05,
            800,
            mode="async",
            max_in_flight=3,
        )
        self.assertEqual(config["mode"], "async")
        self.assertEqual(config["max_in_flight"], 3)
        udp_config = validate_ping_session_config(
            "192.168.1.1", 3, 5, 0.05, 800, protocol="udp"
        )
        self.assertEqual(udp_config["protocol"], "udp")
        sized_config = validate_ping_session_config(
            "192.168.1.1", 3, 5, 0.05, 800, protocol="udp", udp_payload_size=256
        )
        self.assertEqual(sized_config["udp_payload_size"], 256)
        with self.assertRaises(ValueError):
            validate_ping_session_config(
                "192.168.1.1",
                3,
                5,
                0.05,
                800,
                protocol="udp",
                udp_payload_size=UDP_PAYLOAD_MIN_BYTES - 1,
            )
        with self.assertRaises(ValueError):
            validate_ping_session_config(
                "192.168.1.1",
                3,
                5,
                0.05,
                800,
                protocol="udp",
                udp_payload_size=UDP_PAYLOAD_MAX_BYTES + 1,
            )
        with self.assertRaises(ValueError):
            validate_ping_session_config(
                "192.168.1.1", 3, 5, 0.05, 800, mode="unknown"
            )
        with self.assertRaises(ValueError):
            validate_ping_session_config(
                "192.168.1.1", 3, 5, 0.05, 800, mode="async", max_in_flight=33
            )
        with self.assertRaises(ValueError):
            validate_ping_session_config(
                "192.168.1.1", 3, 5, 0.05, 800, protocol="sctp"
            )

    def test_udp_ping_requires_a_matching_dns_response(self) -> None:
        class FakeSocket:
            def __init__(self):
                self.sent = b""
                self.address = None
                self.timeout = None
                self.closed = False

            def settimeout(self, value):
                self.timeout = value

            def connect(self, address):
                self.address = address

            def send(self, payload):
                self.sent = payload
                return len(payload)

            def recv(self, _size):
                return self.sent[:2] + b"\x81\x80" + b"\x00" * 8

            def close(self):
                self.closed = True

        fake_socket = FakeSocket()
        with patch("ping_monitor.socket.socket", return_value=fake_socket):
            latency = udp_ping("192.168.1.1", port=53, timeout_ms=800)

        self.assertIsNotNone(latency)
        self.assertEqual(fake_socket.address, ("192.168.1.1", 53))
        self.assertEqual(fake_socket.timeout, 0.8)
        self.assertTrue(fake_socket.closed)

    def test_udp_query_matches_requested_size(self) -> None:
        for payload_size in (UDP_PAYLOAD_MIN_BYTES, 44, UDP_PAYLOAD_DEFAULT_BYTES, UDP_PAYLOAD_MAX_BYTES):
            packet = _build_udp_dns_query(b"\x12\x34", payload_size)
            self.assertEqual(len(packet), payload_size)
            self.assertEqual(packet[:2], b"\x12\x34")
        padded_packet = _build_udp_dns_query(b"\x12\x34", UDP_PAYLOAD_DEFAULT_BYTES)
        self.assertIn(b"\x00\x0c", padded_packet)

    def test_smart_ping_passes_custom_udp_payload(self) -> None:
        with (
            patch("ping_monitor.native_ping", return_value=None),
            patch("ping_monitor.tcp_ping", return_value=None),
            patch("ping_monitor.udp_ping", return_value=4) as udp_probe,
        ):
            result = smart_ping(
                "192.168.1.1",
                timeout_ms=800,
                protocol="udp",
                udp_payload_size=256,
            )

        self.assertEqual(result, (4, "UDP:53"))
        udp_probe.assert_called_once_with(
            "192.168.1.1", port=53, timeout_ms=500, payload_size=256
        )

    def test_session_forwards_custom_udp_payload(self) -> None:
        calls = []

        def fake_ping(*args, **kwargs):
            calls.append((args, kwargs))
            return 3, "UDP:53"

        with patch("ping_monitor.smart_ping", side_effect=fake_ping):
            session = PingSession(
                "192.168.1.1",
                count=1,
                duration_s=5,
                interval_s=0.05,
                timeout_ms=800,
                protocol="udp",
                udp_payload_size=256,
            )
            self.assertTrue(session.start())
            session.wait(2)

        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][1]["udp_payload_size"], 256)

    def test_smart_ping_can_fall_back_to_udp(self) -> None:
        with (
            patch("ping_monitor.native_ping", return_value=None),
            patch("ping_monitor.tcp_ping", return_value=None),
            patch("ping_monitor.udp_ping", return_value=7) as udp_probe,
        ):
            result = smart_ping("192.168.1.1", timeout_ms=800)

        self.assertEqual(result, (7, "UDP:53"))
        udp_probe.assert_called_once_with("192.168.1.1", port=53, timeout_ms=500)

    def test_forced_udp_skips_icmp_and_tcp(self) -> None:
        with (
            patch("ping_monitor.native_ping") as icmp_probe,
            patch("ping_monitor.tcp_ping") as tcp_probe,
            patch("ping_monitor.udp_ping", return_value=4) as udp_probe,
        ):
            result = smart_ping("192.168.1.1", timeout_ms=800, protocol="udp")

        self.assertEqual(result, (4, "UDP:53"))
        icmp_probe.assert_not_called()
        tcp_probe.assert_not_called()
        udp_probe.assert_called_once_with("192.168.1.1", port=53, timeout_ms=500)

    def test_async_mode_sends_while_previous_probe_is_running(self) -> None:
        active = 0
        peak = 0
        lock = threading.Lock()

        def fake_ping(_host, timeout_ms=800, protocol="auto"):
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(peak, active)
            time.sleep(0.12)
            with lock:
                active -= 1
            return 2, "ICMP"

        summaries = []
        results = []
        with patch("ping_monitor.smart_ping", side_effect=fake_ping):
            session = PingSession(
                "192.168.1.1",
                count=5,
                duration_s=5,
                interval_s=0.05,
                timeout_ms=800,
                mode="async",
                max_in_flight=3,
                on_result=results.append,
                on_complete=summaries.append,
            )
            self.assertTrue(session.start())
            session.wait(3)

        self.assertFalse(session.is_running)
        self.assertEqual(len(results), 5)
        self.assertEqual({item["index"] for item in results}, {1, 2, 3, 4, 5})
        self.assertGreaterEqual(peak, 2)
        self.assertEqual(summaries[0]["stop_reason"], "count")

    def test_session_completes_requested_count_and_reports_stats(self) -> None:
        summaries = []
        results = []
        with patch("ping_monitor.smart_ping", return_value=(2, "ICMP")):
            session = PingSession(
                "192.168.1.1",
                count=3,
                duration_s=5,
                interval_s=0.05,
                timeout_ms=800,
                on_result=results.append,
                on_complete=summaries.append,
            )
            self.assertTrue(session.start())
            session.wait(2)

        self.assertFalse(session.is_running)
        self.assertEqual(len(results), 3)
        self.assertEqual(len(summaries), 1)
        self.assertEqual(summaries[0]["stop_reason"], "count")
        self.assertEqual(summaries[0]["success_count"], 3)
        self.assertEqual(summaries[0]["avg_ms"], 2)

    def test_stop_cancels_before_requested_count(self) -> None:
        with patch("ping_monitor.smart_ping", return_value=(1, "ICMP")):
            session = PingSession(
                "192.168.1.1",
                count=100,
                duration_s=30,
                interval_s=0.05,
                timeout_ms=800,
            )
            self.assertTrue(session.start())
            session.stop()
            session.wait(2)

        self.assertEqual(session.completed_reason, "cancelled")
        self.assertLess(len(session.results), 100)


@unittest.skipUnless(os.name == "nt", "Windows-only process behavior")
class MacRandomizerProcessTests(unittest.TestCase):
    def test_netsh_queries_hide_the_console_window(self) -> None:
        completed = SimpleNamespace(returncode=0, stdout="", stderr="")
        with patch("mac_randomizer.subprocess.run", return_value=completed) as run:
            mac_randomizer.get_saved_wifi_profiles()

        _, kwargs = run.call_args
        self.assertEqual(kwargs["creationflags"], subprocess.CREATE_NO_WINDOW)
        self.assertTrue(kwargs["startupinfo"].dwFlags & subprocess.STARTF_USESHOWWINDOW)
        self.assertEqual(kwargs["startupinfo"].wShowWindow, subprocess.SW_HIDE)

    def test_settings_opens_directly_without_a_cmd_process(self) -> None:
        with (
            patch("mac_randomizer.os.startfile") as startfile,
            patch("mac_randomizer.subprocess.Popen") as popen,
        ):
            self.assertTrue(mac_randomizer.open_windows_wifi_settings())

        startfile.assert_called_once_with("ms-settings:network-wifi")
        popen.assert_not_called()

    def test_mac_profile_settings_keep_only_privacy_mode(self) -> None:
        completed = SimpleNamespace(returncode=0, stdout="    MAC Randomization : Daily\n", stderr="")
        with patch("mac_randomizer._run_hidden", return_value=completed) as run:
            settings = mac_randomizer.get_mac_profile_settings(["Home Wi-Fi"])

        self.assertEqual(settings, [{"ssid": "Home Wi-Fi", "mode": "daily"}])
        self.assertEqual(run.call_count, 1)

    def test_mac_profile_backup_modes_apply_as_netsh_values(self) -> None:
        with patch("mac_randomizer.set_mac_randomization_for_profile", return_value=(True, "ok")) as set_mode:
            results = mac_randomizer.apply_mac_profile_settings([
                {"ssid": "Home", "mode": "yes"},
                {"ssid": "Office", "mode": "daily"},
                {"ssid": "Guest", "mode": "no"},
            ])

        self.assertTrue(all(item["ok"] for item in results))
        self.assertEqual(
            [call.kwargs["mode"] for call in set_mode.call_args_list],
            ["yes", "daily", "no"],
        )

    def test_saved_profiles_supports_vietnamese_netsh_labels(self) -> None:
        completed = SimpleNamespace(
            returncode=0,
            stdout="    Tất cả hồ sơ người dùng : Wi-Fi Nhà\n",
            stderr="",
        )
        with patch("mac_randomizer._run_hidden", return_value=completed):
            profiles = mac_randomizer.get_saved_wifi_profiles()

        self.assertEqual(profiles, ["Wi-Fi Nhà"])


if __name__ == "__main__":
    unittest.main()
