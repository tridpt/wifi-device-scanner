"""Focused regression tests for the scanner's local-network safety features."""

from __future__ import annotations

import os
import struct
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import mac_randomizer
from network_discovery import _build_dns_query, _read_dns_name, assess_visibility
from network_history import NetworkHistory
from scanner import NetworkScanner
from security_audit import check_smb_guest, evaluate_security_audit, run_security_dashboard
from spy_camera_detector import analyze_spy_camera_risk


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


if __name__ == "__main__":
    unittest.main()
