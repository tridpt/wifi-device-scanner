"""Regression tests for the bounded iperf3 throughput helper."""

from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from throughput_test import (
    THROUGHPUT_MAX_RATE_MBPS,
    THROUGHPUT_PROTOCOL_TCP,
    THROUGHPUT_PROTOCOL_UDP,
    THROUGHPUT_ROLE_CLIENT,
    THROUGHPUT_ROLE_SERVER,
    ThroughputTestSession,
    build_iperf3_command,
    parse_iperf3_json,
    ping_stats,
    summarize_iperf3_json,
    summarize_iperf3_text,
    validate_throughput_config,
)


class ThroughputConfigTests(unittest.TestCase):
    def test_client_config_is_private_and_bounded(self) -> None:
        config = validate_throughput_config(
            role=THROUGHPUT_ROLE_CLIENT,
            target="192.168.1.25",
            rate_mbps=20,
            duration_s=30,
            protocol=THROUGHPUT_PROTOCOL_UDP,
            port=5201,
            udp_payload_size=1200,
            ping_target="192.168.1.1",
        )
        self.assertEqual(config["target"], "192.168.1.25")
        self.assertEqual(config["estimated_bytes"], 75_000_000)

    def test_server_config_requires_private_bind_ip(self) -> None:
        config = validate_throughput_config(
            role=THROUGHPUT_ROLE_SERVER,
            bind_ip="10.0.0.10",
            protocol=THROUGHPUT_PROTOCOL_TCP,
        )
        self.assertEqual(config["bind_ip"], "10.0.0.10")
        with self.assertRaises(ValueError):
            validate_throughput_config(
                role=THROUGHPUT_ROLE_CLIENT,
                target="8.8.8.8",
            )
        with self.assertRaises(ValueError):
            validate_throughput_config(
                role=THROUGHPUT_ROLE_CLIENT,
                target="192.168.1.255",
            )
        with self.assertRaises(ValueError):
            validate_throughput_config(
                role=THROUGHPUT_ROLE_CLIENT,
                target="192.168.1.25",
                rate_mbps=THROUGHPUT_MAX_RATE_MBPS + 1,
            )

    def test_commands_are_shell_free_and_protocol_specific(self) -> None:
        config = validate_throughput_config(
            role=THROUGHPUT_ROLE_CLIENT,
            target="192.168.1.25",
            rate_mbps=20,
            duration_s=30,
            protocol=THROUGHPUT_PROTOCOL_UDP,
        )
        command = build_iperf3_command(config, "C:/tools/iperf3.exe")
        self.assertEqual(command[0], "C:/tools/iperf3.exe")
        self.assertIn("-u", command)
        self.assertIn("-b", command)
        self.assertIn("20M", command)
        self.assertIn("-J", command)
        self.assertNotIn("-s", command)

        server_config = validate_throughput_config(
            role=THROUGHPUT_ROLE_SERVER,
            bind_ip="192.168.1.10",
        )
        server_command = build_iperf3_command(server_config, "iperf3.exe")
        self.assertIn("-s", server_command)
        self.assertIn("-1", server_command)
        self.assertIn("192.168.1.10", server_command)

        udp_server_config = validate_throughput_config(
            role=THROUGHPUT_ROLE_SERVER,
            bind_ip="192.168.1.10",
            protocol=THROUGHPUT_PROTOCOL_UDP,
            rate_mbps=100,
        )
        udp_server_command = build_iperf3_command(udp_server_config, "iperf3.exe")
        self.assertIn("100M/1s", udp_server_command)


class ThroughputParsingTests(unittest.TestCase):
    def test_udp_json_is_normalized(self) -> None:
        payload = {
            "end": {
                "sum": {
                    "bytes": 2_400_000,
                    "seconds": 1.2,
                    "bits_per_second": 16_000_000,
                    "jitter_ms": 1.25,
                    "lost_packets": 2,
                    "packets": 2000,
                    "lost_percent": 0.1,
                }
            }
        }
        result = summarize_iperf3_json(payload)
        self.assertEqual(result["bytes"], 2_400_000)
        self.assertEqual(result["mbps"], 16.0)
        self.assertEqual(result["lost_percent"], 0.1)

    def test_json_parser_can_skip_a_status_prefix(self) -> None:
        data = parse_iperf3_json("status\n" + json.dumps({"end": {}}))
        self.assertEqual(data, {"end": {}})

    def test_server_text_output_is_normalized(self) -> None:
        output = (
            "[  5]   0.00-5.00   sec  2.97 MBytes  4.99 Mbits/sec  "
            "0.074 ms  2/2598 (0.08%)  receiver\n"
        )
        result = summarize_iperf3_text(output)
        self.assertEqual(result["bytes"], 2.97 * 1024 * 1024 // 1)
        self.assertEqual(result["mbps"], 4.99)
        self.assertEqual(result["seconds"], 5.0)
        self.assertEqual(result["lost_packets"], 2)

    def test_ping_stats_keeps_timeout_out_of_latency_average(self) -> None:
        result = ping_stats([2, None, 4, 8])
        self.assertEqual(result["sample_count"], 4)
        self.assertEqual(result["success_count"], 3)
        self.assertEqual(result["loss_rate"], 25.0)
        self.assertEqual(result["avg_ms"], 4.7)
        self.assertEqual(result["p95_ms"], 8.0)


class ThroughputSessionTests(unittest.TestCase):
    def test_session_launches_and_parses_iperf_output(self) -> None:
        output = json.dumps(
            {
                "end": {
                    "sum_received": {
                        "bytes": 1_000_000,
                        "seconds": 1.0,
                        "bits_per_second": 8_000_000,
                    }
                }
            }
        )

        class FakeProcess:
            returncode = 0

            def poll(self):
                return 0

            def communicate(self, timeout=None):
                return output, ""

        calls = []

        def fake_popen(command, **kwargs):
            calls.append((command, kwargs))
            return FakeProcess()

        config = validate_throughput_config(
            role=THROUGHPUT_ROLE_CLIENT,
            target="192.168.1.25",
            rate_mbps=8,
            duration_s=5,
            ping_target="",
        )
        completed = []
        with patch("throughput_test.find_iperf3", return_value="C:/tools/iperf3.exe"):
            session = ThroughputTestSession(
                config,
                on_complete=completed.append,
                popen_factory=fake_popen,
            )
            self.assertTrue(session.start())
            session.wait(2)

        self.assertFalse(session.is_running)
        self.assertEqual(len(calls), 1)
        self.assertEqual(len(completed), 1)
        self.assertEqual(completed[0]["result"]["mbps"], 8.0)
        self.assertIsNone(completed[0]["error"])

    def test_server_without_a_peer_reports_a_useful_error(self) -> None:
        class FakeProcess:
            returncode = 0

            def poll(self):
                return 0

            def communicate(self, timeout=None):
                return "Server listening on 192.168.1.10 port 5201\n", ""

        completed = []
        config = validate_throughput_config(
            role=THROUGHPUT_ROLE_SERVER,
            bind_ip="192.168.1.10",
            ping_target="",
        )
        with patch("throughput_test.find_iperf3", return_value="C:/tools/iperf3.exe"):
            session = ThroughputTestSession(
                config,
                on_complete=completed.append,
                popen_factory=lambda *args, **kwargs: FakeProcess(),
            )
            self.assertTrue(session.start())
            session.wait(2)

        self.assertIsNone(completed[0]["result"])
        self.assertIn("Máy kia chưa kết nối", completed[0]["error"])
