"""Bounded LAN throughput tests backed by a local iperf3 runtime.

The existing ping/load tools deliberately send small probes.  This module is
separate: it starts a rate-limited iperf3 TCP or UDP stream between two LAN
hosts and samples the local router at the same time.
"""

from __future__ import annotations

import ipaddress
import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import threading
import time
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence


THROUGHPUT_ROLE_CLIENT = "client"
THROUGHPUT_ROLE_SERVER = "server"
THROUGHPUT_ROLES = (THROUGHPUT_ROLE_CLIENT, THROUGHPUT_ROLE_SERVER)

THROUGHPUT_PROTOCOL_TCP = "tcp"
THROUGHPUT_PROTOCOL_UDP = "udp"
THROUGHPUT_PROTOCOLS = (THROUGHPUT_PROTOCOL_TCP, THROUGHPUT_PROTOCOL_UDP)

THROUGHPUT_DEFAULT_PORT = 5201
THROUGHPUT_MIN_PORT = 1024
THROUGHPUT_MAX_PORT = 65535
THROUGHPUT_MIN_RATE_MBPS = 1.0
THROUGHPUT_MAX_RATE_MBPS = 10000.0
THROUGHPUT_DEFAULT_RATE_MBPS = 20.0
THROUGHPUT_MIN_DURATION_S = 5.0
THROUGHPUT_MAX_DURATION_S = 10 * 60000.0
THROUGHPUT_DEFAULT_DURATION_S = 30.0
THROUGHPUT_MIN_UDP_PAYLOAD_BYTES = 1
THROUGHPUT_MAX_UDP_PAYLOAD_BYTES = 1200
THROUGHPUT_DEFAULT_UDP_PAYLOAD_BYTES = 32
THROUGHPUT_MIN_PING_INTERVAL_S = 0.1
THROUGHPUT_MAX_PING_INTERVAL_S = 1.0
THROUGHPUT_DEFAULT_PING_INTERVAL_S = 0.1
THROUGHPUT_BASELINE_S = 2.0
THROUGHPUT_MAX_TOTAL_BYTES = 8 * 1024 * 1024 * 1024

_PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


def _private_lan_host(value: Any, field_name: str) -> str:
    """Return a safe LAN IPv4 host, rejecting public and special addresses."""
    text = str(value or "").strip()
    try:
        address = ipaddress.ip_address(text)
    except ValueError as exc:
        raise ValueError(f"{field_name} phải là địa chỉ IPv4 nội bộ, ví dụ 192.168.1.25.") from exc

    if (
        address.version != 4
        or not any(address in network for network in _PRIVATE_NETWORKS)
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
        or int(address) & 0xFF in (0, 255)
    ):
        raise ValueError(
            f"{field_name} chỉ được là host IPv4 riêng trong LAN; "
            "không dùng Internet, địa chỉ mạng hoặc broadcast."
        )
    return str(address)


def _bounded_float(value: Any, field_name: str, minimum: float, maximum: float) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} phải là số.") from exc
    if not math.isfinite(number) or not minimum <= number <= maximum:
        raise ValueError(f"{field_name} phải nằm trong khoảng {minimum:g}-{maximum:g}.")
    return number


def _bounded_int(value: Any, field_name: str, minimum: int, maximum: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} phải là số nguyên.") from exc
    if not minimum <= number <= maximum:
        raise ValueError(f"{field_name} phải nằm trong khoảng {minimum}-{maximum}.")
    return number


def normalize_throughput_role(value: Any) -> str:
    role = str(value or THROUGHPUT_ROLE_CLIENT).strip().lower()
    aliases = {
        "client": THROUGHPUT_ROLE_CLIENT,
        "gửi": THROUGHPUT_ROLE_CLIENT,
        "server": THROUGHPUT_ROLE_SERVER,
        "nhận": THROUGHPUT_ROLE_SERVER,
    }
    role = aliases.get(role, role)
    if role not in THROUGHPUT_ROLES:
        raise ValueError("Vai trò phải là Client hoặc Server.")
    return role


def normalize_throughput_protocol(value: Any) -> str:
    protocol = str(value or THROUGHPUT_PROTOCOL_TCP).strip().lower()
    aliases = {"tcp": THROUGHPUT_PROTOCOL_TCP, "udp": THROUGHPUT_PROTOCOL_UDP}
    protocol = aliases.get(protocol, protocol)
    if protocol not in THROUGHPUT_PROTOCOLS:
        raise ValueError("Giao thức phải là TCP hoặc UDP.")
    return protocol


def validate_throughput_config(
    *,
    role: Any = THROUGHPUT_ROLE_CLIENT,
    target: Any = "",
    bind_ip: Any = "",
    rate_mbps: Any = THROUGHPUT_DEFAULT_RATE_MBPS,
    duration_s: Any = THROUGHPUT_DEFAULT_DURATION_S,
    protocol: Any = THROUGHPUT_PROTOCOL_TCP,
    port: Any = THROUGHPUT_DEFAULT_PORT,
    udp_payload_size: Any = THROUGHPUT_DEFAULT_UDP_PAYLOAD_BYTES,
    ping_target: Any = "",
    ping_interval_s: Any = THROUGHPUT_DEFAULT_PING_INTERVAL_S,
) -> Dict[str, Any]:
    """Validate a short, private-LAN-only throughput test configuration."""
    role = normalize_throughput_role(role)
    protocol = normalize_throughput_protocol(protocol)
    rate_mbps = _bounded_float(
        rate_mbps,
        "Tốc độ mục tiêu (Mbps)",
        THROUGHPUT_MIN_RATE_MBPS,
        THROUGHPUT_MAX_RATE_MBPS,
    )
    duration_s = _bounded_float(
        duration_s,
        "Thời gian test (giây)",
        THROUGHPUT_MIN_DURATION_S,
        THROUGHPUT_MAX_DURATION_S,
    )
    port = _bounded_int(port, "Cổng iperf3", THROUGHPUT_MIN_PORT, THROUGHPUT_MAX_PORT)
    udp_payload_size = _bounded_int(
        udp_payload_size,
        "Payload UDP (byte)",
        THROUGHPUT_MIN_UDP_PAYLOAD_BYTES,
        THROUGHPUT_MAX_UDP_PAYLOAD_BYTES,
    )
    ping_interval_s = _bounded_float(
        ping_interval_s,
        "Khoảng lấy mẫu ping (giây)",
        THROUGHPUT_MIN_PING_INTERVAL_S,
        THROUGHPUT_MAX_PING_INTERVAL_S,
    )

    estimated_bytes = rate_mbps * 1_000_000 / 8 * duration_s
    if estimated_bytes > THROUGHPUT_MAX_TOTAL_BYTES:
        raise ValueError("Tổng dữ liệu dự kiến vượt giới hạn an toàn của bài test.")

    normalized_target = ""
    normalized_bind_ip = ""
    if role == THROUGHPUT_ROLE_CLIENT:
        normalized_target = _private_lan_host(target, "IP máy server")
    else:
        normalized_bind_ip = _private_lan_host(bind_ip, "IP nội bộ của máy này")

    normalized_ping_target = ""
    if str(ping_target or "").strip():
        normalized_ping_target = _private_lan_host(ping_target, "IP router để ping")

    return {
        "role": role,
        "target": normalized_target,
        "bind_ip": normalized_bind_ip,
        "rate_mbps": rate_mbps,
        "duration_s": duration_s,
        "protocol": protocol,
        "port": port,
        "udp_payload_size": udp_payload_size,
        "ping_target": normalized_ping_target,
        "ping_interval_s": ping_interval_s,
        "estimated_bytes": int(estimated_bytes),
    }


def _resource_roots() -> Iterable[Path]:
    """Yield likely runtime roots for source runs, PATH installs, and PyInstaller."""
    bundle_root = getattr(sys, "_MEIPASS", None)
    if bundle_root:
        yield Path(bundle_root)
    yield Path(__file__).resolve().parent
    if getattr(sys, "frozen", False):
        yield Path(sys.executable).resolve().parent


def find_iperf3(explicit_path: Any = "") -> Optional[str]:
    """Find the bundled portable iperf3 executable or one supplied by the user."""
    candidates: List[Path] = []
    if str(explicit_path or "").strip():
        candidates.append(Path(str(explicit_path).strip()))

    for root in _resource_roots():
        candidates.extend(
            (
                root / "assets" / "iperf3" / "iperf3.exe",
                root / "iperf3.exe",
            )
        )

    for candidate in candidates:
        try:
            if candidate.is_file():
                return str(candidate.resolve())
        except OSError:
            continue

    for executable_name in ("iperf3.exe", "iperf3"):
        resolved = shutil.which(executable_name)
        if resolved:
            return resolved
    return None


def build_iperf3_command(config: Dict[str, Any], executable: str) -> List[str]:
    """Create an argument list without shell interpolation or unbounded flags."""
    role = config["role"]
    if role == THROUGHPUT_ROLE_SERVER:
        # Allow a little protocol overhead while keeping every accepted client
        # at or below the app's global LAN safety ceiling.
        server_limit_mbps = min(THROUGHPUT_MAX_RATE_MBPS, config["rate_mbps"] * 1.5)
        command = [
            executable,
            "-s",
            "-1",  # Stop after one local-LAN client rather than leaving a service open.
            "-B",
            config["bind_ip"],
            "-p",
            str(config["port"]),
            "--server-bitrate-limit",
            f"{server_limit_mbps:g}M/1s",
            "--server-max-duration",
            str(math.ceil(config["duration_s"] + 2)),
        ]
        return command

    command = [
        executable,
        "-c",
        config["target"],
        "-p",
        str(config["port"]),
        "-t",
        f"{config['duration_s']:g}",
        "-b",
        f"{config['rate_mbps']:g}M",
        "-J",
    ]
    if config["protocol"] == THROUGHPUT_PROTOCOL_UDP:
        command.extend(("-u", "-l", str(config["udp_payload_size"])))
    return command


def parse_iperf3_json(output: str) -> Dict[str, Any]:
    """Read iperf3 JSON even when a wrapper prepends a short status line."""
    text = str(output or "").strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start < 0 or end <= start:
            raise ValueError("iperf3 không trả về dữ liệu JSON hợp lệ.")
        try:
            data = json.loads(text[start : end + 1])
        except json.JSONDecodeError as exc:
            raise ValueError("iperf3 không trả về dữ liệu JSON hợp lệ.") from exc
    if not isinstance(data, dict):
        raise ValueError("Dữ liệu iperf3 không hợp lệ.")
    if data.get("error"):
        raise ValueError(str(data["error"]))
    return data


def summarize_iperf3_json(data: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize TCP and UDP client/server result layouts into one summary."""
    end = data.get("end")
    if not isinstance(end, dict):
        raise ValueError("iperf3 chưa có kết quả hoàn tất.")

    candidates = [end.get("sum_received"), end.get("sum"), end.get("sum_sent")]
    aggregate: Optional[Dict[str, Any]] = None
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        if candidate.get("bits_per_second") is not None:
            aggregate = candidate
            break
    if aggregate is None:
        raise ValueError("iperf3 không trả về thông lượng tổng.")

    try:
        bits_per_second = float(aggregate.get("bits_per_second", 0))
        byte_count = int(aggregate.get("bytes", 0))
        seconds = float(aggregate.get("seconds", aggregate.get("end", 0)))
    except (TypeError, ValueError) as exc:
        raise ValueError("Kết quả iperf3 không đầy đủ.") from exc

    return {
        "bytes": max(0, byte_count),
        "seconds": max(0.0, seconds),
        "bits_per_second": max(0.0, bits_per_second),
        "mbps": max(0.0, bits_per_second) / 1_000_000,
        "jitter_ms": _optional_float(aggregate.get("jitter_ms")),
        "lost_packets": _optional_int(aggregate.get("lost_packets")),
        "packets": _optional_int(aggregate.get("packets")),
        "lost_percent": _optional_float(aggregate.get("lost_percent")),
    }


def summarize_iperf3_text(output: str) -> Dict[str, Any]:
    """Parse the final receiver line emitted by a server without ``-J``."""
    interval_pattern = r"(?P<start_s>[\d.]+)\s*-\s*(?P<end_s>[\d.]+)\s+sec"
    udp_pattern = re.compile(
        r"\[\s*\d+\]\s+" + interval_pattern + r"\s+"
        r"(?P<bytes>[\d.]+)\s+(?P<byte_unit>[KMG]?Bytes)\s+"
        r"(?P<rate>[\d.]+)\s+(?P<rate_unit>[KMG]?bits/sec)\s+"
        r"(?P<jitter>[\d.]+)\s+ms\s+"
        r"(?P<lost>\d+)/(?P<packets>\d+)\s+\((?P<loss>[\d.]+)%\).*receiver\s*$",
        re.IGNORECASE,
    )
    tcp_pattern = re.compile(
        r"\[\s*\d+\]\s+" + interval_pattern + r"\s+"
        r"(?P<bytes>[\d.]+)\s+(?P<byte_unit>[KMG]?Bytes)\s+"
        r"(?P<rate>[\d.]+)\s+(?P<rate_unit>[KMG]?bits/sec).*receiver\s*$",
        re.IGNORECASE,
    )
    match = None
    for line in str(output or "").splitlines():
        match = udp_pattern.search(line) or tcp_pattern.search(line) or match
    if not match:
        raise ValueError("Không tìm thấy dòng kết quả receiver của iperf3.")

    groups = match.groupdict()
    byte_multiplier = {"Bytes": 1, "KBytes": 1024, "MBytes": 1024**2, "GBytes": 1024**3}
    rate_multiplier = {"bits/sec": 1, "Kbits/sec": 1000, "Mbits/sec": 1_000_000, "Gbits/sec": 1_000_000_000}
    byte_unit = groups["byte_unit"].replace(" ", "")
    rate_unit = groups["rate_unit"].replace(" ", "")
    byte_unit_key = {
        "bytes": "Bytes",
        "kbytes": "KBytes",
        "mbytes": "MBytes",
        "gbytes": "GBytes",
    }.get(byte_unit.lower(), byte_unit)
    rate_unit_key = {
        "bits/sec": "bits/sec",
        "kbits/sec": "Kbits/sec",
        "mbits/sec": "Mbits/sec",
        "gbits/sec": "Gbits/sec",
    }.get(rate_unit.lower(), rate_unit)
    bytes_count = float(groups["bytes"]) * byte_multiplier.get(byte_unit_key, 1)
    bits_per_second = float(groups["rate"]) * rate_multiplier.get(rate_unit_key, 1)
    seconds = max(0.0, float(groups["end_s"]) - float(groups["start_s"]))
    return {
        "bytes": int(bytes_count),
        "seconds": seconds,
        "bits_per_second": bits_per_second,
        "mbps": bits_per_second / 1_000_000,
        "jitter_ms": _optional_float(groups.get("jitter")),
        "lost_packets": _optional_int(groups.get("lost")),
        "packets": _optional_int(groups.get("packets")),
        "lost_percent": _optional_float(groups.get("loss")),
    }


def _optional_float(value: Any) -> Optional[float]:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def _optional_int(value: Any) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def ping_stats(samples: Sequence[Optional[float]]) -> Dict[str, Any]:
    """Calculate stable latency metrics without treating a timeout as zero ms."""
    valid: List[float] = []
    for value in samples:
        try:
            number = float(value)
        except (TypeError, ValueError):
            continue
        if math.isfinite(number):
            valid.append(number)
    total = len(samples)
    if not valid:
        return {
            "sample_count": total,
            "success_count": 0,
            "loss_rate": 100.0 if total else 0.0,
            "min_ms": None,
            "avg_ms": None,
            "p50_ms": None,
            "p95_ms": None,
            "max_ms": None,
            "jitter_ms": None,
        }

    ordered = sorted(valid)
    p50_index = max(0, math.ceil(len(ordered) * 0.50) - 1)
    p95_index = max(0, math.ceil(len(ordered) * 0.95) - 1)
    deltas = [abs(valid[index] - valid[index - 1]) for index in range(1, len(valid))]
    return {
        "sample_count": total,
        "success_count": len(valid),
        "loss_rate": round((total - len(valid)) / total * 100, 1) if total else 0.0,
        "min_ms": round(min(valid), 1),
        "avg_ms": round(sum(valid) / len(valid), 1),
        "p50_ms": round(ordered[p50_index], 1),
        "p95_ms": round(ordered[p95_index], 1),
        "max_ms": round(max(valid), 1),
        "jitter_ms": round(sum(deltas) / len(deltas), 1) if deltas else 0.0,
    }


def _default_ping_probe(target: str, timeout_ms: int) -> Optional[int]:
    # Keep this import lazy so parser/validator tests work on non-Windows hosts.
    from ping_monitor import native_ping

    return native_ping(target, timeout_ms=timeout_ms)


class ThroughputTestSession:
    """Run one bounded iperf3 test and collect router latency alongside it."""

    def __init__(
        self,
        config: Dict[str, Any],
        *,
        executable: Optional[str] = None,
        on_update: Optional[Callable[[Dict[str, Any]], None]] = None,
        on_complete: Optional[Callable[[Dict[str, Any]], None]] = None,
        ping_probe: Optional[Callable[[str, int], Optional[int]]] = None,
        popen_factory: Callable[..., Any] = subprocess.Popen,
    ) -> None:
        # Re-validate at the engine boundary so callers cannot bypass the UI
        # limits by constructing a session directly.
        self.config = validate_throughput_config(
            role=config.get("role", THROUGHPUT_ROLE_CLIENT),
            target=config.get("target", ""),
            bind_ip=config.get("bind_ip", ""),
            rate_mbps=config.get("rate_mbps", THROUGHPUT_DEFAULT_RATE_MBPS),
            duration_s=config.get("duration_s", THROUGHPUT_DEFAULT_DURATION_S),
            protocol=config.get("protocol", THROUGHPUT_PROTOCOL_TCP),
            port=config.get("port", THROUGHPUT_DEFAULT_PORT),
            udp_payload_size=config.get("udp_payload_size", THROUGHPUT_DEFAULT_UDP_PAYLOAD_BYTES),
            ping_target=config.get("ping_target", ""),
            ping_interval_s=config.get("ping_interval_s", THROUGHPUT_DEFAULT_PING_INTERVAL_S),
        )
        self.executable = executable
        self.on_update = on_update
        self.on_complete = on_complete
        self._ping_probe = ping_probe or _default_ping_probe
        self._popen_factory = popen_factory
        self._stop_event = threading.Event()
        self._ping_stop_event = threading.Event()
        self._process_lock = threading.Lock()
        self._process: Optional[Any] = None
        self._thread: Optional[threading.Thread] = None
        self._ping_thread: Optional[threading.Thread] = None

        self.is_running = False
        self.started_at: Optional[float] = None
        self.finished_at: Optional[float] = None
        self.baseline_samples: List[Optional[float]] = []
        self.during_samples: List[Optional[float]] = []
        self.summary: Optional[Dict[str, Any]] = None

    def start(self) -> bool:
        if self.is_running:
            return False
        self._stop_event.clear()
        self._ping_stop_event.clear()
        self.baseline_samples = []
        self.during_samples = []
        self.summary = None
        self.started_at = time.monotonic()
        self.finished_at = None
        self.is_running = True
        self._thread = threading.Thread(target=self._run, name="throughput-test", daemon=True)
        self._thread.start()
        return True

    def stop(self) -> None:
        """Stop the process and the sampler; no new network traffic is scheduled."""
        self._stop_event.set()
        self._ping_stop_event.set()
        self._terminate_process()

    def wait(self, timeout: Optional[float] = None) -> None:
        thread = self._thread
        if thread and thread is not threading.current_thread():
            thread.join(timeout)

    def _emit(self, event: Dict[str, Any]) -> None:
        if not self.on_update:
            return
        try:
            self.on_update(event)
        except Exception:
            pass

    def _emit_status(self, message: str) -> None:
        self._emit({"kind": "status", "message": message})

    def _take_baseline(self) -> None:
        target = self.config.get("ping_target", "")
        if not target:
            return
        self._emit_status("Đang lấy mốc ping tới router trước khi truyền dữ liệu...")
        deadline = time.monotonic() + THROUGHPUT_BASELINE_S
        while not self._stop_event.is_set() and time.monotonic() < deadline:
            sample_started = time.monotonic()
            sample = self._probe_ping(target)
            self.baseline_samples.append(sample)
            self._emit({"kind": "ping", "phase": "baseline", "latency_ms": sample})
            self._wait_for_next_ping(sample_started)

    def _probe_ping(self, target: str) -> Optional[float]:
        try:
            value = self._ping_probe(target, 800)
            return float(value) if value is not None else None
        except Exception:
            return None

    def _wait_for_next_ping(self, sample_started: float) -> None:
        remaining = max(0.0, self.config["ping_interval_s"] - (time.monotonic() - sample_started))
        self._stop_event.wait(remaining)

    def _sample_during_test(self) -> None:
        target = self.config.get("ping_target", "")
        if not target:
            return
        while not self._ping_stop_event.is_set() and not self._stop_event.is_set():
            sample_started = time.monotonic()
            sample = self._probe_ping(target)
            self.during_samples.append(sample)
            self._emit({"kind": "ping", "phase": "during", "latency_ms": sample})
            remaining = max(0.0, self.config["ping_interval_s"] - (time.monotonic() - sample_started))
            self._ping_stop_event.wait(remaining)

    def _start_ping_sampler(self) -> None:
        if not self.config.get("ping_target"):
            return
        self._ping_thread = threading.Thread(
            target=self._sample_during_test,
            name="throughput-router-ping",
            daemon=True,
        )
        self._ping_thread.start()

    def _stop_ping_sampler(self) -> None:
        self._ping_stop_event.set()
        thread = self._ping_thread
        if thread and thread is not threading.current_thread():
            thread.join(timeout=1.5)

    def _launch_process(self, command: List[str]) -> Any:
        creationflags = 0
        if os.name == "nt":
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        return self._popen_factory(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=str(Path(command[0]).resolve().parent),
            creationflags=creationflags,
        )

    def _terminate_process(self) -> None:
        with self._process_lock:
            process = self._process
        if not process:
            return
        try:
            if process.poll() is None:
                process.terminate()
                # The Windows build can leave a Cygwin child alive after the
                # wrapper is terminated; end only this process tree.
                if os.name == "nt":
                    subprocess.run(
                        ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        check=False,
                        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                    )
        except Exception:
            pass

    def _start_output_reader(self, process: Any) -> tuple[Dict[str, Any], threading.Thread]:
        """Drain both pipes while iperf3 runs; UDP JSON can exceed a Windows pipe."""
        output: Dict[str, Any] = {"stdout": "", "stderr": "", "error": None}

        def collect() -> None:
            try:
                stdout, stderr = process.communicate()
                output["stdout"] = str(stdout or "")
                output["stderr"] = str(stderr or "")
            except Exception as exc:
                output["error"] = exc

        reader = threading.Thread(target=collect, name="throughput-output-reader", daemon=True)
        reader.start()
        return output, reader

    def _run(self) -> None:
        error: Optional[str] = None
        process_result: Optional[Dict[str, Any]] = None
        process_return_code: Optional[int] = None
        cancelled = False
        timed_out = False
        command: List[str] = []
        test_started_at: Optional[float] = None
        try:
            executable = self.executable or find_iperf3()
            if not executable:
                raise FileNotFoundError(
                    "Không tìm thấy iperf3.exe. Hãy dùng nút Chọn iperf3 hoặc đặt "
                    "iperf3.exe cùng cygwin1.dll vào thư mục assets/iperf3."
                )
            command = build_iperf3_command(self.config, executable)
            self._take_baseline()
            if self._stop_event.is_set():
                cancelled = True
                return

            if self.config["role"] == THROUGHPUT_ROLE_CLIENT:
                self._emit_status("Đang truyền dữ liệu có kiểm soát và lấy mẫu ping router...")
            else:
                self._emit_status("Server đang chờ đúng một client trong mạng LAN...")

            process = self._launch_process(command)
            with self._process_lock:
                self._process = process
            output, output_reader = self._start_output_reader(process)
            test_started_at = time.monotonic()
            self._start_ping_sampler()
            grace_s = 15.0 if self.config["role"] == THROUGHPUT_ROLE_CLIENT else 2.0
            deadline = test_started_at + self.config["duration_s"] + grace_s
            while process.poll() is None:
                now = time.monotonic()
                if self._stop_event.is_set():
                    cancelled = True
                    self._terminate_process()
                elif now >= deadline:
                    timed_out = True
                    self._terminate_process()
                else:
                    self._emit(
                        {
                            "kind": "progress",
                            "elapsed_s": max(0.0, now - test_started_at),
                            "duration_s": self.config["duration_s"],
                        }
                    )
                self._stop_event.wait(0.1)

            output_reader.join(timeout=5)
            stdout = output.get("stdout", "")
            stderr = output.get("stderr", "")
            process_return_code = process.returncode
            if output.get("error") and not cancelled and not timed_out:
                error = f"Không thể đọc kết quả iperf3: {output['error']}"
            if stdout.strip():
                try:
                    process_result = summarize_iperf3_json(parse_iperf3_json(stdout))
                except ValueError as exc:
                    if self.config["role"] == THROUGHPUT_ROLE_SERVER:
                        try:
                            process_result = summarize_iperf3_text(stdout)
                        except ValueError:
                            if process_return_code == 0:
                                error = (
                                    "Không có kết quả throughput. Máy kia chưa kết nối, đã ngắt kết nối, "
                                    "hoặc iperf3 hai bên không tương thích."
                                )
                    elif process_return_code == 0:
                        error = str(exc)
            if process_return_code not in (0, None) and not cancelled and not timed_out:
                error = (stderr.strip() or "iperf3 kết thúc với lỗi.")[:600]
            elif not process_result and not error and not cancelled and not timed_out:
                error = (
                    "Không có kết quả throughput. Máy kia chưa kết nối, đã ngắt kết nối, "
                    "hoặc iperf3 hai bên không tương thích."
                )
        except Exception as exc:
            error = str(exc)
        finally:
            self._stop_ping_sampler()
            with self._process_lock:
                self._process = None
            self.finished_at = time.monotonic()
            self.is_running = False
            elapsed_s = 0.0
            if self.started_at is not None:
                elapsed_s = max(0.0, self.finished_at - self.started_at)
            baseline = ping_stats(self.baseline_samples)
            during = ping_stats(self.during_samples)
            avg_delta = None
            p95_delta = None
            if baseline["avg_ms"] is not None and during["avg_ms"] is not None:
                avg_delta = round(during["avg_ms"] - baseline["avg_ms"], 1)
            if baseline["p95_ms"] is not None and during["p95_ms"] is not None:
                p95_delta = round(during["p95_ms"] - baseline["p95_ms"], 1)

            self.summary = {
                "config": dict(self.config),
                "command": command,
                "return_code": process_return_code,
                "result": process_result,
                "baseline_ping": baseline,
                "during_ping": during,
                "avg_ping_delta_ms": avg_delta,
                "p95_ping_delta_ms": p95_delta,
                "elapsed_s": round(elapsed_s, 2),
                "cancelled": cancelled,
                "timed_out": timed_out,
                "error": error,
            }
            if self.on_complete:
                try:
                    self.on_complete(self.summary)
                except Exception:
                    pass
