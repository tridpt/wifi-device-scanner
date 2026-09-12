"""
ping_monitor.py - Bộ giám sát độ trễ và độ ổn định mạng thời gian thực (Real-time Ping Monitor).
Sử dụng Windows Native ICMP API 64-bit và các probe TCP/UDP.
Đo đồng thời Router nội bộ và Internet để chẩn đoán nguyên nhân gây giật lag.
"""

import ctypes
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
import ipaddress
import math
import secrets
import socket
import struct
import threading
import time
from collections import deque
from ctypes import wintypes
from typing import Optional, Dict, Any, List, Tuple, Callable

# Khởi tạo thư viện ICMP của Windows
_icmp = ctypes.windll.icmp

IcmpCreateFile = _icmp.IcmpCreateFile
IcmpCreateFile.restype = wintypes.HANDLE

IcmpCloseHandle = _icmp.IcmpCloseHandle
IcmpCloseHandle.argtypes = [wintypes.HANDLE]
IcmpCloseHandle.restype = wintypes.BOOL

IcmpSendEcho = _icmp.IcmpSendEcho
IcmpSendEcho.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.WORD,
    wintypes.LPVOID,
    wintypes.LPVOID,
    wintypes.DWORD,
    wintypes.DWORD,
]
IcmpSendEcho.restype = wintypes.DWORD


class IP_OPTION_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("Ttl", ctypes.c_ubyte),
        ("Tos", ctypes.c_ubyte),
        ("Flags", ctypes.c_ubyte),
        ("OptionsSize", ctypes.c_ubyte),
        ("OptionsData", ctypes.c_void_p),
    ]


class ICMP_ECHO_REPLY(ctypes.Structure):
    _fields_ = [
        ("Address", wintypes.DWORD),
        ("Status", wintypes.DWORD),
        ("RoundTripTime", wintypes.DWORD),
        ("DataSize", wintypes.WORD),
        ("Reserved", wintypes.WORD),
        ("Data", ctypes.c_void_p),
        ("Options", IP_OPTION_INFORMATION),
    ]


def native_ping(ip_str: str, timeout_ms: int = 1000) -> Optional[int]:
    """
    Gửi gói ICMP Echo Request trực tiếp bằng Windows Native API.
    Trả về RoundTripTime (ms) nếu thành công, None nếu timeout hoặc rớt gói.
    """
    handle = IcmpCreateFile()
    if not handle or handle == wintypes.HANDLE(-1).value:
        return None
    try:
        dest_addr = struct.unpack("<I", socket.inet_aton(ip_str))[0]
        data = b"wifi_ping_probe"
        reply_size = ctypes.sizeof(ICMP_ECHO_REPLY) + len(data) + 16
        reply_buf = ctypes.create_string_buffer(reply_size)
        res = IcmpSendEcho(
            handle, dest_addr, data, len(data), None, reply_buf, reply_size, timeout_ms
        )
        if res != 0:
            reply = ICMP_ECHO_REPLY.from_buffer_copy(
                reply_buf[: ctypes.sizeof(ICMP_ECHO_REPLY)]
            )
            if reply.Status == 0:
                return reply.RoundTripTime
        return None
    except Exception:
        return None
    finally:
        IcmpCloseHandle(handle)


def tcp_ping(host: str, port: int = 53, timeout_ms: int = 800) -> Optional[int]:
    """
    Đo độ trễ bằng phương pháp bắt tay TCP (TCP SYN/ACK Handshake).
    Vượt qua 100% tường lửa chặn gói tin ICMP của Modem mạng và Nhà mạng.
    """
    t0 = time.perf_counter()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout_ms / 1000.0)
    try:
        s.connect((host, port))
        latency = int(round((time.perf_counter() - t0) * 1000))
        return max(latency, 1)
    except Exception:
        return None
    finally:
        try:
            s.close()
        except Exception:
            pass


UDP_PAYLOAD_MIN_BYTES = 32
UDP_PAYLOAD_MAX_BYTES = 1200
UDP_PAYLOAD_DEFAULT_BYTES = 64


def _validate_udp_payload_size(payload_size: int) -> int:
    try:
        payload_size = int(payload_size)
    except (TypeError, ValueError) as exc:
        raise ValueError("Payload UDP phải là số nguyên (byte).") from exc
    if not UDP_PAYLOAD_MIN_BYTES <= payload_size <= UDP_PAYLOAD_MAX_BYTES:
        raise ValueError(
            f"Payload UDP phải nằm trong khoảng {UDP_PAYLOAD_MIN_BYTES}-"
            f"{UDP_PAYLOAD_MAX_BYTES} byte."
        )
    return payload_size


def _dns_qname_wire(labels: Tuple[str, ...]) -> bytes:
    """Encode DNS labels without allowing an oversized label."""
    encoded = bytearray()
    for label in labels:
        label_bytes = label.encode("ascii")
        if not 1 <= len(label_bytes) <= 63:
            raise ValueError("Nhãn DNS không hợp lệ.")
        encoded.append(len(label_bytes))
        encoded.extend(label_bytes)
    encoded.append(0)
    return bytes(encoded)


def _build_udp_dns_query(query_id: bytes, payload_size: int) -> bytes:
    """Build a DNS query of the requested size using RFC 7830 padding."""
    payload_size = _validate_udp_payload_size(payload_size)
    if len(query_id) != 2:
        raise ValueError("DNS transaction ID phải dài 2 byte.")

    # The ordinary example.com query is 29 bytes. For the small range where an
    # EDNS OPT record would be larger than the requested packet, lengthen the
    # valid QNAME instead.
    base_qname = _dns_qname_wire(("example", "com"))
    base_size = 12 + len(base_qname) + 4
    if payload_size < 44:
        prefix_length = payload_size - base_size - 1
        if prefix_length < 1:
            raise ValueError("Payload UDP quá nhỏ cho truy vấn DNS hợp lệ.")
        qname = _dns_qname_wire(("p" * prefix_length, "example", "com"))
        header = struct.pack("!HHHHHH", int.from_bytes(query_id, "big"), 0x0100, 1, 0, 0, 0)
        return header + qname + b"\x00\x01\x00\x01"

    # OPT header (11 bytes) + PADDING option header (4 bytes) = 15 bytes.
    padding_length = payload_size - (base_size + 15)
    if padding_length < 0:
        raise ValueError("Payload UDP không đủ chỗ cho phần mở rộng DNS.")
    header = struct.pack("!HHHHHH", int.from_bytes(query_id, "big"), 0x0100, 1, 0, 0, 1)
    question = base_qname + b"\x00\x01\x00\x01"
    opt_record = (
        b"\x00\x00\x29"  # root name + OPT record type
        + struct.pack("!H", 1232)  # advertised safe UDP response size
        + b"\x00\x00\x00\x00"  # extended RCODE, version, and flags
        + struct.pack("!H", padding_length + 4)
        + b"\x00\x0c"  # EDNS(0) PADDING option (RFC 7830)
        + struct.pack("!H", padding_length)
        + (b"\x00" * padding_length)
    )
    return header + question + opt_record


def udp_ping(
    host: str,
    port: int = 53,
    timeout_ms: int = 800,
    payload_size: int = UDP_PAYLOAD_DEFAULT_BYTES,
) -> Optional[int]:
    """Measure a padded UDP DNS round trip and require a matching reply."""
    query_id = secrets.token_bytes(2)
    query = _build_udp_dns_query(query_id, payload_size)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout_ms / 1000.0)
        sock.connect((host, port))
        started_at = time.perf_counter()
        sock.send(query)
        reply = sock.recv(4096)
        # Sending a UDP datagram only means the local OS accepted it. A matching
        # DNS response is required before treating the target as reachable.
        if len(reply) < 12 or reply[:2] != query_id or not (reply[2] & 0x80):
            return None
        latency = int(round((time.perf_counter() - started_at) * 1000))
        return max(latency, 1)
    except (OSError, socket.timeout):
        return None
    finally:
        try:
            sock.close()
        except Exception:
            pass


PING_PROTOCOL_AUTO = "auto"
PING_PROTOCOL_ICMP = "icmp"
PING_PROTOCOL_TCP = "tcp"
PING_PROTOCOL_UDP = "udp"
PING_PROTOCOLS = (
    PING_PROTOCOL_AUTO,
    PING_PROTOCOL_ICMP,
    PING_PROTOCOL_TCP,
    PING_PROTOCOL_UDP,
)


def normalize_ping_protocol(protocol: str = PING_PROTOCOL_AUTO) -> str:
    """Normalize protocol labels accepted by the UI and public ping helpers."""
    protocol = str(protocol or PING_PROTOCOL_AUTO).strip().lower()
    aliases = {
        "automatic": PING_PROTOCOL_AUTO,
        "tự động": PING_PROTOCOL_AUTO,
        "tự động (icmp -> tcp -> udp)": PING_PROTOCOL_AUTO,
        "icmp": PING_PROTOCOL_ICMP,
        "tcp": PING_PROTOCOL_TCP,
        "tcp handshake": PING_PROTOCOL_TCP,
        "udp": PING_PROTOCOL_UDP,
        "udp dns": PING_PROTOCOL_UDP,
        "udp dns (53)": PING_PROTOCOL_UDP,
    }
    protocol = aliases.get(protocol, protocol)
    if protocol not in PING_PROTOCOLS:
        raise ValueError("Giao thức phải là Tự động, ICMP, TCP hoặc UDP.")
    return protocol


def smart_ping(
    host: str,
    timeout_ms: int = 800,
    protocol: str = PING_PROTOCOL_AUTO,
    udp_payload_size: int = UDP_PAYLOAD_DEFAULT_BYTES,
) -> Tuple[Optional[int], str]:
    """
    Đo ping theo giao thức chọn trước hoặc Hybrid Smart Ping:
    1. Tự động: ICMP, sau đó TCP, rồi UDP DNS/53 nếu các bước trước thất bại.
    2. TCP: đo bằng TCP handshake tại cổng 53/80/443.
    3. UDP: gửi truy vấn DNS qua UDP/53 và chờ đúng phản hồi DNS.
    Trả về: (latency_ms, method_used)
    """
    protocol = normalize_ping_protocol(protocol)

    if protocol in (PING_PROTOCOL_AUTO, PING_PROTOCOL_ICMP):
        try:
            t_icmp = native_ping(host, timeout_ms=min(timeout_ms, 350))
            if t_icmp is not None:
                return t_icmp, "ICMP"
        except Exception:
            pass
        if protocol == PING_PROTOCOL_ICMP:
            return None, "ICMP Timeout"

    if protocol in (PING_PROTOCOL_AUTO, PING_PROTOCOL_TCP):
        for port in (53, 80, 443):
            t_tcp = tcp_ping(host, port=port, timeout_ms=min(timeout_ms, 300))
            if t_tcp is not None:
                return t_tcp, f"TCP:{port}"
        if protocol == PING_PROTOCOL_TCP:
            return None, "TCP Timeout"

    if protocol in (PING_PROTOCOL_AUTO, PING_PROTOCOL_UDP):
        udp_timeout = min(timeout_ms, 500)
        # Keep the default call shape compatible with existing integrations;
        # only pass the extra argument when a custom payload was requested.
        if udp_payload_size == UDP_PAYLOAD_DEFAULT_BYTES:
            t_udp = udp_ping(host, port=53, timeout_ms=udp_timeout)
        else:
            t_udp = udp_ping(
                host,
                port=53,
                timeout_ms=udp_timeout,
                payload_size=udp_payload_size,
            )
        if t_udp is not None:
            return t_udp, "UDP:53"
        if protocol == PING_PROTOCOL_UDP:
            return None, "UDP:53 Timeout"

    return None, "Timeout"


# Giới hạn an toàn cho một phiên ping thủ công.
PING_MAX_COUNT = 10000
PING_MAX_DURATION_S = 24 * 60 * 60
PING_MIN_INTERVAL_S = 0.05
PING_MAX_INTERVAL_S = 3600.0
PING_MIN_TIMEOUT_MS = 100
PING_MAX_TIMEOUT_MS = 10000
PING_MIN_IN_FLIGHT = 1
PING_MAX_IN_FLIGHT = 32
PING_DEFAULT_IN_FLIGHT = 4
PING_MODE_SEQUENTIAL = "sequential"
PING_MODE_ASYNC = "async"
PING_MODES = (PING_MODE_SEQUENTIAL, PING_MODE_ASYNC)

# Giới hạn cho bài test chịu tải nội bộ. Các giới hạn này thấp hơn nhiều so
# với một công cụ flood và giúp modem có cơ hội xử lý/ghi nhận phản hồi.
LOAD_TEST_MIN_RATE_PPS = 1.0
LOAD_TEST_MAX_RATE_PPS = 100.0
LOAD_TEST_DEFAULT_RATE_PPS = 10.0
LOAD_TEST_MIN_DURATION_S = 1.0
LOAD_TEST_MAX_DURATION_S = 10 * 60
LOAD_TEST_DEFAULT_DURATION_S = 60.0
LOAD_TEST_MAX_PACKETS = 100000
_LOAD_TEST_PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


def validate_load_test_config(
    target: str,
    rate_pps: float,
    duration_s: float,
    timeout_ms: int,
    protocol: str = PING_PROTOCOL_UDP,
    udp_payload_size: int = UDP_PAYLOAD_DEFAULT_BYTES,
    max_in_flight: int = PING_DEFAULT_IN_FLIGHT,
) -> Dict[str, Any]:
    """Validate a bounded load test that can only target a private IPv4 host."""
    target = str(target or "").strip()
    try:
        target_ip = ipaddress.ip_address(target)
    except ValueError as exc:
        raise ValueError("Test chịu tải chỉ nhận địa chỉ IPv4 nội bộ, ví dụ 192.168.1.1.") from exc
    if (
        target_ip.version != 4
        or not any(target_ip in network for network in _LOAD_TEST_PRIVATE_NETWORKS)
        or target_ip.is_loopback
        or target_ip.is_link_local
        or target_ip.is_multicast
        or target_ip.is_unspecified
        or target_ip.is_reserved
        or int(target_ip) & 0xFF in (0, 255)
    ):
        raise ValueError(
            "Chỉ được test tới địa chỉ IPv4 host riêng trong LAN; không dùng "
            "địa chỉ mạng hoặc broadcast."
        )

    try:
        rate_pps = float(rate_pps)
    except (TypeError, ValueError) as exc:
        raise ValueError("Tốc độ phải là số gói/giây.") from exc
    if not math.isfinite(rate_pps):
        raise ValueError("Tốc độ phải là số hữu hạn.")
    if not LOAD_TEST_MIN_RATE_PPS <= rate_pps <= LOAD_TEST_MAX_RATE_PPS:
        raise ValueError(
            f"Tốc độ phải nằm trong khoảng {LOAD_TEST_MIN_RATE_PPS:g}-"
            f"{LOAD_TEST_MAX_RATE_PPS:g} gói/giây."
        )

    try:
        duration_s = float(duration_s)
    except (TypeError, ValueError) as exc:
        raise ValueError("Thời gian test phải là số giây.") from exc
    if not math.isfinite(duration_s):
        raise ValueError("Thời gian test phải là số hữu hạn.")
    if not LOAD_TEST_MIN_DURATION_S <= duration_s <= LOAD_TEST_MAX_DURATION_S:
        raise ValueError(
            f"Thời gian test phải nằm trong khoảng {LOAD_TEST_MIN_DURATION_S:g}-"
            f"{LOAD_TEST_MAX_DURATION_S:g} giây."
        )

    try:
        timeout_ms = int(timeout_ms)
    except (TypeError, ValueError) as exc:
        raise ValueError("Timeout phải là số nguyên (mili-giây).") from exc
    if not PING_MIN_TIMEOUT_MS <= timeout_ms <= PING_MAX_TIMEOUT_MS:
        raise ValueError(
            f"Timeout phải nằm trong khoảng {PING_MIN_TIMEOUT_MS}-"
            f"{PING_MAX_TIMEOUT_MS} ms."
        )

    protocol = normalize_ping_protocol(protocol)
    if protocol == PING_PROTOCOL_AUTO:
        raise ValueError("Test chịu tải cần chọn rõ ICMP, TCP hoặc UDP; không dùng Tự động.")
    udp_payload_size = _validate_udp_payload_size(udp_payload_size)

    try:
        max_in_flight = int(max_in_flight)
    except (TypeError, ValueError) as exc:
        raise ValueError("Số yêu cầu đồng thời phải là số nguyên.") from exc
    if not PING_MIN_IN_FLIGHT <= max_in_flight <= PING_MAX_IN_FLIGHT:
        raise ValueError(
            f"Số yêu cầu đồng thời phải nằm trong khoảng {PING_MIN_IN_FLIGHT}-"
            f"{PING_MAX_IN_FLIGHT}."
        )

    planned_count = math.ceil(rate_pps * duration_s)
    if planned_count > LOAD_TEST_MAX_PACKETS:
        raise ValueError(
            f"Tổng số gói dự kiến không được vượt quá {LOAD_TEST_MAX_PACKETS:,}."
        )

    return {
        "target": target,
        "rate_pps": rate_pps,
        "duration_s": duration_s,
        "timeout_ms": timeout_ms,
        "protocol": protocol,
        "udp_payload_size": udp_payload_size,
        "max_in_flight": max_in_flight,
        "planned_count": planned_count,
    }


def validate_ping_session_config(
    target: str,
    count: int,
    duration_s: Optional[float],
    interval_s: float,
    timeout_ms: int,
    mode: str = PING_MODE_SEQUENTIAL,
    max_in_flight: int = PING_DEFAULT_IN_FLIGHT,
    protocol: str = PING_PROTOCOL_AUTO,
    udp_payload_size: int = UDP_PAYLOAD_DEFAULT_BYTES,
) -> Dict[str, Any]:
    """Validate and normalize settings for a finite ping session."""
    target = str(target or "").strip()
    if not target:
        raise ValueError("Địa chỉ modem/máy chủ không được để trống.")
    if len(target) > 253:
        raise ValueError("Địa chỉ mục tiêu quá dài.")

    try:
        count = int(count)
    except (TypeError, ValueError) as exc:
        raise ValueError("Số lần ping phải là số nguyên.") from exc
    if not 1 <= count <= PING_MAX_COUNT:
        raise ValueError(f"Số lần ping phải nằm trong khoảng 1-{PING_MAX_COUNT}.")

    if duration_s is not None:
        try:
            duration_s = float(duration_s)
        except (TypeError, ValueError) as exc:
            raise ValueError("Thời gian tối đa phải là số.") from exc
        if not math.isfinite(duration_s):
            raise ValueError("Thời gian tối đa phải là số hữu hạn.")
        if duration_s < 0:
            raise ValueError("Thời gian tối đa không được âm.")
        if duration_s > PING_MAX_DURATION_S:
            raise ValueError("Thời gian tối đa không được vượt quá 24 giờ.")
        # 0 nghĩa là không giới hạn thời gian; phiên vẫn dừng khi đủ số lần.
        if duration_s == 0:
            duration_s = None

    try:
        interval_s = float(interval_s)
    except (TypeError, ValueError) as exc:
        raise ValueError("Khoảng cách ping phải là số.") from exc
    if not math.isfinite(interval_s):
        raise ValueError("Khoảng cách ping phải là số hữu hạn.")
    if not PING_MIN_INTERVAL_S <= interval_s <= PING_MAX_INTERVAL_S:
        raise ValueError(
            f"Khoảng cách ping phải nằm trong khoảng {PING_MIN_INTERVAL_S:g}-"
            f"{PING_MAX_INTERVAL_S:g} giây."
        )

    try:
        timeout_ms = int(timeout_ms)
    except (TypeError, ValueError) as exc:
        raise ValueError("Timeout phải là số nguyên (mili-giây).") from exc
    if not PING_MIN_TIMEOUT_MS <= timeout_ms <= PING_MAX_TIMEOUT_MS:
        raise ValueError(
            f"Timeout phải nằm trong khoảng {PING_MIN_TIMEOUT_MS}-"
            f"{PING_MAX_TIMEOUT_MS} ms."
        )

    mode = str(mode or PING_MODE_SEQUENTIAL).strip().lower()
    mode_aliases = {
        "sync": PING_MODE_SEQUENTIAL,
        "synchronous": PING_MODE_SEQUENTIAL,
        "tuần tự": PING_MODE_SEQUENTIAL,
        "tuần tự - đợi phản hồi": PING_MODE_SEQUENTIAL,
        "async": PING_MODE_ASYNC,
        "asynchronous": PING_MODE_ASYNC,
        "bất đồng bộ": PING_MODE_ASYNC,
        "bất đồng bộ - gửi tiếp": PING_MODE_ASYNC,
    }
    mode = mode_aliases.get(mode, mode)
    if mode not in PING_MODES:
        raise ValueError("Kiểu gửi phải là tuần tự hoặc bất đồng bộ.")

    try:
        max_in_flight = int(max_in_flight)
    except (TypeError, ValueError) as exc:
        raise ValueError("Số yêu cầu đồng thời phải là số nguyên.") from exc
    if not PING_MIN_IN_FLIGHT <= max_in_flight <= PING_MAX_IN_FLIGHT:
        raise ValueError(
            f"Số yêu cầu đồng thời phải nằm trong khoảng {PING_MIN_IN_FLIGHT}-"
            f"{PING_MAX_IN_FLIGHT}."
        )

    protocol = normalize_ping_protocol(protocol)
    udp_payload_size = _validate_udp_payload_size(udp_payload_size)

    return {
        "target": target,
        "count": count,
        "duration_s": duration_s,
        "interval_s": interval_s,
        "timeout_ms": timeout_ms,
        "mode": mode,
        "max_in_flight": max_in_flight,
        "protocol": protocol,
        "udp_payload_size": udp_payload_size,
    }


class PingSession:
    """Run a finite, cancellable sequence of sequential or asynchronous pings."""

    def __init__(
        self,
        target: str,
        count: int,
        duration_s: Optional[float] = 30.0,
        interval_s: float = 1.0,
        timeout_ms: int = 800,
        on_result: Optional[Callable[[Dict[str, Any]], None]] = None,
        on_complete: Optional[Callable[[Dict[str, Any]], None]] = None,
        mode: str = PING_MODE_SEQUENTIAL,
        max_in_flight: int = PING_DEFAULT_IN_FLIGHT,
        protocol: str = PING_PROTOCOL_AUTO,
        udp_payload_size: int = UDP_PAYLOAD_DEFAULT_BYTES,
    ):
        config = validate_ping_session_config(
            target,
            count,
            duration_s,
            interval_s,
            timeout_ms,
            mode,
            max_in_flight,
            protocol,
            udp_payload_size,
        )
        self.target = config["target"]
        self.requested_count = config["count"]
        self.duration_s = config["duration_s"]
        self.interval_s = config["interval_s"]
        self.timeout_ms = config["timeout_ms"]
        self.mode = config["mode"]
        self.max_in_flight = config["max_in_flight"]
        self.protocol = config["protocol"]
        self.udp_payload_size = config["udp_payload_size"]
        self.on_result = on_result
        self.on_complete = on_complete

        self.is_running = False
        self.results: List[Dict[str, Any]] = []
        self.completed_reason: Optional[str] = None
        self.started_at: Optional[float] = None
        self.finished_at: Optional[float] = None
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    @property
    def completed_count(self) -> int:
        """Number of probe responses collected so far."""
        return len(self.results)

    def start(self) -> bool:
        """Start the session; return False if it is already running."""
        if self.is_running:
            return False
        self._stop_event.clear()
        self.results = []
        self.completed_reason = None
        self.started_at = time.monotonic()
        self.finished_at = None
        self.is_running = True
        self._thread = threading.Thread(
            target=self._run,
            name="custom-ping-session",
            daemon=True,
        )
        self._thread.start()
        return True

    def stop(self) -> None:
        """Stop scheduling new probes and collect already-started probes."""
        self._stop_event.set()

    def wait(self, timeout: Optional[float] = None) -> None:
        """Wait for the worker to finish (useful for callers and tests)."""
        thread = self._thread
        if thread and thread is not threading.current_thread():
            thread.join(timeout)

    def _emit_result(self, result: Dict[str, Any]) -> None:
        if not self.on_result:
            return
        try:
            self.on_result(result)
        except Exception:
            # A UI callback must not terminate the network worker.
            pass

    def _record_result(self, result: Dict[str, Any]) -> None:
        self.results.append(result)
        result["completed_count"] = len(self.results)
        self._emit_result(result)

    def _probe_one(self, index: int, scheduled_at: float) -> Dict[str, Any]:
        """Execute one probe; this method is also safe to run in a pool."""
        started_at = time.monotonic()
        error = None
        try:
            if self.udp_payload_size == UDP_PAYLOAD_DEFAULT_BYTES:
                if self.protocol == PING_PROTOCOL_AUTO:
                    latency_ms, method = smart_ping(
                        self.target,
                        timeout_ms=self.timeout_ms,
                    )
                else:
                    latency_ms, method = smart_ping(
                        self.target,
                        timeout_ms=self.timeout_ms,
                        protocol=self.protocol,
                    )
            else:
                latency_ms, method = smart_ping(
                    self.target,
                    timeout_ms=self.timeout_ms,
                    protocol=self.protocol,
                    udp_payload_size=self.udp_payload_size,
                )
        except Exception as exc:
            latency_ms, method = None, "Error"
            error = str(exc)

        result: Dict[str, Any] = {
            "index": index,
            "timestamp": time.time(),
            "scheduled_at": scheduled_at,
            "probe_elapsed_ms": round((time.monotonic() - started_at) * 1000, 1),
            "latency_ms": latency_ms,
            "method": method,
            "ok": latency_ms is not None,
        }
        if error:
            result["error"] = error
        return result

    def _build_summary(self, reason: str, error: Optional[str] = None) -> Dict[str, Any]:
        valid = [
            item["latency_ms"]
            for item in self.results
            if item["latency_ms"] is not None
        ]
        total = len(self.results)
        lost = total - len(valid)
        elapsed = 0.0
        if self.started_at is not None:
            end = self.finished_at or time.monotonic()
            elapsed = max(0.0, end - self.started_at)

        summary: Dict[str, Any] = {
            "target": self.target,
            "requested_count": self.requested_count,
            "completed_count": total,
            "success_count": len(valid),
            "lost_count": lost,
            "loss_rate": round((lost / total) * 100, 1) if total else 0.0,
            "min_ms": min(valid) if valid else None,
            "max_ms": max(valid) if valid else None,
            "avg_ms": round(sum(valid) / len(valid), 1) if valid else None,
            "elapsed_s": round(elapsed, 2),
            "stop_reason": reason,
            "mode": self.mode,
            "max_in_flight": self.max_in_flight,
            "protocol": self.protocol,
            "udp_payload_size": self.udp_payload_size,
        }
        if error:
            summary["error"] = error
        return summary

    def _duration_expired(self) -> bool:
        return bool(
            self.duration_s is not None
            and self.started_at is not None
            and time.monotonic() - self.started_at >= self.duration_s
        )

    def _run_sequential(self) -> str:
        for index in range(1, self.requested_count + 1):
            if self._stop_event.is_set():
                return "cancelled"
            if self._duration_expired():
                return "duration"

            self._record_result(self._probe_one(index, time.monotonic()))

            if index >= self.requested_count:
                return "count"
            if self._stop_event.is_set():
                return "cancelled"

            wait_s = self.interval_s
            if self.duration_s is not None and self.started_at is not None:
                remaining = self.duration_s - (time.monotonic() - self.started_at)
                if remaining <= 0:
                    return "duration"
                wait_s = min(wait_s, remaining)
            if self._stop_event.wait(wait_s):
                return "cancelled"
        return "count"

    def _run_async(self) -> str:
        """Schedule probes at the requested interval with bounded concurrency."""
        executor = ThreadPoolExecutor(
            max_workers=self.max_in_flight,
            thread_name_prefix="custom-ping-probe",
        )
        pending: Dict[Any, int] = {}
        next_index = 1
        next_send_at = time.monotonic()
        reason: Optional[str] = None
        try:
            while True:
                now = time.monotonic()
                if reason is None:
                    if self._stop_event.is_set():
                        reason = "cancelled"
                    elif self._duration_expired():
                        reason = "duration"

                if reason is None:
                    while next_index <= self.requested_count and len(pending) < self.max_in_flight:
                        now = time.monotonic()
                        if self._stop_event.is_set():
                            reason = "cancelled"
                            break
                        if self._duration_expired():
                            reason = "duration"
                            break
                        if now < next_send_at:
                            break

                        index = next_index
                        pending[executor.submit(self._probe_one, index, now)] = index
                        next_index += 1
                        # Use a minimum gap between submissions; never burst to catch up.
                        next_send_at = now + self.interval_s

                if not pending:
                    if reason is not None:
                        return reason
                    if next_index > self.requested_count:
                        return "count"
                    wait_s = max(0.0, next_send_at - time.monotonic())
                    if self._stop_event.wait(min(wait_s, 0.1)):
                        reason = "cancelled"
                    continue

                done, _ = wait(list(pending), timeout=0, return_when=FIRST_COMPLETED)
                if not done:
                    wait_s = 0.1
                    if (
                        reason is None
                        and next_index <= self.requested_count
                        and len(pending) < self.max_in_flight
                    ):
                        wait_s = min(wait_s, max(0.0, next_send_at - time.monotonic()))
                    done, _ = wait(list(pending), timeout=wait_s, return_when=FIRST_COMPLETED)

                for future in done:
                    index = pending.pop(future)
                    try:
                        result = future.result()
                    except Exception as exc:
                        result = {
                            "index": index,
                            "timestamp": time.time(),
                            "latency_ms": None,
                            "method": "Error",
                            "ok": False,
                            "error": str(exc),
                        }
                    self._record_result(result)

                if reason is None and next_index > self.requested_count and not pending:
                    return "count"
        finally:
            # Normally all futures are drained above. This also keeps shutdown safe
            # if the scheduler itself encounters an unexpected exception.
            for future in pending:
                future.cancel()
            executor.shutdown(wait=True, cancel_futures=True)

    def _run(self) -> None:
        reason = "count"
        error_message: Optional[str] = None
        try:
            if self.mode == PING_MODE_ASYNC:
                reason = self._run_async()
            else:
                reason = self._run_sequential()
        except Exception as exc:
            reason = "error"
            error_message = str(exc)
        finally:
            self.finished_at = time.monotonic()
            self.is_running = False
            self.completed_reason = reason
            summary = self._build_summary(reason, error_message)
            if self.on_complete:
                try:
                    self.on_complete(summary)
                except Exception:
                    pass


class LoadTestSession:
    """Run a bounded, response-aware load test against a private IPv4 host."""

    def __init__(
        self,
        target: str,
        rate_pps: float = LOAD_TEST_DEFAULT_RATE_PPS,
        duration_s: float = LOAD_TEST_DEFAULT_DURATION_S,
        timeout_ms: int = 800,
        protocol: str = PING_PROTOCOL_UDP,
        udp_payload_size: int = UDP_PAYLOAD_DEFAULT_BYTES,
        max_in_flight: int = PING_DEFAULT_IN_FLIGHT,
        on_result: Optional[Callable[[Dict[str, Any]], None]] = None,
        on_complete: Optional[Callable[[Dict[str, Any]], None]] = None,
    ):
        config = validate_load_test_config(
            target,
            rate_pps,
            duration_s,
            timeout_ms,
            protocol,
            udp_payload_size,
            max_in_flight,
        )
        self.target = config["target"]
        self.rate_pps = config["rate_pps"]
        self.duration_s = config["duration_s"]
        self.timeout_ms = config["timeout_ms"]
        self.protocol = config["protocol"]
        self.udp_payload_size = config["udp_payload_size"]
        self.max_in_flight = config["max_in_flight"]
        self.planned_count = config["planned_count"]
        self.on_result = on_result
        self.on_complete = on_complete

        self.is_running = False
        self.results: List[Dict[str, Any]] = []
        self.sent_count = 0
        self.started_at: Optional[float] = None
        self.finished_at: Optional[float] = None
        self.completed_reason: Optional[str] = None
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    @property
    def completed_count(self) -> int:
        return len(self.results)

    def start(self) -> bool:
        """Start the load test; return False if it is already running."""
        if self.is_running:
            return False
        self._stop_event.clear()
        self.results = []
        self.sent_count = 0
        self.completed_reason = None
        self.started_at = time.monotonic()
        self.finished_at = None
        self.is_running = True
        self._thread = threading.Thread(
            target=self._run,
            name="lan-load-test",
            daemon=True,
        )
        self._thread.start()
        return True

    def stop(self) -> None:
        """Stop scheduling new packets and drain already-started probes."""
        self._stop_event.set()

    def wait(self, timeout: Optional[float] = None) -> None:
        thread = self._thread
        if thread and thread is not threading.current_thread():
            thread.join(timeout)

    def _emit_result(self, result: Dict[str, Any]) -> None:
        if not self.on_result:
            return
        try:
            self.on_result(result)
        except Exception:
            pass

    def _record_result(self, result: Dict[str, Any]) -> None:
        self.results.append(result)
        result["completed_count"] = len(self.results)
        result["sent_count"] = self.sent_count
        self._emit_result(result)

    def _probe_one(self, index: int, scheduled_at: float) -> Dict[str, Any]:
        started_at = time.monotonic()
        error = None
        method = self.protocol.upper()
        try:
            if self.protocol == PING_PROTOCOL_ICMP:
                latency_ms = native_ping(self.target, timeout_ms=self.timeout_ms)
                method = "ICMP"
            elif self.protocol == PING_PROTOCOL_TCP:
                latency_ms = tcp_ping(self.target, port=53, timeout_ms=self.timeout_ms)
                method = "TCP:53"
            else:
                latency_ms = udp_ping(
                    self.target,
                    port=53,
                    timeout_ms=self.timeout_ms,
                    payload_size=self.udp_payload_size,
                )
                method = "UDP:53"
        except Exception as exc:
            latency_ms = None
            method = "Error"
            error = str(exc)

        result: Dict[str, Any] = {
            "index": index,
            "timestamp": time.time(),
            "scheduled_at": scheduled_at,
            "probe_elapsed_ms": round((time.monotonic() - started_at) * 1000, 1),
            "latency_ms": latency_ms,
            "method": method,
            "ok": latency_ms is not None,
        }
        if error:
            result["error"] = error
        return result

    def _build_summary(self, reason: str, error: Optional[str] = None) -> Dict[str, Any]:
        valid = [
            item["latency_ms"]
            for item in self.results
            if item["latency_ms"] is not None
        ]
        total = len(self.results)
        lost = total - len(valid)
        elapsed = 0.0
        if self.started_at is not None:
            end = self.finished_at or time.monotonic()
            elapsed = max(0.0, end - self.started_at)

        summary: Dict[str, Any] = {
            "target": self.target,
            "rate_pps": self.rate_pps,
            "duration_s": self.duration_s,
            "planned_count": self.planned_count,
            "sent_count": self.sent_count,
            "completed_count": total,
            "success_count": len(valid),
            "lost_count": lost,
            "loss_rate": round((lost / total) * 100, 1) if total else 0.0,
            "min_ms": min(valid) if valid else None,
            "max_ms": max(valid) if valid else None,
            "avg_ms": round(sum(valid) / len(valid), 1) if valid else None,
            "elapsed_s": round(elapsed, 2),
            "actual_rate_pps": round(self.sent_count / elapsed, 2) if elapsed else 0.0,
            "stop_reason": reason,
            "protocol": self.protocol,
            "udp_payload_size": self.udp_payload_size,
            "max_in_flight": self.max_in_flight,
        }
        if error:
            summary["error"] = error
        return summary

    def _run(self) -> None:
        executor = ThreadPoolExecutor(
            max_workers=self.max_in_flight,
            thread_name_prefix="lan-load-probe",
        )
        pending: Dict[Any, int] = {}
        next_index = 1
        interval_s = 1.0 / self.rate_pps
        next_send_at = time.monotonic()
        end_at = (self.started_at or time.monotonic()) + self.duration_s
        reason: Optional[str] = None
        error_message: Optional[str] = None
        try:
            while True:
                now = time.monotonic()
                if reason is None:
                    if self._stop_event.is_set():
                        reason = "cancelled"
                    elif now >= end_at:
                        reason = "duration"

                if reason is None:
                    while (
                        next_index <= self.planned_count
                        and len(pending) < self.max_in_flight
                    ):
                        now = time.monotonic()
                        if self._stop_event.is_set():
                            reason = "cancelled"
                            break
                        if now >= end_at:
                            reason = "duration"
                            break
                        if now < next_send_at:
                            break

                        index = next_index
                        pending[executor.submit(self._probe_one, index, now)] = index
                        self.sent_count += 1
                        next_index += 1
                        # Never burst to catch up after a slow callback or probe.
                        next_send_at = max(next_send_at + interval_s, now + interval_s)

                if not pending:
                    if reason is not None:
                        return self._finish(reason, error_message)
                    if next_index > self.planned_count:
                        # Keep the requested test window intact after the last
                        # scheduled packet, so the reported rate uses duration.
                        wait_s = min(0.1, max(0.0, end_at - time.monotonic()))
                        if wait_s <= 0:
                            return self._finish("duration", error_message)
                        if self._stop_event.wait(wait_s):
                            reason = "cancelled"
                        continue
                    wait_s = min(
                        0.1,
                        max(0.0, next_send_at - time.monotonic()),
                        max(0.0, end_at - time.monotonic()),
                    )
                    if self._stop_event.wait(wait_s) and reason is None:
                        reason = "cancelled"
                    continue

                done, _ = wait(list(pending), timeout=0, return_when=FIRST_COMPLETED)
                if not done:
                    wait_s = min(0.1, max(0.0, end_at - time.monotonic()))
                    if (
                        reason is None
                        and next_index <= self.planned_count
                        and len(pending) < self.max_in_flight
                    ):
                        wait_s = min(wait_s, max(0.0, next_send_at - time.monotonic()))
                    done, _ = wait(list(pending), timeout=wait_s, return_when=FIRST_COMPLETED)

                for future in done:
                    index = pending.pop(future)
                    try:
                        result = future.result()
                    except Exception as exc:
                        result = {
                            "index": index,
                            "timestamp": time.time(),
                            "latency_ms": None,
                            "method": "Error",
                            "ok": False,
                            "error": str(exc),
                        }
                    self._record_result(result)

        except Exception as exc:
            reason = "error"
            error_message = str(exc)
            return self._finish(reason, error_message)
        finally:
            for future in pending:
                future.cancel()
            executor.shutdown(wait=True, cancel_futures=True)

    def _finish(self, reason: str, error: Optional[str]) -> Dict[str, Any]:
        self.finished_at = time.monotonic()
        self.is_running = False
        self.completed_reason = reason
        summary = self._build_summary(reason, error)
        if self.on_complete:
            try:
                self.on_complete(summary)
            except Exception:
                pass
        return summary


class PingMonitor:
    """Bộ điều khiển giám sát độ trễ kép (Router và Internet) với bộ đệm lịch sử."""

    MAX_POINTS = 50  # Số điểm vẽ biểu đồ sóng

    def __init__(self, router_ip: str = "192.168.1.1", internet_ip: str = "8.8.8.8"):
        self.router_ip = router_ip
        self.internet_ip = internet_ip
        self.is_running = False
        self.is_paused = False
        self.worker_thread: Optional[threading.Thread] = None

        # Bộ đệm lưu trữ lịch sử các giá trị ping gần nhất (ms)
        self.history_router: deque = deque(maxlen=self.MAX_POINTS)
        self.history_internet: deque = deque(maxlen=self.MAX_POINTS)

        # Bộ đệm tính toán thống kê (100 mẫu gần nhất)
        self.stat_samples_router: deque = deque(maxlen=100)
        self.stat_samples_internet: deque = deque(maxlen=100)

        # Callbacks cập nhật UI
        self.on_update_callback = None

    def start(self, on_update=None):
        """Khởi động luồng đo ping định kỳ."""
        if self.is_running:
            return
        self.is_running = True
        self.is_paused = False
        self.on_update_callback = on_update
        self.worker_thread = threading.Thread(target=self._run_loop, daemon=True)
        self.worker_thread.start()

    def pause(self):
        """Tạm dừng đo."""
        self.is_paused = True

    def resume(self):
        """Tiếp tục đo."""
        self.is_paused = False

    def stop(self):
        """Dừng hẳn tiến trình đo."""
        self.is_running = False

    def reset_data(self):
        """Xóa trắng dữ liệu lịch sử để đo lại từ đầu."""
        self.history_router.clear()
        self.history_internet.clear()
        self.stat_samples_router.clear()
        self.stat_samples_internet.clear()

    def set_targets(self, router_ip: Optional[str] = None, internet_ip: Optional[str] = None):
        """Cập nhật địa chỉ IP mục tiêu."""
        if router_ip:
            self.router_ip = router_ip
        if internet_ip:
            self.internet_ip = internet_ip

    def _run_loop(self):
        while self.is_running:
            if not self.is_paused:
                t_router, r_meth = smart_ping(self.router_ip, timeout_ms=800)
                t_inet, i_meth = smart_ping(self.internet_ip, timeout_ms=800)
                self.last_router_method = r_meth
                self.last_internet_method = i_meth

                self.history_router.append(t_router)
                self.history_internet.append(t_inet)

                self.stat_samples_router.append(t_router)
                self.stat_samples_internet.append(t_inet)

                stats = self.get_current_stats()
                diagnosis = self.diagnose(stats)

                if self.on_update_callback:
                    try:
                        self.on_update_callback(stats, diagnosis)
                    except Exception:
                        pass

            time.sleep(1.0)

    def get_current_stats(self) -> Dict[str, Any]:
        """Tính toán các chỉ số thống kê mạng."""
        def compute(samples_deque, method_name: str = "ICMP"):
            if not samples_deque:
                return {"cur": 0, "min": 0, "max": 0, "avg": 0, "loss_rate": 0, "jitter": 0, "method": method_name}

            valid = [s for s in samples_deque if s is not None]
            total = len(samples_deque)
            lost = total - len(valid)
            loss_rate = round((lost / total) * 100, 1)

            if not valid:
                return {"cur": None, "min": 0, "max": 0, "avg": 0, "loss_rate": loss_rate, "jitter": 0, "method": method_name}

            cur = samples_deque[-1]
            min_val = min(valid)
            max_val = max(valid)
            avg_val = round(sum(valid) / len(valid), 1)

            # Tính Jitter (độ lệch biến thiên trung bình giữa các lần ping liên tiếp)
            jitter = 0
            if len(valid) > 1:
                diffs = [abs(valid[i] - valid[i - 1]) for i in range(1, len(valid))]
                jitter = round(sum(diffs) / len(diffs), 1)

            return {
                "cur": cur,
                "min": min_val,
                "max": max_val,
                "avg": avg_val,
                "loss_rate": loss_rate,
                "jitter": jitter,
                "method": method_name,
            }

        r_meth = getattr(self, "last_router_method", "ICMP")
        i_meth = getattr(self, "last_internet_method", "ICMP")

        return {
            "router_ip": self.router_ip,
            "internet_ip": self.internet_ip,
            "router": compute(self.stat_samples_router, r_meth),
            "internet": compute(self.stat_samples_internet, i_meth),
            "history_router": list(self.history_router),
            "history_internet": list(self.history_internet),
        }

    def diagnose(self, stats: Dict[str, Any]) -> Dict[str, Any]:
        """
        Thuật toán chẩn đoán thông minh:
        Phân biệt mạng chậm do sóng Wi-Fi hay do nhà mạng cáp quang.
        """
        r_stats = stats["router"]
        i_stats = stats["internet"]

        r_cur = r_stats["cur"]
        i_cur = i_stats["cur"]
        r_loss = r_stats["loss_rate"]
        i_loss = i_stats["loss_rate"]

        # Trường hợp 1: Mất mạng hoàn toàn
        if r_cur is None and i_cur is None:
            return {
                "level": "danger",
                "title": "MẤT KẾT NỐI MẠNG HOÀN TOÀN",
                "badge": "⚫ Mất Mạng",
                "color": "#EF4444",
                "desc": "Không thể kết nối tới cả Router Wi-Fi lẫn Internet. Vui lòng kiểm tra lại cáp mạng hoặc kết nối Wi-Fi trên máy tính của bạn.",
            }

        # Trường hợp 2: Wi-Fi yếu / Nhiễu sóng / Quá tải
        if r_loss > 10 or (r_cur is not None and r_cur > 45):
            return {
                "level": "warning",
                "title": "NGUYÊN NHÂN: SÓNG WI-FI YẾU HOẶC NHIỄU SÓNG",
                "badge": "🟡 Sóng Wi-Fi Kém",
                "color": "#F59E0B",
                "desc": f"Độ trễ tới Router nội bộ quá cao ({r_cur or 'Timeout'} ms, rớt {r_loss}% gói). Do máy ở xa cục phát, có vật cản tường dày hoặc cục Wi-Fi đang quá tải.",
            }

        # Trường hợp 3: Kết nối Wi-Fi tốt nhưng cáp quang nhà mạng có vấn đề
        if (r_cur is not None and r_cur <= 10) and (i_cur is None or i_loss > 15 or i_cur > 120):
            return {
                "level": "warning_isp",
                "title": "NGUYÊN NHÂN: ĐƯỜNG TRUYỀN NHÀ MẠNG CÁP QUANG BỊ NGHẼN",
                "badge": "🔴 Sự Cố Nhà Mạng",
                "color": "#EC4899",
                "desc": f"Sóng Wi-Fi tới Router rất tốt ({r_cur} ms) nhưng ping Internet bị lag ({i_cur or 'Timeout'} ms, rớt {i_loss}% gói). Sự cố do nhà cung cấp mạng (Viettel/FPT/VNPT) hoặc nghẽn cáp biển.",
            }

        # Trường hợp 4: Mạng hoạt động tuyệt vời
        if (r_cur is not None and r_cur <= 12) and (i_cur is not None and i_cur <= 90 and i_loss == 0):
            return {
                "level": "success",
                "title": "MẠNG HOẠT ĐỘNG HOÀN HẢO",
                "badge": "🟢 Cực Kỳ Ổn Định",
                "color": "#10B981",
                "desc": f"Sóng Wi-Fi mạnh ({r_cur} ms) và đường truyền Internet thông suốt ({i_cur} ms, 0% rớt gói). Đạt chuẩn xem video 4K và chơi game mượt mà.",
            }

        # Trường hợp 5: Mạng bình thường
        return {
            "level": "normal",
            "title": "KẾT NỐI MẠNG ỔN ĐỊNH",
            "badge": "🔵 Bình Thường",
            "color": "#3B82F6",
            "desc": f"Độ trễ Router: {r_cur} ms | Internet: {i_cur} ms. Mạng đáp ứng tốt các nhu cầu học tập, làm việc và giải trí hàng ngày.",
        }
