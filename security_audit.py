"""
security_audit.py - Đánh giá an ninh mạng Wi-Fi và Router toàn diện.
Bao gồm:
1. Kiểm tra chuẩn mã hóa Wi-Fi (WPA3, WPA2-AES, TKIP, WEP, Open).
2. Quét các cổng dịch vụ nhạy cảm trên Router (Telnet 23, FTP 21, UPnP 1900/5000, TR-069 7547, HTTP 80, HTTPS 443, SSH 22, DNS 53).
3. Kiểm tra tính toàn vẹn và nguy cơ giả mạo máy chủ DNS (DNS Hijacking).
4. Tính điểm an ninh mạng (/100) và danh sách khuyến nghị tăng cường bảo mật (Hardening Guide).
"""

import subprocess
import socket
import re
import time
import json
import os
import ipaddress
import ssl
import struct
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, List, Optional, Tuple

# Danh mục các cổng nhạy cảm trên Router cần kiểm tra
SENSITIVE_ROUTER_PORTS = [
    {
        "port": 23,
        "name": "Telnet",
        "risk": "critical",
        "risk_desc": "Giao thức dòng lệnh văn bản thô, không mã hóa. Cực kỳ nguy hiểm nếu mở, dễ bị hack mật khẩu hoặc lây nhiễm IoT botnet (Mirai).",
        "recommendation": "Tắt tính năng Telnet ngay trong trang quản trị Modem.",
    },
    {
        "port": 21,
        "name": "FTP",
        "risk": "high",
        "risk_desc": "Truyền file văn bản thô không mã hóa. Thường dùng để chia sẻ file USB cắm modem nhưng tiềm ẩn nguy cơ lộ tài khoản.",
        "recommendation": "Tắt dịch vụ chia sẻ file FTP trên Modem nếu không dùng.",
    },
    {
        "port": 1900,
        "name": "UPnP (SSDP)",
        "risk": "medium",
        "risk_desc": "Universal Plug and Play. Cho phép các ứng dụng/mã độc trong mạng LAN tự ý đục lỗ mở cổng ra ngoài Internet mà không cần sự đồng ý của chủ nhà.",
        "recommendation": "Khuyến nghị TẮT tính năng UPnP trong modem để kiểm soát hoàn toàn các cổng kết nối.",
    },
    {
        "port": 5000,
        "name": "UPnP Event / Web",
        "risk": "medium",
        "risk_desc": "Cổng sự kiện UPnP hoặc giao diện dịch vụ nội bộ.",
        "recommendation": "Kiểm tra và vô hiệu hóa UPnP nếu không thật sự cần thiết.",
    },
    {
        "port": 7547,
        "name": "TR-069 / CWMP",
        "risk": "high",
        "risk_desc": "Cổng quản trị từ xa của nhà mạng viễn thông. Từng có nhiều lỗ hổng lớn bị khai thác nếu modem không cập nhật firmware.",
        "recommendation": "Đảm bảo firmware modem được cập nhật bản mới nhất từ nhà mạng.",
    },
    {
        "port": 80,
        "name": "HTTP Web Admin",
        "risk": "low",
        "risk_desc": "Trang đăng nhập quản trị modem qua HTTP không mã hóa.",
        "recommendation": "Nên sử dụng HTTPS (cổng 443) khi đăng nhập modem và đổi mật khẩu mặc định.",
    },
    {
        "port": 443,
        "name": "HTTPS Web Admin",
        "risk": "safe",
        "risk_desc": "Trang quản trị bảo mật có mã hóa SSL/TLS.",
        "recommendation": "Rất tốt. Luôn ưu tiên dùng kết nối HTTPS để bảo vệ mật khẩu quản trị.",
    },
    {
        "port": 22,
        "name": "SSH",
        "risk": "medium",
        "risk_desc": "Quản trị dòng lệnh có mã hóa. An toàn hơn Telnet nhưng không cần thiết phải mở cho gia đình.",
        "recommendation": "Nên tắt SSH nếu chỉ dùng mạng gia đình cơ bản.",
    },
    {
        "port": 53,
        "name": "DNS Relay",
        "risk": "safe",
        "risk_desc": "Dịch vụ chuyển tiếp truy vấn phân giải tên miền nội bộ của Router.",
        "recommendation": "Dịch vụ tiêu chuẩn hoạt động bình thường.",
    },
    {
        "port": 8080,
        "name": "HTTP Alt / Proxy",
        "risk": "medium",
        "risk_desc": "Giao diện web quản trị phụ hoặc cổng proxy.",
        "recommendation": "Kiểm tra xem modem có đang bật chức năng Remote Management qua cổng này không.",
    },
]

# Danh mục các nhà cung cấp DNS an toàn phổ biến
KNOWN_SAFE_DNS = {
    "1.1.1.1": "Cloudflare DNS (Bảo mật cao, tốc độ nhanh nhất thế giới)",
    "1.0.0.1": "Cloudflare DNS Backup",
    "8.8.8.8": "Google Public DNS (Rất ổn định, bảo mật cao)",
    "8.8.4.4": "Google DNS Backup",
    "9.9.9.9": "Quad9 DNS (Tự động chặn mã độc & web lừa đảo)",
    "149.112.112.112": "Quad9 DNS Backup",
    "208.67.222.222": "Cisco OpenDNS (Có lọc web độc hại)",
    "208.67.220.220": "Cisco OpenDNS Backup",
}


def get_wifi_security_info() -> Dict[str, Any]:
    """
    Lấy thông tin bảo mật sóng Wi-Fi từ lệnh hệ thống netsh wlan show interfaces.
    """
    result = {
        "is_connected": False,
        "ssid": "Chưa kết nối Wi-Fi",
        "auth": "Không xác định",
        "cipher": "Không xác định",
        "radio": "Không xác định",
        "band": "Không xác định",
        "channel": 0,
        "signal": 0,
        "bssid": "",
        "security_level": "unknown",  # excellent, good, fair, dangerous
        "security_note": "",
    }

    try:
        cmd = ["netsh", "wlan", "show", "interfaces"]
        raw = subprocess.check_output(cmd, text=True, errors="ignore", creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0)

        for line in raw.splitlines():
            line = line.strip()
            if ":" not in line:
                continue
            key, val = line.split(":", 1)
            key = key.strip().lower()
            val = val.strip()

            if key == "state" and val.lower() == "connected":
                result["is_connected"] = True
            elif key == "ssid":
                result["ssid"] = val
            elif key == "ap bssid":
                result["bssid"] = val
            elif key == "band":
                result["band"] = val
            elif key == "channel":
                try:
                    result["channel"] = int(val)
                except ValueError:
                    pass
            elif key == "radio type":
                result["radio"] = val
            elif key == "authentication":
                result["auth"] = val
            elif key == "cipher":
                result["cipher"] = val
            elif key == "signal":
                try:
                    result["signal"] = int(val.replace("%", "").strip())
                except ValueError:
                    pass

        # Đánh giá mức độ bảo mật của chuẩn Wi-Fi
        auth_upper = result["auth"].upper()
        cipher_upper = result["cipher"].upper()

        if "WPA3" in auth_upper:
            result["security_level"] = "excellent"
            result["security_note"] = "Chuẩn bảo mật WPA3 cao nhất hiện nay. Chống bẻ khóa từ điển ngoại tuyến (SAE), mã hóa dữ liệu độc lập cực kỳ an toàn."
        elif "WPA2" in auth_upper:
            if "CCMP" in cipher_upper or "AES" in cipher_upper:
                result["security_level"] = "good"
                result["security_note"] = "Chuẩn bảo mật WPA2-Personal (AES/CCMP) an toàn tiêu chuẩn quốc tế, bảo vệ tốt trước hầu hết các cuộc tấn công thông thường."
            elif "TKIP" in cipher_upper:
                result["security_level"] = "fair"
                result["security_note"] = "WPA2 sử dụng thuật toán TKIP cũ. Dễ bị tấn công giải mã gói tin. Khuyến nghị cấu hình Modem chuyển sang WPA2-AES hoặc WPA3."
            else:
                result["security_level"] = "good"
                result["security_note"] = "Chuẩn bảo mật WPA2-Personal tiêu chuẩn."
        elif "WPA" in auth_upper:
            result["security_level"] = "fair"
            result["security_note"] = "Chuẩn WPA thế hệ cũ có lỗ hổng bảo mật. Cần nâng cấp ngay lên WPA2-AES hoặc WPA3 trong cài đặt modem."
        elif "WEP" in auth_upper or "OPEN" in auth_upper:
            result["security_level"] = "dangerous"
            result["security_note"] = "CỰC KỲ NGUY HIỂM! Mạng không có mật khẩu hoặc dùng chuẩn WEP đã lỗi thời 20 năm, có thể bị nghe lén toàn bộ dữ liệu."
        else:
            result["security_level"] = "good"
            result["security_note"] = "Đang kết nối qua chuẩn mã hóa của hệ thống."

    except Exception as e:
        result["security_note"] = f"Không thể lấy thông tin Wi-Fi: {e}"

    return result


def _check_single_router_port(router_ip: str, port_meta: dict) -> dict:
    """Kiểm tra 1 cổng dịch vụ trên router."""
    port = port_meta["port"]
    is_open = False
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.35)
    try:
        res = s.connect_ex((router_ip, port))
        if res == 0:
            is_open = True
    except Exception:
        pass
    finally:
        try:
            s.close()
        except Exception:
            pass

    return {
        "port": port,
        "name": port_meta["name"],
        "is_open": is_open,
        "risk": port_meta["risk"],
        "risk_desc": port_meta["risk_desc"],
        "recommendation": port_meta["recommendation"],
    }


def audit_router_ports(router_ip: str, on_progress=None) -> List[dict]:
    """
    Quét đa luồng các cổng nhạy cảm trên router với timeout cực nhanh.
    """
    results = []
    total = len(SENSITIVE_ROUTER_PORTS)
    completed = 0

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(_check_single_router_port, router_ip, p) for p in SENSITIVE_ROUTER_PORTS]
        for f in futures:
            res = f.result()
            results.append(res)
            completed += 1
            if on_progress:
                on_progress(completed, total)

    # Giữ nguyên thứ tự danh sách cổng
    results.sort(key=lambda x: x["port"])
    return results


def audit_dns_security() -> Dict[str, Any]:
    """
    Kiểm tra máy chủ DNS của hệ thống và kiểm tra chống giả mạo DNS Hijacking.
    """
    dns_servers = []
    dns_servers_v6 = []
    evidence = []
    dns_source = "unavailable"

    def add_dns_server(value: Any) -> None:
        raw_value = str(value or "").strip()
        if not raw_value:
            return
        # Windows can return a scoped IPv6 literal.  The scope is not needed
        # for reporting, while ipaddress validates the address portion.
        address_part = raw_value.split("%", 1)[0]
        try:
            parsed = ipaddress.ip_address(address_part)
        except ValueError:
            return
        target = dns_servers_v6 if parsed.version == 6 else dns_servers
        normalized = str(parsed)
        if normalized not in target:
            target.append(normalized)

    try:
        # PowerShell property names are stable across Windows display languages.
        if os.name == "nt":
            raw = subprocess.check_output(
                [
                    "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
                    "-Command",
                    "Get-DnsClientServerAddress | Select-Object -ExpandProperty ServerAddresses | ConvertTo-Json -Compress",
                ],
                text=True,
                errors="replace",
                timeout=3,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                stderr=subprocess.DEVNULL,
            )
            values = json.loads(raw) if raw.strip() else []
            values = values if isinstance(values, list) else [values]
            for value in values:
                add_dns_server(value)
            if dns_servers or dns_servers_v6:
                dns_source = "powershell"
        else:
            raise OSError("PowerShell unavailable")
    except Exception:
        try:
            out = subprocess.check_output(
                ["ipconfig", "/all"],
                text=True,
                errors="ignore",
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            # Chỉ lấy các literal trên dòng có ngữ cảnh DNS; không quét toàn
            # bộ ipconfig để tránh nhầm IP adapter/gateway thành DNS.
            dns_context = False
            for line in out.splitlines():
                if re.search(r"\bDNS\b|name server|сервер|dns", line, re.IGNORECASE):
                    dns_context = True
                elif not line.strip():
                    dns_context = False
                if not dns_context:
                    continue
                for value in re.findall(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", line):
                    add_dns_server(value)
                for value in re.findall(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])", line):
                    add_dns_server(value)
            if dns_servers or dns_servers_v6:
                dns_source = "ipconfig"
        except Exception:
            pass

    primary_dns = dns_servers[0] if dns_servers else (dns_servers_v6[0] if dns_servers_v6 else "")
    provider_name = KNOWN_SAFE_DNS.get(primary_dns, "")
    is_router_relay = False
    if primary_dns:
        try:
            primary_address = ipaddress.ip_address(primary_dns)
            if primary_address.is_private or primary_address.is_link_local:
                is_router_relay = True
                provider_name = f"Resolver nội bộ / router ({primary_dns})"
        except ValueError:
            pass
    else:
        provider_name = "Chưa lấy được DNS"
        evidence.append("Không lấy được danh sách DNS từ Windows; không tự suy đoán gateway là DNS.")

    # Kiểm tra phân giải tên miền Canary (Chống DNS Hijacking)
    canary_test_ok = False
    canary_latency_ms = 0
    resolved_ips = []
    try:
        t0 = time.perf_counter()
        answers = socket.getaddrinfo("google.com", None, type=socket.SOCK_STREAM)
        resolved_ips = list(dict.fromkeys(item[4][0] for item in answers if item and item[4]))
        canary_latency_ms = round((time.perf_counter() - t0) * 1000, 1)
        if resolved_ips and len(resolved_ips) > 0:
            canary_test_ok = True
            evidence.append(f"google.com phân giải thành {', '.join(resolved_ips[:3])}")
    except Exception:
        canary_test_ok = False
        evidence.append("Không phân giải được google.com bằng resolver hiện tại")

    if provider_name:
        evidence.append(f"Resolver chính: {provider_name}")
    elif primary_dns:
        evidence.append(f"Resolver không nằm trong danh sách nhận diện: {primary_dns}")

    if not (dns_servers or dns_servers_v6):
        remediation = ["Kiểm tra lại quyền đọc cấu hình DNS hoặc xem cấu hình adapter; kết quả DNS hiện chưa đủ dữ liệu để kết luận."]
    elif not canary_test_ok:
        remediation = ["Kiểm tra cấu hình DNS và cân nhắc dùng 1.1.1.1, 9.9.9.9 hoặc DNS doanh nghiệp đáng tin cậy."]
    else:
        remediation = ["Giám sát DNS over HTTPS/TLS nếu cần giảm nguy cơ sửa đổi trên mạng không tin cậy."]

    return {
        "dns_servers": dns_servers,
        "dns_servers_v6": dns_servers_v6,
        "primary_dns": primary_dns,
        "provider_name": provider_name,
        "is_router_relay": is_router_relay,
        "dns_source": dns_source,
        "dns_configuration_available": bool(dns_servers or dns_servers_v6),
        "canary_test_ok": canary_test_ok,
        "canary_latency_ms": canary_latency_ms,
        "canary_ips": resolved_ips[:3],
        "evidence": evidence,
        "confidence": 0.85 if canary_test_ok else (0.65 if dns_servers or dns_servers_v6 else 0.35),
        "remediation": remediation,
    }


def _safe_tcp_probe(host: str, port: int, payload: bytes = b"", timeout: float = 0.6, tls: bool = False) -> Dict[str, Any]:
    """Bounded TCP probe used for evidence collection, never for login attempts."""
    result: Dict[str, Any] = {
        "host": host,
        "port": int(port),
        "open": False,
        "response": "",
        "banner": "",
        "error": "",
    }
    sock = None
    try:
        sock = socket.create_connection((host, int(port)), timeout=max(0.1, min(float(timeout), 3.0)))
        if tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=host)
        result["open"] = True
        if payload:
            sock.sendall(payload)
        sock.settimeout(max(0.1, min(float(timeout), 2.0)))
        try:
            raw = sock.recv(4096)
            result["response"] = raw.decode("utf-8", errors="replace")[:2048]
            result["banner"] = result["response"].split("\r\n", 1)[0][:256]
        except (socket.timeout, OSError):
            pass
    except Exception as exc:
        result["error"] = str(exc)[:200]
    finally:
        try:
            if sock:
                sock.close()
        except Exception:
            pass
    return result


def _smb2_header(command: int, message_id: int = 0, session_id: int = 0, tree_id: int = 0) -> bytearray:
    """Create an SMB2 header for a read-only negotiate/session probe."""
    header = bytearray(64)
    header[0:4] = b"\xfeSMB"
    struct.pack_into("<H", header, 4, 64)  # StructureSize
    struct.pack_into("<I", header, 8, 0)  # Status
    struct.pack_into("<H", header, 12, int(command))
    struct.pack_into("<H", header, 14, 1)  # CreditRequest
    struct.pack_into("<I", header, 16, 0)  # Flags
    struct.pack_into("<I", header, 20, 0)  # NextCommand
    struct.pack_into("<Q", header, 24, int(message_id))
    struct.pack_into("<I", header, 32, 0)  # Reserved (SMB2 ProcessId field)
    struct.pack_into("<I", header, 36, int(tree_id))
    struct.pack_into("<Q", header, 40, int(session_id))
    # Signature remains zero for an unauthenticated negotiate.
    return header


def _netbios_frame(payload: bytes) -> bytes:
    length = len(payload)
    return b"\x00" + length.to_bytes(3, "big") + payload


def _smb2_negotiate_request() -> bytes:
    # Keep the request context-free so older SMB2/3 servers accept it; a
    # 3.1.1 negotiate context would require additional pre-auth hash fields.
    dialects = (0x0202, 0x0210, 0x0300)
    body = bytearray(36 + 2 * len(dialects))
    struct.pack_into("<H", body, 0, 36)  # StructureSize
    struct.pack_into("<H", body, 2, len(dialects))
    struct.pack_into("<H", body, 4, 1)  # signing enabled, no credentials
    struct.pack_into("<I", body, 8, 0)  # capabilities
    # ClientGuid can be all zero for a stateless probe.
    struct.pack_into("<I", body, 28, 0)  # NegotiateContextOffset
    struct.pack_into("<H", body, 32, 0)
    struct.pack_into("<H", body, 34, 0)
    for index, dialect in enumerate(dialects):
        struct.pack_into("<H", body, 36 + index * 2, dialect)
    return _netbios_frame(bytes(_smb2_header(0)) + body)


def _smb2_session_setup_anonymous_request() -> bytes:
    # Empty security buffer intentionally tests anonymous/guest policy only;
    # no username, password, or credential material is sent.
    body = bytearray(24)
    struct.pack_into("<H", body, 0, 25)  # StructureSize
    body[2] = 0  # Flags
    body[3] = 0  # SecurityMode
    struct.pack_into("<I", body, 4, 0)  # Capabilities
    struct.pack_into("<I", body, 8, 0)  # Channel
    struct.pack_into("<H", body, 12, 88)  # SecurityBufferOffset
    struct.pack_into("<H", body, 14, 0)  # SecurityBufferLength
    struct.pack_into("<Q", body, 16, 0)  # PreviousSessionId
    return _netbios_frame(bytes(_smb2_header(1, message_id=1)) + body)


def _smb_status_from_response(response: str) -> Optional[int]:
    try:
        raw = response.encode("latin-1", errors="ignore")
        # _safe_tcp_probe stores decoded text, so this path is best effort.
        marker = raw.find(b"\xfeSMB")
        if marker >= 0 and len(raw) >= marker + 12:
            return struct.unpack_from("<I", raw, marker + 8)[0]
    except Exception:
        pass
    return None


def _smb_probe_raw(host: str, payload: bytes, timeout: float) -> Dict[str, Any]:
    """Like _safe_tcp_probe but preserve binary SMB response bytes."""
    result: Dict[str, Any] = {"open": False, "raw": b"", "error": ""}
    sock = None
    try:
        sock = socket.create_connection((host, 445), timeout=max(0.1, min(float(timeout), 3.0)))
        result["open"] = True
        sock.sendall(payload)
        sock.settimeout(max(0.1, min(float(timeout), 2.0)))
        result["raw"] = sock.recv(8192)
    except Exception as exc:
        result["error"] = str(exc)[:200]
    finally:
        try:
            if sock:
                sock.close()
        except Exception:
            pass
    return result


def _recv_smb_frame(sock: socket.socket, max_length: int = 8192) -> bytes:
    """Read one Direct-TCP SMB frame without assuming recv returns it whole."""
    def receive_exact(size: int) -> bytes:
        chunks = []
        remaining = size
        while remaining:
            chunk = sock.recv(remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    header = receive_exact(4)
    if len(header) != 4:
        return header
    length = int.from_bytes(header[1:4], "big")
    if length <= 0 or length > max_length:
        return header
    return header + receive_exact(length)


def _smb_negotiate_then_empty_session(host: str, timeout: float) -> Dict[str, Any]:
    """Keep SMB negotiate and session setup on one TCP connection."""
    result: Dict[str, Any] = {"open": False, "negotiate": b"", "session": b"", "error": ""}
    sock = None
    try:
        sock = socket.create_connection((host, 445), timeout=max(0.1, min(float(timeout), 3.0)))
        sock.settimeout(max(0.1, min(float(timeout), 2.0)))
        result["open"] = True
        sock.sendall(_smb2_negotiate_request())
        result["negotiate"] = _recv_smb_frame(sock)
        # SMB state is connection-scoped.  Opening a second TCP connection
        # here would make a SessionSetup response meaningless or rejected.
        if result["negotiate"]:
            sock.sendall(_smb2_session_setup_anonymous_request())
            result["session"] = _recv_smb_frame(sock)
    except Exception as exc:
        result["error"] = str(exc)[:200]
    finally:
        try:
            if sock:
                sock.close()
        except Exception:
            pass
    return result


def check_smb_guest(host: str, timeout: float = 0.6) -> Dict[str, Any]:
    """Perform negotiate + empty-session probes without guessing credentials.

    ``guest_confirmed`` is emitted only when the server explicitly accepts an
    empty session and sets the SMB guest flag. A TCP-open or negotiate-only
    result remains ``unverified`` rather than being called guest access.
    """
    exchange = _smb_negotiate_then_empty_session(host, timeout)
    if not exchange["open"]:
        return {
            "check": "smb_guest", "host": host, "status": "unreachable", "port_open": False,
            "evidence": exchange.get("error", "Không phản hồi TCP/445"), "response_excerpt": "",
            "confidence": 0.85, "risk": "safe",
            "remediation": "Không quan sát được SMB trên cổng 445.",
        }
    raw = exchange.get("negotiate", b"")
    status_code = struct.unpack_from("<I", raw, 12)[0] if len(raw) >= 16 and raw[4:8] == b"\xfeSMB" else None
    if status_code not in (None, 0, 0x00000103):
        return {
            "check": "smb_guest", "host": host, "status": "negotiate_rejected", "port_open": True,
            "evidence": f"SMB negotiate status 0x{status_code:08X}" if status_code is not None else "SMB endpoint phản hồi không chuẩn",
            "response_excerpt": raw[:256].hex(), "confidence": 0.8, "risk": "safe",
            "remediation": "Cập nhật/kiểm tra cấu hình SMB nếu thiết bị cần chia sẻ tệp.",
        }
    session_raw = exchange.get("session", b"")
    session_status = struct.unpack_from("<I", session_raw, 12)[0] if len(session_raw) >= 16 and session_raw[4:8] == b"\xfeSMB" else None
    guest_flag = False
    if session_status == 0 and len(session_raw) >= 72:
        # SessionSetup response flags follow the 64-byte SMB2 header and
        # structure size (2 bytes); bit 0 indicates guest, bit 1 null session.
        flags_offset = 4 + 64 + 2
        guest_flag = bool(struct.unpack_from("<H", session_raw, flags_offset)[0] & 0x0001)
    if guest_flag:
        status = "guest_confirmed"
        risk = "high"
        confidence = 0.96
        evidence = "SMB SessionSetup chấp nhận phiên rỗng và đặt cờ IS_GUEST."
    elif session_status in (0xC0000022, 0xC000006D, 0xC0000064):
        status = "guest_denied"
        risk = "safe"
        confidence = 0.92
        evidence = f"Server từ chối phiên rỗng (NTSTATUS 0x{session_status:08X})."
    else:
        status = "unverified"
        risk = "medium"
        confidence = 0.55
        evidence = "TCP/445 và SMB negotiate phản hồi nhưng chưa xác minh được guest/anonymous."
        if exchange.get("error"):
            evidence += f" SessionSetup: {exchange['error']}"
    return {
        "check": "smb_guest", "host": host, "status": status, "port_open": True,
        "evidence": evidence, "response_excerpt": session_raw[:512].hex(),
        "confidence": confidence, "risk": risk,
        "remediation": "Tắt SMB guest/anonymous và yêu cầu xác thực; chỉ mở chia sẻ trong VLAN tin cậy." if status == "guest_confirmed" else "Không kết luận guest nếu server chưa trả cờ xác nhận; tiếp tục theo dõi.",
    }


def check_telnet(host: str, timeout: float = 0.6) -> Dict[str, Any]:
    probe = _safe_tcp_probe(host, 23, timeout=timeout)
    return {
        "check": "telnet",
        "host": host,
        "status": "open" if probe["open"] else "closed",
        "evidence": probe.get("banner") or probe.get("error", "Không phản hồi"),
        "banner": probe.get("response", "")[:500],
        "confidence": 0.9,
        "risk": "critical" if probe["open"] else "safe",
        "remediation": "Tắt Telnet và dùng SSH/HTTPS quản trị; cập nhật firmware thiết bị." if probe["open"] else "Cổng Telnet không phản hồi.",
    }


def check_http_admin(host: str, ports: tuple = (80, 8080, 443), timeout: float = 0.7) -> List[Dict[str, Any]]:
    """Collect HTTP status/title/server evidence without submitting forms."""
    findings: List[Dict[str, Any]] = []
    request = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: WifiDeviceScanner-Audit/1\r\nConnection: close\r\n\r\n".encode("ascii", errors="ignore")
    for port in ports:
        probe = _safe_tcp_probe(host, port, request, timeout, tls=(int(port) == 443))
        if not probe["open"]:
            continue
        response = probe.get("response", "")
        status_line = response.split("\r\n", 1)[0] if response else "TCP kết nối thành công"
        server_match = re.search(r"^Server:\s*(.+)$", response, re.IGNORECASE | re.MULTILINE)
        findings.append(
            {
                "check": "http_admin",
                "host": host,
                "port": int(port),
                "status": "open",
                "protocol": "https" if int(port) == 443 else "http",
                "evidence": status_line[:250],
                "server": server_match.group(1).strip()[:200] if server_match else "",
                "response_excerpt": response[:800],
                "confidence": 0.75,
                "risk": "medium" if int(port) != 443 else "safe",
                "remediation": "Ưu tiên HTTPS, tắt HTTP quản trị và giới hạn quản trị từ LAN/VLAN tin cậy." if int(port) != 443 else "Giới hạn giao diện quản trị vào mạng quản trị và cập nhật firmware.",
            }
        )
    return findings


def check_upnp(
    host: str,
    timeout: float = 0.7,
    ssdp_records: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Check for a UPnP control endpoint; an open port alone is only evidence."""
    probe = _safe_tcp_probe(host, 5000, timeout=timeout)
    ssdp_evidence = ""
    ssdp_seen = False
    if ssdp_records is not None:
        for record in ssdp_records:
            if str(record.get("ip") or "") != str(host):
                continue
            ssdp_seen = True
            ssdp_evidence = (
                str(record.get("status") or "")
                or str(record.get("server") or "")
                or str(record.get("st") or "")
            )[:200]
            break
    else:
        # Standalone callers still get a single bounded SSDP query.  The
        # dashboard supplies shared records so it does not send one multicast
        # request per device.
        udp = None
        try:
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            udp.settimeout(max(0.1, min(float(timeout), 2.0)))
            request = (
                "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
                "MAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n"
            ).encode("ascii")
            udp.sendto(request, ("239.255.255.250", 1900))
            deadline = time.monotonic() + max(0.1, min(float(timeout), 2.0))
            while time.monotonic() < deadline:
                raw, addr = udp.recvfrom(4096)
                if addr and addr[0] == host:
                    ssdp_seen = True
                    ssdp_evidence = raw.decode("utf-8", errors="replace").split("\r\n", 1)[0][:200]
                    break
        except Exception:
            pass
        finally:
            try:
                if udp:
                    udp.close()
            except Exception:
                pass
    if ssdp_seen:
        status = "ssdp_response"
    elif probe["open"]:
        status = "endpoint_reachable"
    else:
        status = "not_observed"
    return {
        "check": "upnp",
        "host": host,
        "status": status,
        "evidence": ssdp_evidence or probe.get("banner") or ("TCP/5000 phản hồi" if probe["open"] else probe.get("error", "Không phản hồi")),
        "confidence": 0.9 if ssdp_seen else (0.55 if probe["open"] else 0.75),
        "risk": "medium" if (probe["open"] or ssdp_seen) else "safe",
        "remediation": "Tắt UPnP nếu không cần; nếu cần, rà soát port mapping và giới hạn thiết bị được phép." if (probe["open"] or ssdp_seen) else "Chưa quan sát endpoint UPnP.",
    }


def run_security_dashboard(
    gateway_ip: str,
    devices: Optional[List[Dict[str, Any]]] = None,
    timeout: float = 0.7,
    dns_info: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Run bounded defensive checks and return evidence-rich findings."""
    targets: List[Tuple[str, str]] = []
    if gateway_ip:
        targets.append((str(gateway_ip), "gateway"))
    for device in devices or []:
        ip = str(device.get("ip", ""))
        if ip and ip != str(gateway_ip) and len(targets) < 9:
            targets.append((ip, "device"))
    findings: List[Dict[str, Any]] = []
    try:
        from network_discovery import discover_ssdp

        ssdp_records = discover_ssdp(timeout=min(max(float(timeout), 0.1), 1.5))
    except Exception:
        ssdp_records = []

    def inspect(target: Tuple[str, str]) -> List[Dict[str, Any]]:
        host, role = target
        local: List[Dict[str, Any]] = []
        for item in (
            check_smb_guest(host, timeout),
            check_telnet(host, timeout),
            check_upnp(host, timeout, ssdp_records=ssdp_records),
        ):
            item["role"] = role
            local.append(item)
        for item in check_http_admin(host, timeout=timeout):
            item["role"] = role
            local.append(item)
        return local

    with ThreadPoolExecutor(max_workers=max(1, min(8, len(targets)))) as executor:
        futures = [executor.submit(inspect, target) for target in targets]
        for future in futures:
            try:
                findings.extend(future.result())
            except Exception:
                continue
    return {
        "generated_at": time.time(),
        "gateway_ip": gateway_ip,
        "findings": findings,
        "ssdp_records": ssdp_records,
        "dns": dns_info if dns_info is not None else audit_dns_security(),
        "summary": {
            "critical": sum(1 for f in findings if f.get("risk") == "critical"),
            "high": sum(1 for f in findings if f.get("risk") == "high"),
            "medium": sum(1 for f in findings if f.get("risk") == "medium"),
            "observations": len(findings),
        },
    }


def evaluate_security_audit(wifi_info: dict, router_ports: list, dns_info: dict, dashboard: Optional[dict] = None) -> Dict[str, Any]:
    """
    Tổng hợp và chấm điểm an ninh mạng (/100), đưa ra khuyến nghị tăng cường.
    """
    score = 100
    deductions = []
    recommendations = []

    # 1. Đánh giá chuẩn mã hóa Wi-Fi (Tối đa trừ 40 điểm)
    wifi_level = wifi_info.get("security_level", "unknown")
    auth = wifi_info.get("auth", "")
    cipher = wifi_info.get("cipher", "")

    if wifi_level == "dangerous":
        score -= 40
        deductions.append("Wi-Fi không đặt mật khẩu hoặc dùng chuẩn WEP đã lỗi thời (-40đ)")
        recommendations.append("🚨 ĐẶT MẬT KHẨU WI-FI NGAY: Đổi sang chuẩn WPA2-Personal hoặc WPA3 trong trang cấu hình modem.")
    elif wifi_level == "fair":
        score -= 20
        deductions.append("Wi-Fi dùng chuẩn WPA cũ hoặc mã hóa TKIP (-20đ)")
        recommendations.append("⚠️ NÂNG CẤP MÃ HÓA: Chuyển mã hóa Wi-Fi từ TKIP sang AES (CCMP) hoặc WPA3 để chống bị bẻ khóa.")
    elif wifi_level == "good":
        # WPA2-AES là tiêu chuẩn tốt, trừ nhẹ 5đ khuyến khích lên WPA3 nếu có
        score -= 5
        deductions.append("Mạng đạt chuẩn an toàn WPA2-Personal tiêu chuẩn (-5đ so với WPA3)")
        recommendations.append("💡 Gợi ý nâng cao: Nếu modem hỗ trợ WPA3/WPA2 Mixed Mode, bạn có thể bật lên để tăng tối đa bảo mật.")
    elif wifi_level == "excellent":
        # WPA3 hoàn hảo
        pass

    # 2. Đánh giá các cổng nhạy cảm trên Router (Tối đa trừ 40 điểm)
    open_risky_ports = []
    has_https = False
    has_http = False

    for p in router_ports:
        port_num = p["port"]
        is_open = p["is_open"]
        risk = p["risk"]

        if is_open:
            if port_num == 443:
                has_https = True
            elif port_num == 80:
                has_http = True

            if risk == "critical":
                score -= 25
                deductions.append(f"Cổng cực kỳ nguy hiểm Telnet ({port_num}) đang MỞ trên Router (-25đ)")
                recommendations.append(f"🚨 TẮT TELNET NGAY: Cổng 23 Telnet đang mở trên router. Hãy vào trang quản trị modem và tắt ngay.")
            elif risk == "high":
                score -= 15
                deductions.append(f"Cổng có độ rủi ro cao {p['name']} ({port_num}) đang MỞ (-15đ)")
                recommendations.append(f"⚠️ ĐÓNG CỔNG {p['name']}: {p['recommendation']}")
            elif risk == "medium" and port_num in (1900, 5000):
                score -= 10
                deductions.append(f"Dịch vụ UPnP ({port_num}) đang mở trên Router (-10đ)")
                recommendations.append("🛡️ VÔ HIỆU HÓA UPNP: Tắt tính năng UPnP trên modem để chặn mã độc tự ý mở cổng ra ngoài.")
            elif risk == "medium" and port_num == 22:
                score -= 5
                deductions.append(f"Cổng SSH ({port_num}) đang mở trên Router (-5đ)")

    if has_http and not has_https:
        score -= 5
        deductions.append("Trang quản trị Modem chỉ hỗ trợ HTTP thông thường, chưa bật HTTPS (-5đ)")

    # 3. Đánh giá DNS và Toàn vẹn (Tối đa trừ 20 điểm)
    dns_config_known = bool(
        dns_info.get("dns_configuration_available")
        if "dns_configuration_available" in dns_info
        else (dns_info.get("dns_servers") or dns_info.get("dns_servers_v6") or dns_info.get("primary_dns"))
    )
    if not dns_info.get("canary_test_ok") and dns_config_known:
        score -= 20
        deductions.append("Truy vấn thử nghiệm DNS thất bại hoặc bị chặn (-20đ)")
        recommendations.append("🚨 KIỂM TRA MÁY CHỦ DNS: Kiểm tra lại cấu hình DNS trong máy tính hoặc đổi sang Cloudflare 1.1.1.1 / Google 8.8.8.8.")
    elif not dns_info.get("canary_test_ok"):
        recommendations.append("ℹ️ CHƯA ĐỦ DỮ LIỆU DNS: Không lấy được danh sách resolver; hãy kiểm tra lại sau khi adapter hoạt động.")
    else:
        if dns_info.get("is_router_relay"):
            # Sử dụng DNS mặc định của nhà mạng qua router
            recommendations.append("🚀 TỐI ƯU TỐC ĐỘ & BẢO MẬT: Đổi DNS sang Cloudflare (1.1.1.1) hoặc Quad9 (9.9.9.9) để tăng tốc độ lướt web và tự động chặn trang web lừa đảo.")

    # 4. Các quan sát dịch vụ bổ sung.  Chỉ trừ điểm khi trạng thái mở/
    # reachable có bằng chứng; SMB guest chưa xác minh không bị coi là đã bật.
    service_deduction_budget = 15
    router_open_ports = {
        int(item.get("port"))
        for item in router_ports
        if item.get("is_open") and str(item.get("port", "")).isdigit()
    }
    for finding in (dashboard or {}).get("findings", []):
        status = str(finding.get("status", "")).lower()
        risk = str(finding.get("risk", "")).lower()
        if status not in ("open", "endpoint_reachable", "ssdp_response", "guest_confirmed"):
            continue
        if risk == "critical" and finding.get("check") == "telnet":
            # Telnet trên thiết bị đã được tính ở phần router ports; tránh trừ đôi.
            if finding.get("role") != "gateway":
                deduction = min(10, service_deduction_budget)
                score -= deduction
                service_deduction_budget -= deduction
                deductions.append(f"Thiết bị {finding.get('host')} đang mở Telnet (-10đ)")
        elif finding.get("role") == "gateway" and finding.get("check") == "upnp":
            # TCP/5000 and TCP/1900 observations on the gateway were already
            # scored above when the corresponding router port is open.
            if (
                (status == "endpoint_reachable" and 5000 in router_open_ports)
                or (status == "ssdp_response" and 1900 in router_open_ports)
            ):
                continue
            if risk != "medium":
                continue
            if service_deduction_budget <= 0:
                continue
            deduction = min(3, service_deduction_budget)
            score -= deduction
            service_deduction_budget -= deduction
            recommendations.append(
                f"Kiểm tra UPnP trên {finding.get('host')}: {finding.get('remediation', 'giới hạn dịch vụ vào mạng tin cậy.')}"
            )
        elif finding.get("role") == "gateway" and finding.get("check") == "http_admin":
            # The router-port audit already accounts for HTTP/HTTPS admin
            # endpoints, while the dashboard retains their banner evidence.
            continue
        elif risk == "high":
            if service_deduction_budget <= 0:
                continue
            deduction = min(8, service_deduction_budget)
            score -= deduction
            service_deduction_budget -= deduction
            deductions.append(f"Dịch vụ rủi ro cao trên {finding.get('host')} cần được khóa (-{deduction}đ)")
            recommendations.append(
                f"Khắc phục {finding.get('check')} trên {finding.get('host')}: {finding.get('remediation', 'tắt truy cập khách/ẩn danh và giới hạn theo VLAN.')}"
            )
        elif risk == "medium":
            if service_deduction_budget <= 0:
                continue
            deduction = min(3, service_deduction_budget)
            score -= deduction
            service_deduction_budget -= deduction
            recommendations.append(
                f"Kiểm tra {finding.get('check')} trên {finding.get('host')}: {finding.get('remediation', 'giới hạn dịch vụ vào mạng tin cậy.')}"
            )

    # Luôn khuyến nghị đổi mật khẩu mặc định modem
    recommendations.append("🔑 ĐỔI MẬT KHẨU QUẢN TRỊ MODEM: Không nên để mật khẩu mặc định (admin/admin hoặc mật khẩu in dưới đáy modem) vì ai bắt được Wi-Fi cũng có thể vào xem.")

    # Đảm bảo điểm nằm trong khoảng 0 - 100
    score = max(0, min(100, score))

    # Xếp hạng tổng thể
    if score >= 90:
        grade = "A"
        badge_text = "🛡️ MẠNG RẤT AN TOÀN (CHUẨN BẢO VỆ CAO)"
        badge_color = "#10B981"
    elif score >= 75:
        grade = "B"
        badge_text = "🟢 MẠNG AN TOÀN TIÊU CHUẨN"
        badge_color = "#3B82F6"
    elif score >= 50:
        grade = "C"
        badge_text = "🟡 MỨC ĐỘ TRUNG BÌNH - CẦN CẢI THIỆN CẤU HÌNH"
        badge_color = "#F59E0B"
    else:
        grade = "D"
        badge_text = "🔴 CẢNH BÁO NGUY HIỂM: NHIỀU LỖ HỔNG AN NINH"
        badge_color = "#EF4444"

    return {
        "score": score,
        "grade": grade,
        "badge_text": badge_text,
        "badge_color": badge_color,
        "deductions": deductions,
        "recommendations": recommendations,
    }
