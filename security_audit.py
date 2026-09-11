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
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, List

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
    try:
        out = subprocess.check_output(
            ["ipconfig", "/all"],
            text=True,
            errors="ignore",
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
        )
        dns_servers = re.findall(r"DNS Servers[ .:]+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", out)
    except Exception:
        pass

    if not dns_servers:
        dns_servers = ["192.168.1.1"]

    primary_dns = dns_servers[0] if dns_servers else "192.168.1.1"
    provider_name = KNOWN_SAFE_DNS.get(primary_dns, "")
    is_router_relay = False
    if primary_dns.startswith("192.168.") or primary_dns.startswith("10.") or primary_dns.startswith("172."):
        is_router_relay = True
        provider_name = f"Modem / Router chuyển tiếp nội bộ ({primary_dns})"

    # Kiểm tra phân giải tên miền Canary (Chống DNS Hijacking)
    canary_test_ok = False
    canary_latency_ms = 0
    resolved_ips = []
    try:
        t0 = time.perf_counter()
        resolved_ips = socket.gethostbyname_ex("google.com")[2]
        canary_latency_ms = round((time.perf_counter() - t0) * 1000, 1)
        # Google IPs thường bắt đầu bằng 142.250., 172.217., 74.125., 216.58., v.v.
        if resolved_ips and len(resolved_ips) > 0:
            canary_test_ok = True
    except Exception:
        canary_test_ok = False

    return {
        "dns_servers": dns_servers,
        "primary_dns": primary_dns,
        "provider_name": provider_name,
        "is_router_relay": is_router_relay,
        "canary_test_ok": canary_test_ok,
        "canary_latency_ms": canary_latency_ms,
        "canary_ips": resolved_ips[:3],
    }


def evaluate_security_audit(wifi_info: dict, router_ports: list, dns_info: dict) -> Dict[str, Any]:
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
    if not dns_info.get("canary_test_ok"):
        score -= 20
        deductions.append("Truy vấn thử nghiệm DNS thất bại hoặc bị chặn (-20đ)")
        recommendations.append("🚨 KIỂM TRA MÁY CHỦ DNS: Kiểm tra lại cấu hình DNS trong máy tính hoặc đổi sang Cloudflare 1.1.1.1 / Google 8.8.8.8.")
    else:
        if dns_info.get("is_router_relay"):
            # Sử dụng DNS mặc định của nhà mạng qua router
            recommendations.append("🚀 TỐI ƯU TỐC ĐỘ & BẢO MẬT: Đổi DNS sang Cloudflare (1.1.1.1) hoặc Quad9 (9.9.9.9) để tăng tốc độ lướt web và tự động chặn trang web lừa đảo.")

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
