"""
spy_camera_detector.py - Module quét tìm Camera giấu kín & Thiết bị quay lén trong mạng Wi-Fi.
Chuyên sâu phát hiện các dòng camera ngụy trang (Tuya, Espressif ESP32-CAM, Xiongmai, Hikvision, Dahua...),
quét các cổng truyền luồng video thời gian thực (RTSP 554, Dahua 37777, XMeye 34567, ONVIF 8899)
và phát còi báo động âm thanh bảo vệ riêng tư cho người dùng.
"""

import socket
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, List, Optional

try:
    import winsound
except ImportError:
    winsound = None

# Danh mục các nhà sản xuất và nền tảng chip Camera giấu kín / IoT phổ biến
CAMERA_CHIP_SIGNATURES = {
    "tuya": "Tuya Smart (Nền tảng phổ biến nhất của các dòng camera mini ngụy trang cúc áo / đồng hồ / báo khói)",
    "espressif": "Espressif Systems (Chip ESP8266 / ESP32-CAM dùng chế tạo camera quay lén siêu nhỏ)",
    "xiongmai": "Hangzhou Xiongmai (XMeye - Nhà sản xuất bo mạch camera IP OEM lớn nhất thế giới)",
    "hikvision": "Hangzhou Hikvision / Ezviz (Thương hiệu camera quan sát hàng đầu)",
    "dahua": "Zhejiang Dahua / Imou / Lechange (Camera an ninh & giám sát video)",
    "anyka": "Anyka Microelectronics (Chip chuyên dụng camera mini Yoosee / Vstarcam)",
    "goke": "Goke Microelectronics (Vi xử lý hình ảnh camera IP)",
    "allwinner": "Allwinner Technology (SoC camera giám sát mini)",
    "ingenic": "Ingenic Semiconductor (Chip camera thông minh)",
    "foscam": "Foscam Network Camera",
    "reolink": "Reolink Digital Technology",
    "wyze": "Wyze Labs Camera",
    "amcrest": "Amcrest Technologies",
    "vstarcam": "Vstarcam Network Camera",
    "yoosee": "Yoosee Wi-Fi Camera",
    "shenzhen bilian": "ShenZhen Bilian (Module Wi-Fi camera mini)",
    "shenzhen yunji": "ShenZhen Yunji Technology",
    "ogemray": "ShenZhen Ogemray (Module truyền video Wi-Fi)",
    "sunplus": "Sunplus Technology (Chip xử lý hình ảnh)",
}

# Các cổng dịch vụ video và điều khiển đặc thù của camera
CAMERA_PORTS = [
    (554, "RTSP", "Luồng phát trực tiếp video thời gian thực (Real Time Streaming Protocol)"),
    (8554, "RTSP-Alt", "Cổng luồng video phụ"),
    (37777, "Dahua-Media", "Cổng truyền luồng video độc quyền Dahua / Imou"),
    (34567, "XMeye-Media", "Cổng truyền luồng video độc quyền Xiongmai / XMeye"),
    (8000, "Hikvision-Device", "Cổng quản trị thiết bị Hikvision / Ezviz"),
    (8899, "ONVIF-API", "Cổng giao tiếp chuẩn mở ONVIF Camera"),
    (1935, "RTMP", "Giao thức truyền phát video trực tiếp RTMP"),
    (8080, "Camera-Web-Alt", "Trang web quản trị camera phụ"),
    (80, "Camera-Web", "Trang web quản trị camera mặc định"),
]


def play_alarm_sound():
    """Phát chuỗi âm thanh còi báo động khẩn cấp qua loa máy tính."""
    def _beep_worker():
        if not winsound:
            return
        try:
            # Phát 3 hồi còi báo động dồn dập
            for _ in range(3):
                winsound.Beep(1200, 120)
                time.sleep(0.04)
                winsound.Beep(1800, 200)
                time.sleep(0.08)
        except Exception:
            pass

    threading.Thread(target=_beep_worker, daemon=True).start()


def check_camera_video_ports(ip_str: str, timeout_sec: float = 0.2) -> List[Dict[str, Any]]:
    """Kiểm tra các cổng dịch vụ video của camera trên địa chỉ IP đích."""
    open_ports = []

    def _probe(port, name, desc):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout_sec)
        try:
            res = s.connect_ex((ip_str, port))
            if res == 0:
                open_ports.append({
                    "port": port,
                    "name": name,
                    "desc": desc,
                })
        except Exception:
            pass
        finally:
            try:
                s.close()
            except Exception:
                pass

    with ThreadPoolExecutor(max_workers=len(CAMERA_PORTS)) as executor:
        for p, n, d in CAMERA_PORTS:
            executor.submit(_probe, p, n, d)

    open_ports.sort(key=lambda x: x["port"])
    return open_ports


def verify_rtsp_service(ip_str: str, port: int = 554, timeout_sec: float = 0.4) -> Dict[str, Any]:
    """
    Xác minh một cổng TCP thực sự nói giao thức RTSP.
    Chỉ mở TCP không đủ để kết luận đó là camera; dịch vụ phải trả status line RTSP.
    """
    result: Dict[str, Any] = {
        "verified": False,
        "status_code": None,
        "server": "",
    }
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout_sec)
    try:
        s.connect((ip_str, port))
        request = (
            f"OPTIONS rtsp://{ip_str}:{port}/ RTSP/1.0\r\n"
            "CSeq: 1\r\n"
            "User-Agent: WiFiDeviceScanner/1.0\r\n"
            "\r\n"
        )
        s.sendall(request.encode("ascii", errors="ignore"))
        response = s.recv(4096).decode("utf-8", errors="ignore")

        status_match = re.search(
            r"(?im)^RTSP/\d+(?:\.\d+)?\s+(\d{3})\b",
            response,
        )
        if status_match:
            result["verified"] = True
            result["status_code"] = int(status_match.group(1))

        server_match = re.search(r"(?im)^Server:\s*([^\r\n]+)", response)
        if server_match:
            result["server"] = server_match.group(1).strip()
    except Exception:
        pass
    finally:
        try:
            s.close()
        except Exception:
            pass
    return result


def grab_camera_web_info(ip_str: str, port: int = 80, timeout_sec: float = 0.3) -> Dict[str, str]:
    """Thử lấy tiêu đề trang web hoặc Server banner của camera."""
    info = {"title": "", "server": "", "is_camera_web": False}
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout_sec)
    try:
        s.connect((ip_str, port))
        req = f"GET / HTTP/1.1\r\nHost: {ip_str}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
        s.sendall(req.encode())
        resp = s.recv(4096).decode("utf-8", errors="ignore")

        # Tìm Server header
        m_srv = re.search(r"Server:\s*([^\r\n]+)", resp, re.IGNORECASE)
        if m_srv:
            info["server"] = m_srv.group(1).strip()

        # Tìm Title
        m_title = re.search(r"<title[^>]*>(.*?)</title>", resp, re.IGNORECASE | re.DOTALL)
        if m_title:
            info["title"] = m_title.group(1).strip()

        # Kiểm tra từ khóa camera trong banner
        combined = (info["server"] + " " + info["title"]).lower()
        keywords = [
            "camera",
            "netcam",
            "ipcam",
            "webcam",
            "live view",
            "dvr",
            "nvr",
            "dahua",
            "hikvision",
            "tapo",
            "ezviz",
            "imou",
            "xiongmai",
            "boa",
            "goahead",
            "mini-httpd",
            "uc-httpd",
        ]
        if any(re.search(rf"\b{re.escape(keyword)}\b", combined) for keyword in keywords):
            info["is_camera_web"] = True

    except Exception:
        pass
    finally:
        try:
            s.close()
        except Exception:
            pass

    return info


def analyze_spy_camera_risk(device: dict) -> Dict[str, Any]:
    """
    Phân tích toàn diện mức độ rủi ro camera quay lén của 1 thiết bị:
    - Trả về: risk_level ('confirmed', 'suspicious', 'potential', 'safe')
    - Chỉ dùng 'confirmed' khi có bằng chứng giao thức RTSP và nhận diện camera bổ sung.
    """
    ip = device.get("ip", "")
    mac = device.get("mac", "")
    vendor = (device.get("vendor") or "").lower()
    name = (device.get("name") or "").lower()
    is_gateway = device.get("is_gateway", False)
    is_self = device.get("is_self", False)

    # Nếu là Router hoặc máy tính hiện tại -> Bỏ qua
    if is_gateway or is_self:
        return {
            "device": device,
            "risk_level": "safe",
            "risk_title": "Thiết bị an toàn (Router / Máy này)",
            "threat_score": 0,
            "matched_chip": "",
            "open_cam_ports": [],
            "rtsp_url": "",
            "web_url": "",
            "reasons": [],
        }

    # 1. Quét các cổng video camera
    open_cam_ports = check_camera_video_ports(ip)
    open_port_nums = [p["port"] for p in open_cam_ports]

    # Xác minh handshake RTSP; TCP connect thành công đơn thuần chưa đủ kết luận.
    rtsp_checks: Dict[int, Dict[str, Any]] = {}
    for rtsp_port in (554, 8554):
        if rtsp_port in open_port_nums:
            rtsp_checks[rtsp_port] = verify_rtsp_service(ip, rtsp_port)
    verified_rtsp_ports = [
        port for port, check in rtsp_checks.items() if check.get("verified")
    ]

    # 2. Kiểm tra chữ ký chip / nhà sản xuất
    matched_chip = ""
    for sig, desc in CAMERA_CHIP_SIGNATURES.items():
        if sig in vendor or sig in name:
            matched_chip = desc
            break

    # 3. Lấy thông tin Web Camera nếu có cổng 80 / 8080
    web_info = {"title": "", "server": "", "is_camera_web": False}
    web_port = None
    if 80 in open_port_nums:
        web_port = 80
    elif 8080 in open_port_nums:
        web_port = 8080

    if web_port:
        web_info = grab_camera_web_info(ip, web_port)

    # 4. Phân loại mức độ nguy cơ
    reasons = []
    threat_score = 0
    risk_level = "safe"

    # Cổng mở chỉ là dấu hiệu; cần handshake/banner trước khi xác nhận.
    open_rtsp_ports = [port for port in (554, 8554) if port in open_port_nums]
    if verified_rtsp_ports:
        ports_text = ", ".join(str(port) for port in verified_rtsp_ports)
        reasons.append(
            f"Đã xác minh phản hồi giao thức RTSP trên cổng {ports_text}; "
            "vẫn cần đối chiếu thiết bị thực tế."
        )
        threat_score += 40
    elif open_rtsp_ports:
        ports_text = ", ".join(str(port) for port in open_rtsp_ports)
        reasons.append(
            f"Cổng TCP {ports_text} đang mở nhưng chưa xác minh được handshake RTSP; "
            "có thể là media server hoặc dịch vụ khác."
        )
        threat_score += 15
    if 37777 in open_port_nums:
        reasons.append("Có dấu hiệu dịch vụ Dahua / Imou (37777) đang mở; chưa đủ để xác nhận camera.")
        threat_score += 20
    if 34567 in open_port_nums:
        reasons.append("Có dấu hiệu dịch vụ Xiongmai / XMeye (34567) đang mở; chưa đủ để xác nhận camera.")
        threat_score += 20
    if 8000 in open_port_nums:
        reasons.append("Có dấu hiệu dịch vụ Hikvision / Ezviz (8000) đang mở; chưa đủ để xác nhận camera.")
        threat_score += 15
    if 8899 in open_port_nums:
        reasons.append("Có dấu hiệu cổng ONVIF (8899) đang mở; cần xác minh thiết bị.")
        threat_score += 15
    if web_info["is_camera_web"]:
        reasons.append(f"Giao diện web máy chủ xác nhận Camera (Tiêu đề: '{web_info['title']}', Server: '{web_info['server']}')")
        threat_score += 35

    # Dấu hiệu chữ ký phần cứng nghi vấn
    if matched_chip:
        reasons.append(f"Sử dụng nền tảng chip nhạy cảm: {matched_chip}")
        threat_score += 15

    proprietary_camera_ports = bool(
        set(open_port_nums) & {37777, 34567, 8000, 8899}
    )
    has_camera_identity = bool(web_info["is_camera_web"] or matched_chip)

    # Chỉ xác nhận khi có handshake RTSP cùng một tín hiệu nhận diện bổ sung.
    if verified_rtsp_ports and (has_camera_identity or proprietary_camera_ports):
        risk_level = "confirmed"
        risk_title = "🔴 XÁC MINH: THIẾT BỊ CÓ DỊCH VỤ CAMERA / RTSP"
    elif verified_rtsp_ports or web_info["is_camera_web"] or open_rtsp_ports:
        risk_level = "suspicious"
        risk_title = "🟠 NGHI VẤN: CÓ DỊCH VỤ CAMERA / RTSP, CẦN KIỂM TRA THÊM"
    elif proprietary_camera_ports or matched_chip:
        risk_level = "potential"
        risk_title = "🟡 CHÚ Ý: THIẾT BỊ IOT MỞ CỔNG DỊCH VỤ LẠ"
    else:
        risk_level = "safe"
        risk_title = "🟢 THIẾT BỊ BÌNH THƯỜNG"

    rtsp_port = next(
        (port for port in (554, 8554) if port in open_port_nums),
        None,
    )
    rtsp_url = f"rtsp://{ip}:{rtsp_port}/" if rtsp_port else ""
    web_url = f"http://{ip}:{web_port}" if web_port else ""

    return {
        "device": device,
        "risk_level": risk_level,
        "risk_title": risk_title,
        "threat_score": threat_score,
        "matched_chip": matched_chip,
        "open_cam_ports": open_cam_ports,
        "rtsp_checks": rtsp_checks,
        "web_info": web_info,
        "rtsp_url": rtsp_url,
        "web_url": web_url,
        "reasons": reasons,
    }
