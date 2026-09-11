"""
port_scanner.py - Bộ quét cổng dịch vụ (Port Scanner) hiệu năng cao cho mạng LAN.
Hỗ trợ:
- 4 Chế độ quét: Quét nhanh (Top 30), Quét mở rộng (Top 100), Quét chuyên sâu (1 - 1024)
  và Tùy chỉnh dải cổng (Custom Range) bất kỳ (ví dụ: '1-1000', '8000-8100', '80,443,554,37777').
- Hơn 100+ cổng dịch vụ phân loại chi tiết (Camera, Web, Database, Remote, Share, Media, IoT).
- Cơ chế báo cáo thời gian thực (Live Stream) giúp hiển thị kết quả ngay khi vừa tìm thấy.
"""

import socket
import urllib.request
import re
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional, Callable, Set

# Cơ sở dữ liệu cổng dịch vụ mở rộng (Hơn 100 cổng chi tiết)
PORT_DATABASE: Dict[int, Dict[str, str]] = {
    # 1. Web & Giao diện quản trị
    80: {"service": "HTTP", "desc": "Trang Web / Giao diện quản trị Router, Camera, Thiết bị", "cat": "web"},
    443: {"service": "HTTPS", "desc": "Trang Web bảo mật mã hóa (SSL/TLS)", "cat": "web"},
    8080: {"service": "HTTP-Proxy", "desc": "Cổng Web phụ / Proxy / Tomcat / Jenkins", "cat": "web"},
    8000: {"service": "HTTP-Dev / Cam", "desc": "Web phụ / Cổng quản trị Hikvision / Ezviz", "cat": "camera"},
    8443: {"service": "HTTPS-Alt", "desc": "Trang Web bảo mật phụ / UniFi Controller", "cat": "web"},
    8888: {"service": "HTTP-Alt", "desc": "Bảng điều khiển Web / Cpanel / Jupyter", "cat": "web"},
    8081: {"service": "HTTP-Alt2", "desc": "Trang Web phụ / Camera Stream Web", "cat": "web"},
    8082: {"service": "HTTP-Alt3", "desc": "Dịch vụ Web phụ", "cat": "web"},
    8088: {"service": "HTTP-Alt4", "desc": "Web Media / Cổng phát video", "cat": "web"},
    8880: {"service": "HTTP-Alt5", "desc": "Web Server / Router Web", "cat": "web"},
    9000: {"service": "Portainer / Web", "desc": "Giao diện quản trị Docker Portainer / SonarQube", "cat": "web"},
    9443: {"service": "HTTPS-Alt2", "desc": "Trang quản trị bảo mật phụ", "cat": "web"},
    10000: {"service": "Webmin", "desc": "Trang quản trị máy chủ Linux Webmin", "cat": "admin"},

    # 2. Camera An Ninh & Luồng Video Thời Gian Thực
    554: {"service": "RTSP", "desc": "CAMERA AN NINH (Luồng phát Video trực tiếp H.264/H.265)", "cat": "camera"},
    8554: {"service": "RTSP-Alt", "desc": "Luồng phát video phụ của camera mini", "cat": "camera"},
    37777: {"service": "Dahua-Media", "desc": "Cổng truyền luồng video độc quyền Dahua / Imou", "cat": "camera"},
    34567: {"service": "XMeye-Media", "desc": "Cổng truyền luồng video độc quyền Xiongmai / Yoosee", "cat": "camera"},
    8899: {"service": "ONVIF-API", "desc": "Cổng chuẩn giao tiếp mở camera IP quốc tế (ONVIF)", "cat": "camera"},
    1935: {"service": "RTMP", "desc": "Giao thức truyền phát video trực tiếp RTMP", "cat": "camera"},
    5540: {"service": "RTSP-Custom", "desc": "Cổng video RTSP tùy chỉnh", "cat": "camera"},

    # 3. Chia Sẻ Tệp & Lưu Trữ Mạng (NAS / File Sharing)
    445: {"service": "SMB", "desc": "CHIA SẺ Ổ ĐĨA MẠNG WINDOWS (File & Folder Sharing)", "cat": "share"},
    139: {"service": "NetBIOS", "desc": "Dịch vụ chia sẻ tệp NetBIOS Windows cũ", "cat": "share"},
    21: {"service": "FTP", "desc": "Máy chủ truyền nhận tệp tin (FTP)", "cat": "file"},
    20: {"service": "FTP-Data", "desc": "Cổng truyền dữ liệu FTP", "cat": "file"},
    2049: {"service": "NFS", "desc": "Chia sẻ ổ đĩa mạng Linux/Unix (NFS)", "cat": "share"},
    111: {"service": "RPCbind", "desc": "Dịch vụ ánh xạ cổng chia sẻ mạng RPC", "cat": "share"},
    873: {"service": "Rsync", "desc": "Đồng bộ hóa dữ liệu sao lưu Rsync", "cat": "file"},

    # 4. Điều Khiển Từ Xa & Quản Trị Hệ Thống (Remote Desktop & Admin)
    3389: {"service": "RDP", "desc": "ĐIỀU KHIỂN MÁY TÍNH TỪ XA (Windows Remote Desktop)", "cat": "remote"},
    22: {"service": "SSH", "desc": "Quản trị dòng lệnh máy chủ bảo mật (SSH)", "cat": "admin"},
    23: {"service": "Telnet", "desc": "Quản trị dòng lệnh không mã hóa (Rất nguy hiểm nếu mở ngoài)", "cat": "admin"},
    5900: {"service": "VNC", "desc": "Điều khiển màn hình từ xa VNC (UltraVNC/RealVNC/Mac)", "cat": "remote"},
    5901: {"service": "VNC-Display1", "desc": "Màn hình VNC phụ số 1", "cat": "remote"},
    8291: {"service": "Winbox", "desc": "Cổng quản trị Router MikroTik Winbox", "cat": "admin"},
    5985: {"service": "WinRM-HTTP", "desc": "Quản trị từ xa Windows Remote Management (HTTP)", "cat": "admin"},
    5986: {"service": "WinRM-HTTPS", "desc": "Quản trị từ xa Windows Remote Management (HTTPS)", "cat": "admin"},
    4899: {"service": "Radmin", "desc": "Phần mềm điều khiển máy tính từ xa Radmin", "cat": "remote"},

    # 5. Cơ Sở Dữ Liệu (Databases)
    3306: {"service": "MySQL / MariaDB", "desc": "Máy chủ cơ sở dữ liệu MySQL / MariaDB", "cat": "db"},
    5432: {"service": "PostgreSQL", "desc": "Máy chủ cơ sở dữ liệu PostgreSQL", "cat": "db"},
    6379: {"service": "Redis", "desc": "Bộ nhớ đệm dữ liệu siêu tốc Redis", "cat": "db"},
    27017: {"service": "MongoDB", "desc": "Cơ sở dữ liệu tài liệu MongoDB NoSQL", "cat": "db"},
    1433: {"service": "MS-SQL", "desc": "Máy chủ cơ sở dữ liệu Microsoft SQL Server", "cat": "db"},
    1521: {"service": "Oracle-DB", "desc": "Cơ sở dữ liệu doanh nghiệp Oracle Database", "cat": "db"},
    9200: {"service": "Elasticsearch", "desc": "Công cụ tìm kiếm & phân tích Elasticsearch", "cat": "db"},
    9300: {"service": "Elastic-Cluster", "desc": "Cổng giao tiếp cụm Elasticsearch Cluster", "cat": "db"},

    # 6. Truyền Phát Đa Phương Tiện (Media Servers / Smart TV / AirPlay)
    32400: {"service": "Plex Media", "desc": "Máy chủ phim & video gia đình Plex Media Server", "cat": "media"},
    8096: {"service": "Jellyfin Media", "desc": "Máy chủ xem phim mã nguồn mở Jellyfin", "cat": "media"},
    5000: {"service": "UPnP / Synology", "desc": "Dịch vụ phát media DLNA / Quản trị NAS Synology", "cat": "media"},
    5001: {"service": "Synology-HTTPS", "desc": "Quản trị bảo mật NAS Synology DSM", "cat": "media"},
    7000: {"service": "AirPlay", "desc": "Cổng truyền phát hình ảnh Apple AirPlay", "cat": "media"},

    # 7. Thiết Bị Thông Minh & Nhà Thông Minh (IoT & Smart Home)
    1883: {"service": "MQTT", "desc": "Giao thức truyền tin nhà thông minh / Hub IoT (MQTT)", "cat": "iot"},
    8883: {"service": "MQTT-SSL", "desc": "Giao thức MQTT mã hóa bảo mật", "cat": "iot"},
    8123: {"service": "Home-Assistant", "desc": "Máy chủ trung tâm nhà thông minh Home Assistant", "cat": "iot"},
    1900: {"service": "UPnP-SSDP", "desc": "Giao thức tự động nhận diện thiết bị mạng UPnP", "cat": "iot"},

    # 8. Máy In Mạng (Network Printers)
    9100: {"service": "JetDirect RAW", "desc": "Cổng in ấn trực tiếp máy in mạng (HP, Canon, Brother)", "cat": "printer"},
    631: {"service": "IPP / CUPS", "desc": "Giao thức in ấn mạng Internet Printing Protocol", "cat": "printer"},
    515: {"service": "LPD / LPR", "desc": "Dịch vụ hàng đợi máy in mạng LPD", "cat": "printer"},

    # 9. Dịch Vụ Mạng Cốt Lõi (Core Network Services)
    53: {"service": "DNS", "desc": "Máy chủ phân giải tên miền (DNS Server)", "cat": "dns"},
    67: {"service": "DHCP-Server", "desc": "Máy chủ cấp phát địa chỉ IP (DHCP)", "cat": "dns"},
    123: {"service": "NTP", "desc": "Đồng bộ hóa giờ chuẩn mạng (Network Time)", "cat": "admin"},
    161: {"service": "SNMP", "desc": "Giao thức giám sát thiết bị mạng (SNMP)", "cat": "admin"},
    389: {"service": "LDAP", "desc": "Xác thực danh bạ người dùng Active Directory", "cat": "admin"},
    636: {"service": "LDAPS", "desc": "Xác thực danh bạ bảo mật qua SSL", "cat": "admin"},

    # 10. Lập Trình & Container (Dev, Web Apps, Microservices)
    3000: {"service": "React / Node.js", "desc": "Ứng dụng Web cục bộ Node.js / React / Grafana", "cat": "web"},
    5173: {"service": "Vite Dev", "desc": "Máy chủ thử nghiệm Frontend Vite", "cat": "web"},
    4200: {"service": "Angular Dev", "desc": "Máy chủ thử nghiệm Angular", "cat": "web"},
    2375: {"service": "Docker API", "desc": "Cổng điều khiển Docker Daemon không bảo mật", "cat": "admin"},
    2376: {"service": "Docker-TLS", "desc": "Cổng điều khiển Docker Daemon bảo mật", "cat": "admin"},
    6443: {"service": "Kubernetes API", "desc": "Cổng điều khiển máy chủ cụm Kubernetes (K8s)", "cat": "admin"},
}

# Danh mục Presets cổng phổ biến
PORT_PRESETS = {
    "top30": {
        "name": "⚡ Nhanh (Top 30 cổng)",
        "desc": "Quét nhanh các cổng phổ biến nhất (Web, Cam, SMB, RDP, SSH, FTP, DNS)",
        "ports": [
            21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 554, 993, 995,
            1433, 1723, 1883, 3000, 3306, 3389, 5000, 5432, 5900, 6379,
            8000, 8080, 8443, 8888, 9100, 37777,
        ],
    },
    "top100": {
        "name": "🛡️ Mở Rộng (Top 100 cổng - Khuyên dùng)",
        "desc": "Quét toàn diện Web, Camera, Media Stream, NAS, Remote, Database, IoT",
        "ports": sorted(list(PORT_DATABASE.keys())),
    },
    "well_known_1024": {
        "name": "🔬 Toàn Bộ Cổng Chuẩn (1 - 1024)",
        "desc": "Quét sạch toàn bộ 1.024 cổng dịch vụ tiêu chuẩn theo IANA / Nmap",
        "ports": list(range(1, 1025)),
    },
}


def parse_custom_ports(text: str) -> List[int]:
    """
    Phân tích chuỗi cổng tùy chỉnh của người dùng:
    Hỗ trợ:
      - Cổng đơn: '80, 443, 8080'
      - Dải cổng: '1-100', '8000-8100'
      - Kết hợp: '80, 443, 554, 8000-8090, 37777'
    Tự động lọc trùng, giới hạn 1 - 65535, sắp xếp tăng dần.
    """
    ports: Set[int] = set()
    parts = re.split(r"[,;\s]+", text.strip())
    for part in parts:
        if not part:
            continue
        if "-" in part:
            sub = part.split("-")
            if len(sub) == 2 and sub[0].isdigit() and sub[1].isdigit():
                start = max(1, int(sub[0]))
                end = min(65535, int(sub[1]))
                if start <= end:
                    # Giới hạn tối đa 5000 cổng trong 1 lần quét để bảo vệ độ ổn định
                    if end - start > 5000:
                        end = start + 5000
                    ports.update(range(start, end + 1))
        elif part.isdigit():
            val = int(part)
            if 1 <= val <= 65535:
                ports.add(val)
    return sorted(list(ports))


def check_single_port(ip: str, port: int, timeout: float = 0.2) -> Optional[Dict[str, Any]]:
    """
    Kiểm tra 1 cổng TCP cụ thể trên địa chỉ IP.
    Trả về thông tin chi tiết nếu cổng MỞ (Open), ngược lại None.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        res = s.connect_ex((ip, port))
        if res == 0:
            port_meta = PORT_DATABASE.get(port, {
                "service": f"Cổng {port}",
                "desc": "Dịch vụ mạng tùy chỉnh / chưa xác định",
                "cat": "unknown",
            })
            info = {
                "port": port,
                "service": port_meta["service"],
                "desc": port_meta["desc"],
                "cat": port_meta["cat"],
                "banner": "",
            }

            # Thử lấy tiêu đề Web nếu là cổng HTTP/HTTPS
            web_ports = (80, 8080, 8000, 8888, 3000, 5000, 5173, 8081, 8082, 8088, 8096, 8123, 9000)
            if port in web_ports:
                info["banner"] = _grab_http_title(ip, port, is_https=False)
            elif port in (443, 8443, 9443):
                info["banner"] = _grab_http_title(ip, port, is_https=True)

            return info
    except Exception:
        pass
    finally:
        try:
            s.close()
        except Exception:
            pass
    return None


def _grab_http_title(ip: str, port: int, is_https: bool = False, timeout: float = 0.4) -> str:
    """Cố gắng đọc thẻ <title> của trang web để biết tên trang quản trị."""
    proto = "https" if is_https else "http"
    url = f"{proto}://{ip}:{port}"
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
        )
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            content = resp.read(2048).decode("utf-8", errors="ignore")
            match = re.search(r"<title[^>]*>(.*?)</title>", content, re.IGNORECASE | re.DOTALL)
            if match:
                title = match.group(1).strip()
                return title[:60]
    except Exception:
        pass
    return ""


def scan_device_ports(
    ip: str,
    ports: Optional[List[int]] = None,
    max_workers: Optional[int] = None,
    timeout: float = 0.2,
    on_port_checked: Optional[Callable[[int, int], None]] = None,
    on_port_found: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> List[Dict[str, Any]]:
    """
    Quét danh sách các cổng dịch vụ trên thiết bị IP.
    Hỗ trợ báo cáo tiến trình (on_port_checked) và hiển thị thời gian thực (on_port_found).
    """
    if ports is None:
        ports = PORT_PRESETS["top100"]["ports"]

    # Tự động điều chỉnh số luồng theo quy mô số cổng
    total = len(ports)
    if max_workers is None:
        if total <= 50:
            workers = 25
        elif total <= 200:
            workers = 50
        else:
            workers = 100
    else:
        workers = max_workers

    open_ports = []
    checked_count = 0

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_port = {executor.submit(check_single_port, ip, p, timeout): p for p in ports}
        for future in as_completed(future_to_port):
            checked_count += 1
            if on_port_checked:
                try:
                    on_port_checked(checked_count, total)
                except Exception:
                    pass

            try:
                res = future.result()
                if res:
                    open_ports.append(res)
                    if on_port_found:
                        try:
                            on_port_found(res)
                        except Exception:
                            pass
            except Exception:
                pass

    # Sắp xếp các cổng theo số cổng tăng dần
    open_ports.sort(key=lambda x: x["port"])
    return open_ports


def analyze_device_roles(open_ports: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Phân tích và nhận diện vai trò thiết bị dựa trên các cổng đang mở.
    """
    ports_num = {p["port"] for p in open_ports}

    has_camera = bool(ports_num & {554, 8554, 37777, 34567, 8899, 1935})
    has_web = bool(ports_num & {80, 443, 8080, 8000, 8443, 8888, 9000})
    has_smb = bool(ports_num & {445, 139})
    has_rdp = (3389 in ports_num)
    has_ssh = (22 in ports_num)
    has_printer = bool(ports_num & {9100, 631, 515})
    has_iot = bool(ports_num & {1883, 8883, 8123})
    has_db = bool(ports_num & {3306, 5432, 6379, 27017, 1433, 1521, 9200})
    has_media = bool(ports_num & {32400, 8096, 5000, 7000})

    roles = []
    if has_camera:
        roles.append("📷 Camera an ninh (RTSP / Media)")
    if has_rdp:
        roles.append("💻 Máy tính bật Remote Desktop (RDP)")
    if has_smb:
        roles.append("📁 Ổ đĩa chia sẻ mạng Windows (SMB)")
    if has_web:
        roles.append("🌐 Giao diện Web quản trị")
    if has_db:
        roles.append("🗄️ Máy chủ Cơ sở dữ liệu (Database)")
    if has_media:
        roles.append("🎬 Máy chủ phát Media (Plex / DLNA)")
    if has_printer:
        roles.append("🖨️ Máy in mạng (Printer)")
    if has_iot:
        roles.append("⚡ Thiết bị nhà thông minh (IoT/MQTT)")
    if has_ssh:
        roles.append("🛡️ Máy chủ Linux / Quản trị SSH")

    return {
        "has_camera": has_camera,
        "has_web": has_web,
        "has_smb": has_smb,
        "has_rdp": has_rdp,
        "has_ssh": has_ssh,
        "has_db": has_db,
        "has_media": has_media,
        "has_printer": has_printer,
        "has_iot": has_iot,
        "roles": roles,
    }
