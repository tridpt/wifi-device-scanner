"""
camera_auth_checker.py - Module Chuyên Sâu Kiểm Tra Trạng Thái Bảo Vệ Mật Khẩu Camera (Authentication Check).

Kiểm tra:
1. Cổng RTSP (554 / 8554): Gửi lệnh DESCRIBE không kèm xác thực.
   - Nếu phản hồi 401 Unauthorized -> ĐÃ BẬT MẬT KHẨU BẢO VỆ (Trích xuất Realm, Digest/Basic).
   - Nếu phản hồi 200 OK -> CẢNH BÁO: MỞ TOANG KHÔNG CẦN MẬT KHẨU!
2. Cổng Web & API (80 / 8080 / 8000 / 443):
   - Kiểm tra các luồng API (ISAPI, Onvif, Realmonitor) và ảnh Snapshot.
   - Phân biệt trang Login form (an toàn) vs luồng video công khai (nguy hiểm).
"""

import os
import sys

# Thiết lập mã hóa UTF-8 cho console Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

import socket
import urllib.request
import urllib.error
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List, Optional
import tkinter as tk
from tkinter import messagebox
import customtkinter as ctk


def check_rtsp_auth(ip: str, port: int = 554, timeout: float = 2.0) -> Dict[str, Any]:
    """
    Gửi yêu cầu RTSP DESCRIBE chuẩn tới camera mà không kèm thông tin đăng nhập.
    Kiểm tra xem camera có trả về mã 401 Unauthorized hay cho phép xem tự do (200 OK).
    """
    result = {
        "port": port,
        "is_open": False,
        "status_code": 0,
        "status_line": "",
        "auth_header": "",
        "auth_type": "Không xác định",
        "realm": "",
        "server_banner": "",
        "verdict": "closed",
        "message": "Không kết nối được tới cổng RTSP (cổng đóng hoặc quá thời gian)",
    }

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        result["is_open"] = True

        # Gửi gói tin RTSP DESCRIBE chuẩn mực
        req = (
            f"DESCRIBE rtsp://{ip}:{port}/ RTSP/1.0\r\n"
            f"CSeq: 1\r\n"
            f"User-Agent: CamSecurityAuditor/1.0\r\n"
            f"Accept: application/sdp\r\n\r\n"
        )
        sock.sendall(req.encode("ascii", errors="ignore"))

        response_raw = sock.recv(4096).decode("latin1", errors="ignore")
        sock.close()

        if not response_raw:
            result["verdict"] = "no_response"
            result["message"] = "Cổng RTSP mở nhưng không phản hồi gói tin DESCRIBE."
            return result

        lines = response_raw.split("\r\n")
        result["status_line"] = lines[0] if lines else ""

        # Bóc tách mã trạng thái (status code)
        match_code = re.search(r"RTSP/\d\.\d\s+(\d+)", result["status_line"])
        if match_code:
            result["status_code"] = int(match_code.group(1))

        # Tìm header Server và WWW-Authenticate
        for line in lines:
            lower = line.lower()
            if lower.startswith("server:"):
                result["server_banner"] = line[7:].strip()
            elif lower.startswith("www-authenticate:"):
                result["auth_header"] = line[17:].strip()
                if "digest" in lower:
                    result["auth_type"] = "Digest (Mã hóa cao cấp)"
                elif "basic" in lower:
                    result["auth_type"] = "Basic (Văn bản mã hóa base64)"

                # Trích xuất Realm (thường chứa tên model camera)
                realm_m = re.search(r'realm=[\'"]([^\'"]+)[\'"]', line, re.I)
                if realm_m:
                    result["realm"] = realm_m.group(1)

        # Đánh giá kết quả
        code = result["status_code"]
        if code == 401:
            result["verdict"] = "protected"
            realm_info = f" (Thiết bị: {result['realm']})" if result["realm"] else ""
            result["message"] = f"🔒 TỐT: Luồng RTSP đã được BẢO VỆ BẰNG MẬT KHẨU (401 Unauthorized){realm_info}."
        elif code == 200:
            result["verdict"] = "vulnerable"
            result["message"] = "🚨 NGUY CƠ CAO: Luồng RTSP MỞ TOANG (200 OK)! Bất kỳ ai cũng có thể xem trực tiếp không cần mật khẩu!"
        elif code in (403, 404):
            result["verdict"] = "protected"
            result["message"] = f"🔒 Luồng RTSP từ chối truy cập (Mã {code}). Luồng đã được bảo vệ."
        else:
            result["verdict"] = "unknown"
            result["message"] = f"Phản hồi RTSP mã {code}: {result['status_line']}"

    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        result["is_open"] = False
        result["verdict"] = "closed"
        result["message"] = f"Cổng RTSP không phản hồi ({e})."

    return result


def check_web_auth(ip: str, port: int = 80, timeout: float = 2.0) -> Dict[str, Any]:
    """
    Kiểm tra cổng Web (80, 8080, 8000) và các API/Snapshot của camera xem có yêu cầu đăng nhập không.
    """
    result = {
        "port": port,
        "is_open": False,
        "status_code": 0,
        "server_banner": "",
        "auth_header": "",
        "realm": "",
        "is_login_page": False,
        "has_open_snapshot": False,
        "verdict": "closed",
        "message": f"Cổng Web ({port}) không phản hồi.",
    }

    # 1. Thử truy cập root /
    url_root = f"http://{ip}:{port}/"
    try:
        req = urllib.request.Request(
            url_root,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            result["is_open"] = True
            result["status_code"] = resp.status
            result["server_banner"] = resp.headers.get("Server", "")

            body_preview = resp.read(2048).decode("utf-8", errors="ignore").lower()
            if any(k in body_preview for k in ("login", "password", "username", "doc/index.html", "userlogin", "auth")):
                result["is_login_page"] = True

    except urllib.error.HTTPError as e:
        result["is_open"] = True
        result["status_code"] = e.code
        result["server_banner"] = e.headers.get("Server", "")
        auth_hdr = e.headers.get("WWW-Authenticate", "")
        if auth_hdr:
            result["auth_header"] = auth_hdr
            realm_m = re.search(r'realm=[\'"]([^\'"]+)[\'"]', auth_hdr, re.I)
            if realm_m:
                result["realm"] = realm_m.group(1)

    except (urllib.error.URLError, OSError):
        return result

    # 2. Kiểm tra thêm các endpoint API và snapshot nhạy cảm
    sensitive_paths = [
        "/ISAPI/Streaming/channels/101",
        "/ISAPI/System/deviceInfo",
        "/snapshot.jpg",
        "/webcapture.jpg?command=snap&channel=1",
        "/cgi-bin/snapshot.cgi",
    ]

    api_requires_auth = False
    open_snapshot_url = None

    for path in sensitive_paths:
        test_url = f"http://{ip}:{port}{path}"
        try:
            req_api = urllib.request.Request(
                test_url,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
            )
            with urllib.request.urlopen(req_api, timeout=1.0) as r_api:
                c_type = r_api.headers.get("Content-Type", "").lower()
                data = r_api.read(256)
                # Nếu tải được file ảnh JPEG/PNG trực tiếp không cần mật khẩu
                if "image" in c_type or data.startswith(b"\xff\xd8\xff") or data.startswith(b"\x89PNG"):
                    open_snapshot_url = test_url
                    result["has_open_snapshot"] = True
                    break
        except urllib.error.HTTPError as e_api:
            if e_api.code in (401, 403):
                api_requires_auth = True
                if not result["realm"]:
                    auth_hdr = e_api.headers.get("WWW-Authenticate", "")
                    realm_m = re.search(r'realm=[\'"]([^\'"]+)[\'"]', auth_hdr, re.I)
                    if realm_m:
                        result["realm"] = realm_m.group(1)
        except Exception:
            pass

    # 3. Đưa ra kết luận cho cổng Web
    if result["has_open_snapshot"]:
        result["verdict"] = "vulnerable"
        result["message"] = f"🚨 NGUY HIỂM: Endpoint ảnh ({open_snapshot_url}) MỞ CÔNG KHAI không cần mật khẩu!"
    elif result["status_code"] in (401, 403) or api_requires_auth:
        result["verdict"] = "protected"
        realm_str = f" (Thiết bị: {result['realm']})" if result["realm"] else ""
        result["message"] = f"🔒 TỐT: Cổng Web/API yêu cầu mật khẩu xác thực (401 Unauthorized){realm_str}."
    elif result["status_code"] == 200 and result["is_login_page"]:
        result["verdict"] = "protected"
        result["message"] = "🔒 TỐT: Trang đăng nhập (Login Portal) yêu cầu tài khoản/mật khẩu mới được vào quản trị."
    elif result["status_code"] == 200:
        result["verdict"] = "suspicious"
        result["message"] = "⚠️ Cổng Web phản hồi 200 OK nhưng chưa xác định được cơ chế khóa mật khẩu."
    else:
        result["verdict"] = "unknown"
        result["message"] = f"Cổng Web phản hồi mã {result['status_code']}."

    return result


def audit_camera_security_posture(
    ip: str,
    web_ports: Optional[List[int]] = None,
    rtsp_ports: Optional[List[int]] = None,
    timeout: float = 2.0,
) -> Dict[str, Any]:
    """
    Hàm tổng kiểm tra toàn diện trạng thái bảo vệ mật khẩu của một camera IP.
    Kiểm tra đồng thời cả cổng Web (80, 8080) và RTSP (554) trên các luồng đa nhiệm.
    """
    if web_ports is None:
        web_ports = [80, 8080, 8000]
    if rtsp_ports is None:
        rtsp_ports = [554]

    report = {
        "ip": ip,
        "rtsp_results": [],
        "web_results": [],
        "overall_status": "unknown",
        "badge_text": "",
        "badge_color": ("#6B7280", "#9CA3AF"),
        "summary": "",
        "recommendation": "",
        "device_hint": "",
    }

    # Quét đồng thời các cổng
    with ThreadPoolExecutor(max_workers=6) as executor:
        rtsp_futures = {executor.submit(check_rtsp_auth, ip, p, timeout): p for p in rtsp_ports}
        web_futures = {executor.submit(check_web_auth, ip, p, timeout): p for p in web_ports}

        for f in as_completed(rtsp_futures):
            report["rtsp_results"].append(f.result())

        for f in as_completed(web_futures):
            report["web_results"].append(f.result())

    # Thu thập gợi ý thiết bị (Realm, Server banner)
    for r in report["rtsp_results"] + report["web_results"]:
        if r.get("realm") and not report["device_hint"]:
            report["device_hint"] = r["realm"]
        elif r.get("server_banner") and not report["device_hint"]:
            report["device_hint"] = r["server_banner"]

    # Đánh giá tổng quan
    has_vulnerable = any(
        r.get("verdict") == "vulnerable" for r in report["rtsp_results"] + report["web_results"]
    )
    has_protected_rtsp = any(
        r.get("verdict") == "protected" for r in report["rtsp_results"]
    )
    has_protected_web = any(
        r.get("verdict") == "protected" for r in report["web_results"]
    )

    if has_vulnerable:
        report["overall_status"] = "vulnerable"
        report["badge_text"] = "🚨 CẢNH BÁO: CAMERA MỞ TOANG (KHÔNG CẦN MẬT KHẨU)"
        report["badge_color"] = ("#DC2626", "#EF4444")
        report["summary"] = "Phát hiện luồng video RTSP hoặc ảnh chụp Snapshot của camera đang mở công khai. Bất kỳ ai trong cùng mạng Wi-Fi đều có thể xem trực tiếp hình ảnh mà không cần đăng nhập!"
        report["recommendation"] = "Cần đăng nhập vào trang quản trị camera ngay lập tức và bật mật khẩu bảo vệ (Authentication / Password Protection)."
    elif has_protected_rtsp or has_protected_web:
        report["overall_status"] = "protected"
        report["badge_text"] = "🟢 ĐÃ BẬT MẬT KHẨU BẢO VỆ (401 UNAUTHORIZED)"
        report["badge_color"] = ("#16A34A", "#22C55E")
        report["summary"] = "Camera này đã được cài mật khẩu bảo vệ chặt chẽ (Phản hồi 401 Unauthorized khi không có tài khoản). Người lạ trong mạng Wi-Fi KHÔNG THỂ tự ý xem trộm luồng hình ảnh của camera này."
        report["recommendation"] = "Trạng thái rất tốt! Camera đang được khóa bảo vệ an toàn."
    else:
        report["overall_status"] = "closed"
        report["badge_text"] = "⚪ KHÔNG PHẢN HỒI / CỔNG ĐÓNG"
        report["badge_color"] = ("#6B7280", "#9CA3AF")
        report["summary"] = "Các cổng RTSP (554) và Web (80/8080) không phản hồi hoặc đã bị đóng."
        report["recommendation"] = "Kiểm tra xem camera có đang bật nguồn hoặc sử dụng cổng tùy chỉnh khác không."

    return report


class CameraAuthWindow(ctk.CTkToplevel):
    """Cửa sổ trực quan chuyên biệt kiểm tra trạng thái bảo vệ mật khẩu của Camera."""

    def __init__(self, master, device_data: dict):
        super().__init__(master)
        self.device = device_data
        self.ip = device_data.get("ip", "")
        self.mac = device_data.get("mac", "")
        self.vendor = device_data.get("vendor", "Chưa rõ")
        self.name = device_data.get("name", "Camera")

        self.title(f"🛡️ Kiểm Tra Bảo Vệ Mật Khẩu Camera - {self.ip}")
        self.geometry("680x600")
        self.minsize(620, 520)

        self.transient(master)
        self.after(50, self.lift)

        self._build_ui()
        # Tự động bắt đầu kiểm tra sau 300ms
        self.after(300, self._start_audit)

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)

        # 1. Header Card
        hdr = ctk.CTkFrame(self, fg_color=("#F0FDF4", "#064E3B"), border_width=1, border_color="#10B981", corner_radius=8)
        hdr.grid(row=0, column=0, padx=16, pady=(14, 10), sticky="ew")
        hdr.grid_columnconfigure(1, weight=1)

        lbl_icon = ctk.CTkLabel(hdr, text="🛡️", font=ctk.CTkFont(size=28), width=45)
        lbl_icon.grid(row=0, column=0, rowspan=2, padx=(12, 8), pady=10)

        ctk.CTkLabel(
            hdr,
            text="KIỂM TRA TRẠNG THÁI BẢO VỆ MẬT KHẨU (AUTHENTICATION AUDIT)",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=("#047857", "#A7F3D0"),
            anchor="w",
        ).grid(row=0, column=1, padx=4, pady=(8, 2), sticky="w")

        sub_info = f"IP: {self.ip}   •   MAC: {self.mac}   •   Hãng: {self.vendor}"
        ctk.CTkLabel(
            hdr,
            text=sub_info,
            font=ctk.CTkFont(size=11),
            text_color=("#065F46", "#6EE7B7"),
            anchor="w",
        ).grid(row=1, column=1, padx=4, pady=(0, 8), sticky="w")

        # 2. Main Status Card (Hiển thị kết quả đánh giá to rõ)
        self.card_status = ctk.CTkFrame(self, fg_color=("#FFFFFF", "#1E293B"), corner_radius=8)
        self.card_status.grid(row=1, column=0, padx=16, pady=(0, 10), sticky="ew")
        self.card_status.grid_columnconfigure(0, weight=1)

        # Badge kết quả
        self.badge_frame = ctk.CTkFrame(self.card_status, fg_color=("#E5E7EB", "#334155"), corner_radius=6)
        self.badge_frame.pack(padx=16, pady=(14, 8), fill="x")

        self.lbl_badge = ctk.CTkLabel(
            self.badge_frame,
            text="⏳ Đang gửi yêu cầu kiểm tra tới cổng RTSP (554) và Web (80/8080)...",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=("#1F2937", "#F3F4F6"),
            pady=8,
        )
        self.lbl_badge.pack()

        # Tóm tắt kết quả
        self.lbl_summary = ctk.CTkLabel(
            self.card_status,
            text="Đang kết nối thử nghiệm để kiểm tra xem camera có trả về mã 401 Unauthorized hay mở toang 200 OK...",
            font=ctk.CTkFont(size=12),
            text_color=("#4B5563", "#94A3B8"),
            wraplength=620,
            justify="left",
        )
        self.lbl_summary.pack(padx=16, pady=(0, 8), anchor="w")

        # Khuyến nghị
        self.lbl_rec = ctk.CTkLabel(
            self.card_status,
            text="",
            font=ctk.CTkFont(size=11, slant="italic"),
            text_color=("#059669", "#34D399"),
            wraplength=620,
            justify="left",
        )
        self.lbl_rec.pack(padx=16, pady=(0, 12), anchor="w")

        # 3. Technical Breakdown Card (Chi tiết từng cổng phản hồi)
        tech_card = ctk.CTkFrame(self, fg_color=("#FFFFFF", "#1E293B"), corner_radius=8)
        tech_card.grid(row=2, column=0, padx=16, pady=(0, 12), sticky="nsew")
        self.grid_rowconfigure(2, weight=1)
        tech_card.grid_columnconfigure(0, weight=1)
        tech_card.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(
            tech_card,
            text="📋 CHI TIẾT PHẢN HỒI KỸ THUẬT TỪ CÁC CỔNG DỊCH VỤ:",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=("#6B7280", "#94A3B8"),
        ).grid(row=0, column=0, padx=14, pady=(10, 6), sticky="w")

        self.box_details = ctk.CTkTextbox(
            tech_card,
            font=ctk.CTkFont(family="Consolas", size=11),
            fg_color=("#F8FAFC", "#0F172A"),
            text_color=("#1E293B", "#F1F5F9"),
            corner_radius=6,
        )
        self.box_details.grid(row=1, column=0, padx=14, pady=(0, 12), sticky="nsew")
        self.box_details.insert("1.0", "Đang thu thập thông tin các cổng...")
        self.box_details.configure(state="disabled")

        # 4. Action Bar (Nút thao tác dưới cùng)
        act_bar = ctk.CTkFrame(self, fg_color="transparent")
        act_bar.grid(row=3, column=0, padx=16, pady=(0, 14), sticky="ew")

        self.btn_recheck = ctk.CTkButton(
            act_bar,
            text="🔄 Quét Kiểm Tra Lại",
            width=150,
            height=34,
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#0284C7",
            hover_color="#0369A1",
            command=self._start_audit,
        )
        self.btn_recheck.pack(side="left", padx=(0, 8))

        btn_stream = ctk.CTkButton(
            act_bar,
            text="📺 Mở Trình Soi Luồng Cam",
            width=180,
            height=34,
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#7C3AED",
            hover_color="#6D28D9",
            command=self._open_streamer,
        )
        btn_stream.pack(side="left", padx=4)

        btn_web = ctk.CTkButton(
            act_bar,
            text="🌐 Mở Web Quản Trị",
            width=140,
            height=34,
            font=ctk.CTkFont(size=12),
            fg_color=("#E5E7EB", "#334155"),
            text_color=("#1F2937", "#F3F4F6"),
            hover_color=("#D1D5DB", "#475569"),
            command=self._open_web,
        )
        btn_web.pack(side="left", padx=4)

        btn_close = ctk.CTkButton(
            act_bar,
            text="Đóng",
            width=80,
            height=34,
            font=ctk.CTkFont(size=12),
            fg_color=("#E5E7EB", "#334155"),
            text_color=("#1F2937", "#F3F4F6"),
            hover_color=("#D1D5DB", "#475569"),
            command=self.destroy,
        )
        btn_close.pack(side="right")

    def _start_audit(self):
        self.btn_recheck.configure(state="disabled", text="⏳ Đang kiểm tra...")
        self.lbl_badge.configure(text="⏳ Đang kết nối gửi yêu cầu kiểm tra cổng RTSP 554 và Web 80/8080...")
        self.badge_frame.configure(fg_color=("#E5E7EB", "#334155"))
        self.lbl_badge.configure(text_color=("#1F2937", "#F3F4F6"))

        import threading

        def worker():
            report = audit_camera_security_posture(self.ip, web_ports=[80, 8080, 8000], rtsp_ports=[554])
            self.after(0, lambda: self._on_audit_finished(report))

        threading.Thread(target=worker, daemon=True).start()

    def _on_audit_finished(self, report: dict):
        self.btn_recheck.configure(state="normal", text="🔄 Quét Kiểm Tra Lại")

        # Cập nhật Badge
        status = report.get("overall_status", "unknown")
        badge_text = report.get("badge_text", "")
        self.lbl_badge.configure(text=badge_text)

        if status == "protected":
            self.badge_frame.configure(fg_color=("#DCFCE7", "#14532D"))
            self.lbl_badge.configure(text_color=("#15803D", "#4ADE80"))
        elif status == "vulnerable":
            self.badge_frame.configure(fg_color=("#FEE2E2", "#7F1D1D"))
            self.lbl_badge.configure(text_color=("#B91C1C", "#F87171"))
        else:
            self.badge_frame.configure(fg_color=("#F3F4F6", "#374151"))
            self.lbl_badge.configure(text_color=("#4B5563", "#D1D5DB"))

        # Cập nhật tóm tắt & khuyến nghị
        self.lbl_summary.configure(text=report.get("summary", ""))
        self.lbl_rec.configure(text=f"💡 Khuyến nghị: {report.get('recommendation', '')}")

        # Cập nhật Textbox chi tiết kỹ thuật
        lines = []
        lines.append(f"=== KẾT QUẢ KIỂM TRA BẢO VỆ MẬT KHẨU CAMERA {self.ip} ===")
        if report.get("device_hint"):
            lines.append(f"🏷️ Dấu vết nhận diện thiết bị (Realm/Banner): {report['device_hint']}\n")

        lines.append("[1] LUỒNG VIDEO RTSP (Cổng 554):")
        for r in report.get("rtsp_results", []):
            p = r.get("port")
            if r.get("is_open"):
                lines.append(f"  • Cổng {p}: ĐANG MỞ (Phản hồi: {r.get('status_line', '')})")
                lines.append(f"    - Cơ chế xác thực: {r.get('auth_type', 'Không rõ')}")
                if r.get("realm"):
                    lines.append(f"    - Định danh Realm: {r['realm']}")
                lines.append(f"    - Đánh giá: {r.get('message', '')}")
            else:
                lines.append(f"  • Cổng {p}: {r.get('message', 'Không kết nối được')}")

        lines.append("\n[2] GIAO DIỆN WEB & API HÌNH ẢNH (Cổng 80, 8080, 8000):")
        for w in report.get("web_results", []):
            p = w.get("port")
            if w.get("is_open"):
                lines.append(f"  • Cổng {p}: ĐANG MỞ (HTTP {w.get('status_code')})")
                if w.get("server_banner"):
                    lines.append(f"    - Server Banner: {w['server_banner']}")
                if w.get("realm"):
                    lines.append(f"    - Realm: {w['realm']}")
                lines.append(f"    - Đánh giá: {w.get('message', '')}")
            else:
                lines.append(f"  • Cổng {p}: Đóng hoặc không phản hồi.")

        lines.append("\n[3] KẾT LUẬN TỰ VỆ:")
        if status == "protected":
            lines.append("  ==> Camera NÀY ĐÃ ĐƯỢC BẢO VỆ BẰNG MẬT KHẨU CHẶT CHẼ.")
            lines.append("  ==> Luồng video trực tiếp KHÔNG THỂ bị xem lén nếu kẻ xấu không có mật khẩu.")
        elif status == "vulnerable":
            lines.append("  ==> CẢNH BÁO NGUY HIỂM: Camera này có luồng video hoặc ảnh mở toang.")
            lines.append("  ==> Bất kỳ ai trong Wi-Fi đều có thể trích xuất hình ảnh mà không cần pass!")
        else:
            lines.append("  ==> Không phát hiện cổng luồng video mở công khai.")

        full_text = "\n".join(lines)
        self.box_details.configure(state="normal")
        self.box_details.delete("1.0", "end")
        self.box_details.insert("1.0", full_text)
        self.box_details.configure(state="disabled")

    def _open_streamer(self):
        from camera_streamer import CameraStreamWindow
        CameraStreamWindow(self.master, self.device, initial_port=554)

    def _open_web(self):
        import webbrowser
        webbrowser.open(f"http://{self.ip}")


if __name__ == "__main__":
    import json
    test_ip = "192.168.1.211"
    print(f"Kiểm tra bảo vệ mật khẩu trên IP: {test_ip}")
    res = audit_camera_security_posture(test_ip)
    print(json.dumps(res, indent=2, ensure_ascii=False))
