"""
camera_streamer.py - Module Soi & Xem Trực Tiếp Luồng Video Camera (RTSP / VLC / Snapshot).
Cho phép dò tìm URL luồng video của các hãng camera phổ biến (Hikvision, Dahua, Yoosee, Tuya, Tapo...),
tự động khởi chạy xem trực tiếp bằng VLC Media Player với độ trễ thấp (low caching),
và thử chụp ảnh tức thời (Snapshot) qua giao diện Web của camera.
"""

import os
import sys
import shutil
import subprocess
import urllib.request
import urllib.error
import io
import time
from typing import Optional, Dict, Any, List, Tuple
import tkinter as tk
from tkinter import messagebox
import customtkinter as ctk

try:
    from PIL import Image
except ImportError:
    Image = None

# Danh mục các mẫu URL luồng RTSP phổ biến theo từng hãng camera
CAMERA_STREAM_PRESETS: List[Dict[str, str]] = [
    {
        "id": "generic_root",
        "brand": "Mặc định (Generic RTSP)",
        "name": "Luồng gốc mặc định (/)",
        "path": "/",
        "desc": "Đường dẫn RTSP tiêu chuẩn mở, thường gặp ở các camera mini OEM hoặc máy tính phát stream.",
    },
    {
        "id": "hikvision_main",
        "brand": "Hikvision / EZVIZ",
        "name": "Kênh 1 - Luồng chính sắc nét (101)",
        "path": "/Streaming/Channels/101",
        "desc": "Luồng video Full HD / 2K chính của camera Hikvision và camera gia đình EZVIZ.",
    },
    {
        "id": "hikvision_sub",
        "brand": "Hikvision / EZVIZ",
        "name": "Kênh 1 - Luồng phụ mượt mà (102)",
        "path": "/Streaming/Channels/102",
        "desc": "Luồng video phụ độ phân giải vừa phải, tải cực nhanh và không bị giật lag.",
    },
    {
        "id": "dahua_main",
        "brand": "Dahua / Imou",
        "name": "Kênh 1 - Mainstream (Độ phân giải cao)",
        "path": "/cam/realmonitor?channel=1&subtype=0",
        "desc": "Đường dẫn truyền video tiêu chuẩn của camera Dahua, Imou và Lechange.",
    },
    {
        "id": "dahua_sub",
        "brand": "Dahua / Imou",
        "name": "Kênh 1 - Substream (Xem nhanh)",
        "path": "/cam/realmonitor?channel=1&subtype=1",
        "desc": "Luồng phụ độ trễ thấp của camera Dahua / Imou.",
    },
    {
        "id": "yoosee_onvif",
        "brand": "Yoosee / Vstarcam / Xiongmai",
        "name": "Luồng ONVIF 1 (/onvif1)",
        "path": "/onvif1",
        "desc": "Đường dẫn RTSP phổ biến nhất trên camera 3 râu Yoosee, camera bóng đèn, camera báo khói.",
    },
    {
        "id": "yoosee_ch0",
        "brand": "Yoosee / Xiongmai (XMeye)",
        "name": "Kênh 0 trực tiếp (/live/ch0)",
        "path": "/live/ch0",
        "desc": "Đường dẫn luồng video trực tiếp của bo mạch Xiongmai (XMeye).",
    },
    {
        "id": "tuya_mini",
        "brand": "Tuya Smart / Cam Ngụy Trang",
        "name": "Luồng H.264 Preview (/h264Preview_01_main)",
        "path": "/h264Preview_01_main",
        "desc": "Đường dẫn camera ngụy trang siêu nhỏ chạy nền tảng chip Tuya hoặc Allwinner.",
    },
    {
        "id": "tapo_stream1",
        "brand": "TP-Link Tapo",
        "name": "Luồng chính Tapo (/stream1)",
        "path": "/stream1",
        "desc": "Luồng video RTSP chính của dòng camera TP-Link Tapo C200, C210, TC70...",
    },
    {
        "id": "tapo_stream2",
        "brand": "TP-Link Tapo",
        "name": "Luồng phụ Tapo (/stream2)",
        "path": "/stream2",
        "desc": "Luồng phụ tiết kiệm băng thông của camera TP-Link Tapo.",
    },
]

# Các endpoint chụp ảnh snapshot thường gặp
SNAPSHOT_PATHS = [
    "/snapshot.jpg",
    "/webcapture.jpg?command=snap&channel=1",
    "/cgi-bin/snapshot.cgi",
    "/image.jpg",
    "/jpg/image.jpg",
    "/onvif/snapshot",
    "/tmpfs/auto.jpg",
    "/cgi-bin/viewer/video.jpg",
]


def find_vlc_executable() -> Optional[str]:
    """Tìm đường dẫn tệp thực thi VLC Media Player trên Windows."""
    # 1. Kiểm tra các đường dẫn cài đặt chuẩn của Windows
    candidates = [
        r"C:\Program Files\VideoLAN\VLC\vlc.exe",
        r"C:\Program Files (x86)\VideoLAN\VLC\vlc.exe",
        os.path.expandvars(r"%ProgramFiles%\VideoLAN\VLC\vlc.exe"),
        os.path.expandvars(r"%ProgramFiles(x86)%\VideoLAN\VLC\vlc.exe"),
        os.path.expandvars(r"%LocalAppData%\VideoLAN\VLC\vlc.exe"),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c

    # 2. Kiểm tra biến môi trường PATH
    which_vlc = shutil.which("vlc")
    if which_vlc and os.path.isfile(which_vlc):
        return which_vlc

    return None


def build_rtsp_url(ip: str, port: int = 554, path: str = "/", user: str = "", password: str = "") -> str:
    """Ghép chuỗi URL RTSP hoàn chỉnh kèm thông tin xác thực nếu có."""
    clean_path = path.strip()
    if not clean_path.startswith("/"):
        clean_path = "/" + clean_path

    port_str = f":{port}" if port and port != 554 else ""

    if user:
        if password:
            auth_str = f"{user}:{password}@"
        else:
            auth_str = f"{user}@"
    else:
        auth_str = ""

    return f"rtsp://{auth_str}{ip}{port_str}{clean_path}"


def launch_vlc_stream(rtsp_url: str, caching_ms: int = 300) -> Tuple[bool, str]:
    """Khởi chạy VLC Media Player để xem trực tiếp luồng RTSP."""
    vlc_bin = find_vlc_executable()
    if not vlc_bin:
        return False, "Không tìm thấy phần mềm VLC Media Player trên máy tính.\nVui lòng tải và cài đặt VLC từ trang web chính thức (videolan.org)."

    try:
        cmd = [
            vlc_bin,
            rtsp_url,
            f"--network-caching={caching_ms}",
            "--no-video-title-show",
            "--play-and-exit",
        ]
        subprocess.Popen(cmd)
        return True, f"Đã khởi động VLC Media Player đang kết nối luồng:\n{rtsp_url}"
    except Exception as e:
        return False, f"Lỗi khi khởi chạy VLC: {e}"


def try_grab_snapshot(
    ip: str,
    web_port: int = 80,
    user: str = "",
    password: str = "",
    timeout_sec: float = 1.2,
) -> Optional[Tuple[bytes, str]]:
    """
    Thử chụp 1 khung ảnh tĩnh (Snapshot) từ các endpoint HTTP quen thuộc của camera.
    Trả về (image_bytes, url_used) nếu thành công, ngược lại None.
    """
    for path in SNAPSHOT_PATHS:
        url = f"http://{ip}:{web_port}{path}"
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
            )

            # Xử lý Basic Authentication nếu có
            if user:
                import base64
                auth_str = base64.b64encode(f"{user}:{password}".encode()).decode("ascii")
                req.add_header("Authorization", f"Basic {auth_str}")

            with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
                data = resp.read()
                # Kiểm tra định dạng ảnh (JPEG hoặc PNG)
                if data and (data.startswith(b"\xff\xd8\xff") or data.startswith(b"\x89PNG")):
                    return data, url
        except Exception:
            continue
    return None


class CameraStreamWindow(ctk.CTkToplevel):
    """Cửa sổ chuyên sâu Soi & Xem Trực Tiếp Luồng Video Camera."""

    def __init__(self, master, device_data: dict, initial_port: int = 554):
        super().__init__(master)
        self.device = device_data
        self.ip = device_data.get("ip", "")
        self.mac = device_data.get("mac", "")
        self.vendor = device_data.get("vendor", "Chưa rõ")
        self.name = device_data.get("name", "Camera")
        self.port = initial_port

        self.title(f"📺 Soi & Xem Luồng Video Camera - {self.ip} ({self.vendor})")
        self.geometry("780x700")
        self.minsize(680, 580)

        self.transient(master)
        self.after(50, self.lift)

        self.vlc_path = find_vlc_executable()
        self.current_snapshot_img = None

        self._build_ui()
        self._auto_select_brand_preset()

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)

        # 1. Header Card (Tím / Indigo hiện đại)
        header_card = ctk.CTkFrame(self, fg_color=("#F5F3FF", "#1E1738"), border_width=1, border_color="#8B5CF6", corner_radius=8)
        header_card.grid(row=0, column=0, padx=16, pady=(12, 8), sticky="ew")
        header_card.grid_columnconfigure(1, weight=1)

        lbl_icon = ctk.CTkLabel(header_card, text="📹", font=ctk.CTkFont(size=28), width=45)
        lbl_icon.grid(row=0, column=0, rowspan=2, padx=(12, 8), pady=10)

        lbl_t = ctk.CTkLabel(
            header_card,
            text=f"TRÌNH SOI & XEM TRỰC TIẾP LUỒNG VIDEO CAMERA",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=("#6D28D9", "#C4B5FD"),
            anchor="w",
        )
        lbl_t.grid(row=0, column=1, padx=4, pady=(8, 2), sticky="w")

        vlc_badge = "✅ Đã tìm thấy VLC Media Player trên máy" if self.vlc_path else "⚠️ Chưa cài đặt VLC Player"
        sub_info = f"IP: {self.ip}   •   MAC: {self.mac}   •   Hãng: {self.vendor}   •   {vlc_badge}"
        lbl_sub = ctk.CTkLabel(
            header_card,
            text=sub_info,
            font=ctk.CTkFont(size=11),
            text_color=("#4C1D95", "#DDD6FE"),
            anchor="w",
        )
        lbl_sub.grid(row=1, column=1, padx=4, pady=(0, 8), sticky="w")

        # 2. Hộp cấu hình Luồng RTSP (RTSP Stream Config Box)
        cfg_box = ctk.CTkFrame(self, fg_color=("#FFFFFF", "#1E293B"), corner_radius=8)
        cfg_box.grid(row=1, column=0, padx=16, pady=(0, 8), sticky="ew")
        cfg_box.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            cfg_box,
            text="⚙️ CẤU HÌNH ĐƯỜNG DẪN LUỒNG VIDEO (RTSP):",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=("#6B7280", "#94A3B8"),
        ).grid(row=0, column=0, columnspan=2, padx=14, pady=(10, 6), sticky="w")

        # Preset Dropdown
        ctk.CTkLabel(cfg_box, text="Dòng Camera / Mẫu Luồng:", font=ctk.CTkFont(size=12, weight="bold")).grid(row=1, column=0, padx=(14, 8), pady=4, sticky="w")
        preset_names = [f"{p['brand']} — {p['name']}" for p in CAMERA_STREAM_PRESETS]
        self.opt_preset = ctk.CTkOptionMenu(
            cfg_box,
            values=preset_names,
            command=self._on_select_preset,
            height=30,
            font=ctk.CTkFont(size=12),
        )
        self.opt_preset.grid(row=1, column=1, padx=(0, 14), pady=4, sticky="ew")
        self.opt_preset.set(preset_names[0])

        # Mô tả preset
        self.lbl_preset_desc = ctk.CTkLabel(
            cfg_box,
            text=CAMERA_STREAM_PRESETS[0]["desc"],
            font=ctk.CTkFont(size=11),
            text_color=("#6B7280", "#94A3B8"),
            anchor="w",
        )
        self.lbl_preset_desc.grid(row=2, column=1, padx=(0, 14), pady=(0, 6), sticky="w")

        # Ô nhập Path tùy chỉnh
        ctk.CTkLabel(cfg_box, text="Đường dẫn Stream (Path):", font=ctk.CTkFont(size=12)).grid(row=3, column=0, padx=(14, 8), pady=4, sticky="w")
        self.entry_path = ctk.CTkEntry(cfg_box, height=30, font=ctk.CTkFont(family="Consolas", size=12))
        self.entry_path.grid(row=3, column=1, padx=(0, 14), pady=4, sticky="ew")
        self.entry_path.insert(0, CAMERA_STREAM_PRESETS[0]["path"])
        self.entry_path.bind("<KeyRelease>", lambda e: self._update_full_url())

        # Cổng RTSP
        ctk.CTkLabel(cfg_box, text="Cổng RTSP:", font=ctk.CTkFont(size=12)).grid(row=4, column=0, padx=(14, 8), pady=4, sticky="w")
        self.entry_port = ctk.CTkEntry(cfg_box, height=30, width=100, font=ctk.CTkFont(family="Consolas", size=12))
        self.entry_port.grid(row=4, column=1, padx=(0, 14), pady=4, sticky="w")
        self.entry_port.insert(0, str(self.port))
        self.entry_port.bind("<KeyRelease>", lambda e: self._update_full_url())

        # Tài khoản & Mật khẩu
        auth_row = ctk.CTkFrame(cfg_box, fg_color="transparent")
        auth_row.grid(row=5, column=0, columnspan=2, padx=14, pady=4, sticky="ew")

        ctk.CTkLabel(auth_row, text="Tài khoản:", font=ctk.CTkFont(size=12)).pack(side="left", padx=(0, 4))
        self.entry_user = ctk.CTkEntry(auth_row, width=110, height=28, placeholder_text="Mặc định: để trống")
        self.entry_user.pack(side="left", padx=(0, 12))
        self.entry_user.bind("<KeyRelease>", lambda e: self._update_full_url())

        ctk.CTkLabel(auth_row, text="Mật khẩu:", font=ctk.CTkFont(size=12)).pack(side="left", padx=(0, 4))
        self.entry_pass = ctk.CTkEntry(auth_row, width=110, height=28, placeholder_text="Mật khẩu", show="•")
        self.entry_pass.pack(side="left", padx=(0, 12))
        self.entry_pass.bind("<KeyRelease>", lambda e: self._update_full_url())

        # Nút điền nhanh tài khoản phổ biến
        btn_quick_admin = ctk.CTkButton(
            auth_row,
            text="Gợi ý: admin / admin",
            width=125,
            height=26,
            font=ctk.CTkFont(size=10),
            fg_color=("#E5E7EB", "#334155"),
            text_color=("#1F2937", "#F3F4F6"),
            hover_color=("#D1D5DB", "#475569"),
            command=lambda: self._set_quick_auth("admin", "admin"),
        )
        btn_quick_admin.pack(side="left", padx=2)

        btn_quick_blank = ctk.CTkButton(
            auth_row,
            text="Xóa trắng",
            width=70,
            height=26,
            font=ctk.CTkFont(size=10),
            fg_color=("#E5E7EB", "#334155"),
            text_color=("#1F2937", "#F3F4F6"),
            hover_color=("#D1D5DB", "#475569"),
            command=lambda: self._set_quick_auth("", ""),
        )
        btn_quick_blank.pack(side="left", padx=2)

        # Hộp hiển thị URL đầy đủ
        url_display_box = ctk.CTkFrame(cfg_box, fg_color=("#F8FAFC", "#0F172A"), corner_radius=6)
        url_display_box.grid(row=6, column=0, columnspan=2, padx=14, pady=(8, 12), sticky="ew")

        ctk.CTkLabel(
            url_display_box,
            text="ĐƯỜNG DẪN RTSP KẾT NỐI TRỰC TIẾP:",
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color="#64748B",
        ).pack(padx=10, pady=(6, 2), anchor="w")

        self.lbl_full_url = ctk.CTkLabel(
            url_display_box,
            text="",
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            text_color="#8B5CF6",
            anchor="w",
            wraplength=700,
            justify="left",
        )
        self.lbl_full_url.pack(padx=10, pady=(0, 6), fill="x", anchor="w")

        # 3. Khu vực Xem Ảnh Thử / Snapshot (Preview Area)
        self.preview_card = ctk.CTkFrame(self, fg_color=("#FFFFFF", "#1E293B"), corner_radius=8)
        self.preview_card.grid(row=2, column=0, padx=16, pady=(0, 10), sticky="nsew")
        self.grid_rowconfigure(2, weight=1)
        self.preview_card.grid_columnconfigure(0, weight=1)
        self.preview_card.grid_rowconfigure(1, weight=1)

        pv_hdr = ctk.CTkFrame(self.preview_card, fg_color="transparent")
        pv_hdr.grid(row=0, column=0, padx=14, pady=(8, 4), sticky="ew")

        ctk.CTkLabel(
            pv_hdr,
            text="🖼️ KHUNG XEM THỬ HÌNH ẢNH CAMERA (SNAPSHOT TỨC THỜI):",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=("#6B7280", "#94A3B8"),
        ).pack(side="left")

        self.lbl_snap_status = ctk.CTkLabel(
            pv_hdr,
            text="Chưa lấy ảnh",
            font=ctk.CTkFont(size=11),
            text_color="#94A3B8",
        )
        self.lbl_snap_status.pack(side="right")

        self.pv_container = ctk.CTkFrame(self.preview_card, fg_color=("#0F172A", "#090D16"), corner_radius=6)
        self.pv_container.grid(row=1, column=0, padx=14, pady=(0, 8), sticky="nsew")
        self.pv_container.grid_columnconfigure(0, weight=1)
        self.pv_container.grid_rowconfigure(0, weight=1)

        self.lbl_pv_content = ctk.CTkLabel(
            self.pv_container,
            text="💡 Bấm '📸 Chụp Thử Snapshot' bên dưới để trích xuất ảnh xem trước trực tiếp từ camera\nhoặc bấm '▶️ MỞ XEM BẰNG VLC' để phát trực tiếp video thời gian thực.",
            font=ctk.CTkFont(size=12),
            text_color="#64748B",
            justify="center",
        )
        self.lbl_pv_content.grid(row=0, column=0, padx=20, pady=20)

        # 4. Thanh nút Thao Tác (Action Bar)
        act_bar = ctk.CTkFrame(self, fg_color="transparent")
        act_bar.grid(row=3, column=0, padx=16, pady=(0, 14), sticky="ew")

        # Nút to nổi bật nhất: Mở VLC Player
        self.btn_vlc = ctk.CTkButton(
            act_bar,
            text="▶️ MỞ XEM TRỰC TIẾP BẰNG VLC",
            font=ctk.CTkFont(size=13, weight="bold"),
            height=38,
            width=230,
            fg_color="#7C3AED",
            hover_color="#6D28D9",
            command=self._launch_vlc,
        )
        self.btn_vlc.pack(side="left", padx=(0, 8))

        # Nút Chụp Snapshot
        self.btn_snap = ctk.CTkButton(
            act_bar,
            text="📸 Chụp Thử Snapshot",
            font=ctk.CTkFont(size=12, weight="bold"),
            height=38,
            width=165,
            fg_color="#0284C7",
            hover_color="#0369A1",
            command=self._grab_snapshot,
        )
        self.btn_snap.pack(side="left", padx=4)

        # Nút Sao chép Link RTSP
        btn_copy = ctk.CTkButton(
            act_bar,
            text="📋 Copy Link RTSP",
            font=ctk.CTkFont(size=12),
            height=38,
            width=135,
            fg_color=("#E5E7EB", "#334155"),
            text_color=("#1F2937", "#F3F4F6"),
            hover_color=("#D1D5DB", "#475569"),
            command=self._copy_rtsp_url,
        )
        btn_copy.pack(side="left", padx=4)

        # Nút Kiểm Tra Khóa Mật Khẩu (Auth Check)
        self.btn_auth_check = ctk.CTkButton(
            act_bar,
            text="🛡️ Kiểm Tra Khóa Pass",
            font=ctk.CTkFont(size=12, weight="bold"),
            height=38,
            width=160,
            fg_color="#059669",
            hover_color="#047857",
            command=self._check_auth_status,
        )
        self.btn_auth_check.pack(side="left", padx=4)

        # Nút Mở Web Camera
        btn_web = ctk.CTkButton(
            act_bar,
            text="🌐 Mở Web Quản Trị",
            font=ctk.CTkFont(size=12),
            height=38,
            width=130,
            fg_color=("#E5E7EB", "#334155"),
            text_color=("#1F2937", "#F3F4F6"),
            hover_color=("#D1D5DB", "#475569"),
            command=self._open_web_admin,
        )
        btn_web.pack(side="right")

        self._update_full_url()

    def _check_auth_status(self):
        """Mở cửa sổ chẩn đoán kiểm tra trạng thái bảo vệ mật khẩu (401 vs 200)."""
        from camera_auth_checker import CameraAuthWindow
        CameraAuthWindow(self, self.device)

    def _auto_select_brand_preset(self):
        """Tự động chọn mẫu URL phù hợp nhất dựa trên Hãng sản xuất phát hiện được."""
        v = self.vendor.lower()
        matched_idx = 0

        if "hikvision" in v or "ezviz" in v:
            matched_idx = 1
        elif "dahua" in v or "imou" in v:
            matched_idx = 3
        elif "xiongmai" in v or "yoosee" in v or "xm" in v:
            matched_idx = 5
        elif "tuya" in v or "espressif" in v or "allwinner" in v:
            matched_idx = 7
        elif "tapo" in v or "tp-link" in v:
            matched_idx = 8

        preset_names = [f"{p['brand']} — {p['name']}" for p in CAMERA_STREAM_PRESETS]
        self.opt_preset.set(preset_names[matched_idx])
        self._on_select_preset(preset_names[matched_idx])

    def _on_select_preset(self, choice: str):
        """Khi người dùng chọn một preset từ danh sách."""
        for p in CAMERA_STREAM_PRESETS:
            combined = f"{p['brand']} — {p['name']}"
            if combined == choice:
                self.entry_path.delete(0, "end")
                self.entry_path.insert(0, p["path"])
                self.lbl_preset_desc.configure(text=p["desc"])
                break
        self._update_full_url()

    def _set_quick_auth(self, u: str, p: str):
        self.entry_user.delete(0, "end")
        self.entry_user.insert(0, u)
        self.entry_pass.delete(0, "end")
        self.entry_pass.insert(0, p)
        self._update_full_url()

    def _get_current_url(self) -> str:
        try:
            port_val = int(self.entry_port.get().strip())
        except ValueError:
            port_val = 554
        return build_rtsp_url(
            ip=self.ip,
            port=port_val,
            path=self.entry_path.get().strip() or "/",
            user=self.entry_user.get().strip(),
            password=self.entry_pass.get().strip(),
        )

    def _update_full_url(self):
        url = self._get_current_url()
        self.lbl_full_url.configure(text=url)

    def _copy_rtsp_url(self):
        url = self._get_current_url()
        self.clipboard_clear()
        self.clipboard_append(url)
        messagebox.showinfo("Đã sao chép", f"Đã sao chép đường dẫn RTSP vào bộ nhớ tạm:\n\n{url}\n\nBạn có thể dán link này vào phần mềm VLC Media Player, OBS Studio hoặc trình phát video bất kỳ.")

    def _launch_vlc(self):
        url = self._get_current_url()
        ok, msg = launch_vlc_stream(url, caching_ms=300)
        if ok:
            messagebox.showinfo(
                "Đang phát video qua VLC",
                f"Đã kích hoạt VLC Media Player kết nối đến luồng video:\n\n{url}\n\n💡 Ghi chú:\n• Nếu camera yêu cầu mật khẩu, hãy nhập User/Pass ở bảng trên rồi bấm mở lại.\n• Nếu màn hình VLC màu xám, hãy thử đổi sang preset kênh khác (như Kênh phụ / Substream).",
            )
        else:
            messagebox.showerror("Không thể mở VLC", msg)

    def _open_web_admin(self):
        import webbrowser
        webbrowser.open(f"http://{self.ip}")

    def _grab_snapshot(self):
        """Gửi request lấy ảnh snapshot tức thời từ camera trong thread riêng."""
        self.btn_snap.configure(state="disabled", text="⏳ Đang tải...")
        self.lbl_snap_status.configure(text="Đang kết nối thử các cổng web ảnh...", text_color="#38BDF8")

        u = self.entry_user.get().strip()
        p = self.entry_pass.get().strip()

        def worker():
            res = try_grab_snapshot(self.ip, web_port=80, user=u, password=p)
            if not res:
                # Thử thêm cổng 8080 nếu cổng 80 không được
                res = try_grab_snapshot(self.ip, web_port=8080, user=u, password=p)

            self.after(0, lambda: self._on_snapshot_finished(res))

        import threading
        threading.Thread(target=worker, daemon=True).start()

    def _on_snapshot_finished(self, res: Optional[Tuple[bytes, str]]):
        self.btn_snap.configure(state="normal", text="📸 Chụp Thử Snapshot")

        if not res:
            self.lbl_snap_status.configure(text="❌ Không trích xuất được ảnh qua Web HTTP", text_color="#F87171")
            self.lbl_pv_content.configure(
                text="❌ Camera không mở cổng ảnh tĩnh HTTP công khai (hoặc yêu cầu xác thực RTSP riêng).\n\n👉 Bạn hãy bấm nút '▶️ MỞ XEM TRỰC TIẾP BẰNG VLC' để mở luồng video H.264/RTSP trực tiếp!",
                text_color="#FCA5A5",
            )
            return

        img_bytes, url_used = res
        self.lbl_snap_status.configure(text=f"✅ Chụp ảnh thành công ({url_used})", text_color="#4ADE80")

        if Image:
            try:
                pil_img = Image.open(io.BytesIO(img_bytes))
                # Resize ảnh giữ đúng tỷ lệ vừa khung nhìn
                max_w, max_h = 580, 300
                pil_img.thumbnail((max_w, max_h), Image.Resampling.LANCZOS)

                ctk_img = ctk.CTkImage(light_image=pil_img, dark_image=pil_img, size=pil_img.size)
                self.lbl_pv_content.configure(image=ctk_img, text="")
                self.current_snapshot_img = ctk_img
            except Exception as e:
                self.lbl_pv_content.configure(text=f"✅ Đã tải được tệp ảnh ({len(img_bytes)} bytes) nhưng không thể giải mã: {e}")
        else:
            self.lbl_pv_content.configure(text=f"✅ Đã tải được ảnh ({len(img_bytes)} bytes) từ {url_used}!")
