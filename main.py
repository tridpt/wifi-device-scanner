"""
main.py - Giao diện Desktop ứng dụng Wi-Fi Device Scanner bằng CustomTkinter.
Giao diện trực quan, hỗ trợ Dark/Light mode, quét mạng đa luồng thời gian thực,
lọc tìm kiếm tức thì và xuất báo cáo CSV/JSON.
"""

import os
import sys

# Thiết lập mã hóa UTF-8 cho console Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

import threading
import queue
import webbrowser
import subprocess
import math
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import tkinter as tk
from tkinter import filedialog, messagebox
import customtkinter as ctk

# Thêm thư mục hiện tại vào sys.path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from scanner import NetworkScanner, get_wifi_ssid, get_local_ip, get_default_gateway
from export_utils import export_to_csv, export_to_json
from port_scanner import (
    scan_device_ports,
    analyze_device_roles,
    parse_custom_ports,
    PORT_PRESETS,
    PORT_DATABASE,
)
from ping_monitor import PingMonitor
from mac_blocker import get_guide_for_router, format_mac_variants
from security_audit import (
    get_wifi_security_info,
    audit_router_ports,
    audit_dns_security,
    evaluate_security_audit,
    run_security_dashboard,
)
from wake_on_lan import send_magic_packet, load_saved_wol_devices, save_wol_device, delete_saved_wol_device, get_wol_setup_guide
from spy_camera_detector import analyze_spy_camera_risk, play_alarm_sound, CAMERA_CHIP_SIGNATURES
from camera_streamer import CameraStreamWindow
from camera_auth_checker import CameraAuthWindow
from mac_randomizer import MacRandomizerWindow
from network_topology import NetworkTopologyView
from lan_shared_folders import LanSharedFoldersView, open_in_explorer
from lan_speedtest import LanSpeedtestView
from wifi_channel_analyzer import WifiChannelAnalyzerView
from network_history import NetworkHistory, device_fingerprint
from network_discovery import enrich_devices, run_local_discovery, assess_visibility, get_network_adapters
from report_utils import export_report_html, export_report_pdf
from notifications import notify_changes

# Thiết lập phong cách giao diện mặc định
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

CATEGORY_ICONS = {
    "router": "🌐",
    "pc": "💻",
    "mobile": "📱",
    "iot": "⚡",
    "camera": "📷",
    "private": "🔒",
    "system": "📡",
    "unknown": "❓",
}


class BlockMacGuideWindow(ctk.CTkToplevel):
    """Cửa sổ Popup hướng dẫn chặn thiết bị lạ qua Bộ lọc MAC (MAC Filter) của Modem."""

    def __init__(self, master, device_data: dict, gateway_ip: str = "192.168.1.1", router_vendor: str = "ZTE"):
        super().__init__(master)
        self.device = device_data
        self.gateway_ip = gateway_ip
        self.router_vendor = router_vendor

        mac = device_data.get("mac", "")
        ip = device_data.get("ip", "")
        name = device_data.get("name", "Thiết bị lạ")

        self.title(f"🚫 Hướng Dẫn Chặn Thiết Bị Lạ - {ip}")
        self.geometry("760x640")
        self.minsize(660, 520)

        # Căn giữa cửa sổ con so với cửa sổ cha
        self.transient(master)
        self.after(50, self.lift)

        # Tự động sao chép địa chỉ MAC vào clipboard
        self.mac_formats = format_mac_variants(mac)
        self.clipboard_clear()
        self.clipboard_append(self.mac_formats["colon"])

        # Tự động mở trang quản trị modem trên trình duyệt
        try:
            webbrowser.open(f"http://{self.gateway_ip}")
        except Exception:
            pass

        self.guide = get_guide_for_router(router_vendor)
        self._build_ui()

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        mac = self.device.get("mac", "")
        ip = self.device.get("ip", "")
        name = self.device.get("name", "Thiết bị lạ")
        vendor = self.device.get("vendor", "Chưa rõ hãng")

        # 1. Header cảnh báo (Rose/Red)
        header_box = ctk.CTkFrame(
            self,
            fg_color=("#FEF2F2", "#450A0A"),
            border_width=1,
            border_color="#EF4444",
            corner_radius=8,
        )
        header_box.grid(row=0, column=0, padx=20, pady=(15, 8), sticky="ew")
        header_box.grid_columnconfigure(1, weight=1)

        lbl_icon = ctk.CTkLabel(header_box, text="🚫", font=ctk.CTkFont(size=30), width=45)
        lbl_icon.grid(row=0, column=0, rowspan=2, padx=(15, 10), pady=10)

        lbl_t = ctk.CTkLabel(
            header_box,
            text="HƯỚNG DẪN CHẶN THIẾT BỊ LẠ TRUY CẬP WI-FI",
            font=ctk.CTkFont(size=15, weight="bold"),
            text_color=("#991B1B", "#FCA5A5"),
            anchor="w",
        )
        lbl_t.grid(row=0, column=1, padx=5, pady=(10, 2), sticky="w")

        sub_txt = f"Thiết bị: {name}   •   IP: {ip}   •   Hãng: {vendor}"
        lbl_sub = ctk.CTkLabel(
            header_box,
            text=sub_txt,
            font=ctk.CTkFont(size=12),
            text_color=("#B91C1C", "#F87171"),
            anchor="w",
        )
        lbl_sub.grid(row=1, column=1, padx=5, pady=(0, 10), sticky="w")

        # 2. Hộp hiển thị địa chỉ MAC to rõ & Đã copy
        mac_box = ctk.CTkFrame(self, fg_color=("#FFFFFF", "#1E293B"), corner_radius=8)
        mac_box.grid(row=1, column=0, padx=20, pady=(0, 10), sticky="ew")

        ctk.CTkLabel(
            mac_box,
            text="ĐỊA CHỈ MAC CẦN CHẶN:",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=("#6B7280", "#94A3B8"),
        ).pack(padx=16, pady=(10, 2), anchor="w")

        mac_display = ctk.CTkFrame(mac_box, fg_color="transparent")
        mac_display.pack(padx=16, pady=(0, 6), fill="x")

        lbl_mac_val = ctk.CTkLabel(
            mac_display,
            text=self.mac_formats["colon"],
            font=ctk.CTkFont(family="Consolas", size=22, weight="bold"),
            text_color="#EF4444",
        )
        lbl_mac_val.pack(side="left")

        lbl_copied_badge = ctk.CTkLabel(
            mac_display,
            text="✅ ĐÃ COPY MAC & ĐANG MỞ TRANG MODEM",
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color="#059669",
            text_color="white",
            corner_radius=4,
            padx=8,
            pady=2,
        )
        lbl_copied_badge.pack(side="left", padx=15)

        fmt_box = ctk.CTkFrame(mac_box, fg_color="transparent")
        fmt_box.pack(padx=16, pady=(0, 10), fill="x")

        ctk.CTkLabel(
            fmt_box,
            text="Các kiểu định dạng khác (nếu modem yêu cầu):",
            font=ctk.CTkFont(size=11),
            text_color=("#6B7280", "#94A3B8"),
        ).pack(side="left", padx=(0, 10))

        btn_copy_colon = ctk.CTkButton(
            fmt_box,
            text=f"Copy: {self.mac_formats['colon']}",
            height=26,
            font=ctk.CTkFont(family="Consolas", size=11),
            fg_color=("#E5E7EB", "#374151"),
            text_color=("#111827", "#F9FAFB"),
            hover_color=("#D1D5DB", "#4B5563"),
            command=lambda: self._copy_mac(self.mac_formats["colon"], "định dạng hai chấm"),
        )
        btn_copy_colon.pack(side="left", padx=4)

        btn_copy_dash = ctk.CTkButton(
            fmt_box,
            text=f"Copy: {self.mac_formats['dash']}",
            height=26,
            font=ctk.CTkFont(family="Consolas", size=11),
            fg_color=("#E5E7EB", "#374151"),
            text_color=("#111827", "#F9FAFB"),
            hover_color=("#D1D5DB", "#4B5563"),
            command=lambda: self._copy_mac(self.mac_formats["dash"], "định dạng gạch ngang"),
        )
        btn_copy_dash.pack(side="left", padx=4)

        # 3. Khung hướng dẫn từng bước theo dòng Router (Scrollable)
        guide_box = ctk.CTkScrollableFrame(self, fg_color=("#FFFFFF", "#1E293B"), corner_radius=8)
        guide_box.grid(row=2, column=0, padx=20, pady=(0, 10), sticky="nsew")
        guide_box.grid_columnconfigure(0, weight=1)

        lbl_router_hdr = ctk.CTkLabel(
            guide_box,
            text=f"📌 Hướng dẫn thao tác cho: {self.guide['name']}",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=("#1F2937", "#F9FAFB"),
            anchor="w",
        )
        lbl_router_hdr.pack(padx=10, pady=(10, 4), fill="x", anchor="w")

        path_card = ctk.CTkFrame(guide_box, fg_color=("#F3F4F6", "#0F172A"))
        path_card.pack(padx=10, pady=4, fill="x")
        ctk.CTkLabel(
            path_card,
            text=f"📂 Đường dẫn menu: {self.guide['menu_path']}",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#0284C7",
            anchor="w",
        ).pack(padx=12, pady=6, anchor="w")

        for idx, step_text in enumerate(self.guide["steps"], start=1):
            step_row = ctk.CTkFrame(guide_box, fg_color="transparent")
            step_row.pack(padx=10, pady=3, fill="x", anchor="w")

            ctk.CTkLabel(
                step_row,
                text=f"Bước {idx}:",
                font=ctk.CTkFont(size=12, weight="bold"),
                text_color="#3B82F6",
                width=55,
                anchor="w",
            ).pack(side="left")
            ctk.CTkLabel(
                step_row,
                text=step_text,
                font=ctk.CTkFont(size=12),
                text_color=("#374151", "#E5E7EB"),
                anchor="w",
                wraplength=580,
                justify="left",
            ).pack(side="left", fill="x")

        warn_box = ctk.CTkFrame(guide_box, fg_color=("#FEF3C7", "#451A03"), border_width=1, border_color="#F59E0B", corner_radius=6)
        warn_box.pack(padx=10, pady=(10, 6), fill="x")
        ctk.CTkLabel(
            warn_box,
            text=f"⚠️ LƯU Ý SỐNG CÒN:\n{self.guide['warning']}",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=("#92400E", "#FDE68A"),
            justify="left",
            anchor="w",
            wraplength=640,
        ).pack(padx=12, pady=8, fill="x")

        # 4. Thanh nút hành động ở chân cửa sổ
        bottom_bar = ctk.CTkFrame(self, fg_color="transparent")
        bottom_bar.grid(row=3, column=0, padx=20, pady=(0, 15), sticky="ew")

        btn_open_modem = ctk.CTkButton(
            bottom_bar,
            text=f"🌐 Mở Trang Quản Trị Modem Ngay (http://{self.gateway_ip})",
            font=ctk.CTkFont(size=13, weight="bold"),
            height=38,
            fg_color="#0284C7",
            hover_color="#0369A1",
            command=lambda: webbrowser.open(f"http://{self.gateway_ip}"),
        )
        btn_open_modem.pack(side="left", padx=(0, 10))

        btn_close = ctk.CTkButton(
            bottom_bar,
            text="Đã hiểu & Đóng",
            font=ctk.CTkFont(size=12),
            height=38,
            width=120,
            fg_color=("#E5E7EB", "#374151"),
            text_color=("#111827", "#F9FAFB"),
            hover_color=("#D1D5DB", "#4B5563"),
            command=self.destroy,
        )
        btn_close.pack(side="right")

    def _copy_mac(self, text_val: str, label_name: str):
        self.clipboard_clear()
        self.clipboard_append(text_val)
        messagebox.showinfo("Đã sao chép", f"Đã sao chép MAC {label_name}:\n{text_val}")


class WakeOnLanWindow(ctk.CTkToplevel):
    """Cửa sổ Popup Bật máy tính từ xa qua mạng (Wake-on-LAN - WoL)."""

    def __init__(self, master, target_device: dict = None):
        super().__init__(master)
        self.target_device = target_device or {}

        self.title("⚡ Wake-on-LAN - Bật Máy Tính Từ Xa Qua Mạng")
        self.geometry("740x650")
        self.minsize(660, 540)

        self.transient(master)
        self.after(50, self.lift)

        self.saved_devices = load_saved_wol_devices()
        self.guide = get_wol_setup_guide()

        self._build_ui()

        # Nếu có target_device, điền sẵn thông tin
        if self.target_device:
            ip = self.target_device.get("ip", "")
            mac = self.target_device.get("mac", "")
            name = self.target_device.get("name", "Máy tính")
            vendor = self.target_device.get("vendor", "")
            full_name = f"{name} ({vendor})" if vendor and vendor not in ("Chưa rõ", "Không xác định") else name

            self.entry_name.delete(0, "end")
            self.entry_name.insert(0, full_name)
            self.entry_mac.delete(0, "end")
            self.entry_mac.insert(0, mac)
            self.entry_ip.delete(0, "end")
            self.entry_ip.insert(0, ip)

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        # 1. Header Card (Hổ phách / Amber)
        header_box = ctk.CTkFrame(
            self,
            fg_color=("#FFFBEB", "#451A03"),
            border_width=1,
            border_color="#F59E0B",
            corner_radius=8,
        )
        header_box.grid(row=0, column=0, padx=20, pady=(15, 8), sticky="ew")
        header_box.grid_columnconfigure(1, weight=1)

        lbl_icon = ctk.CTkLabel(header_box, text="⚡", font=ctk.CTkFont(size=32), width=45)
        lbl_icon.grid(row=0, column=0, rowspan=2, padx=(15, 10), pady=10)

        lbl_t = ctk.CTkLabel(
            header_box,
            text="WAKE-ON-LAN (WoL) — BẬT MÁY TÍNH TỪ XA",
            font=ctk.CTkFont(size=15, weight="bold"),
            text_color=("#B45309", "#FCD34D"),
            anchor="w",
        )
        lbl_t.grid(row=0, column=1, padx=5, pady=(10, 2), sticky="w")

        lbl_sub = ctk.CTkLabel(
            header_box,
            text="Gửi gói tin Magic Packet (UDP 9 & 7) để đánh thức card mạng, khởi động máy tính đang tắt mà không cần bấm nút nguồn.",
            font=ctk.CTkFont(size=11),
            text_color=("#D97706", "#FDE68A"),
            anchor="w",
            wraplength=580,
            justify="left",
        )
        lbl_sub.grid(row=1, column=1, padx=5, pady=(0, 10), sticky="w")

        # 2. Khung Chọn máy đã lưu & Form nhập thông tin
        form_box = ctk.CTkFrame(self, fg_color=("#FFFFFF", "#1E293B"), corner_radius=8)
        form_box.grid(row=1, column=0, padx=20, pady=(0, 8), sticky="ew")
        form_box.grid_columnconfigure(1, weight=1)

        # Dòng chọn nhanh từ danh bạ đã lưu
        ctk.CTkLabel(form_box, text="Danh bạ PC đã lưu:", font=ctk.CTkFont(size=12, weight="bold"), text_color=("#4B5563", "#94A3B8"), anchor="w").grid(row=0, column=0, padx=(15, 10), pady=(12, 6), sticky="w")

        saved_names = [f"{d.get('name', 'PC')} ({d.get('mac')})" for d in self.saved_devices] or ["(Chưa có máy nào được lưu)"]
        self.opt_saved = ctk.CTkOptionMenu(
            form_box,
            values=saved_names,
            command=self._on_select_saved,
            height=30,
            font=ctk.CTkFont(size=12),
        )
        self.opt_saved.grid(row=0, column=1, padx=(0, 15), pady=(12, 6), sticky="ew")

        # Dòng Tên gợi nhớ
        ctk.CTkLabel(form_box, text="Tên máy tính:", font=ctk.CTkFont(size=12, weight="bold"), anchor="w").grid(row=1, column=0, padx=(15, 10), pady=6, sticky="w")
        self.entry_name = ctk.CTkEntry(form_box, placeholder_text="Ví dụ: PC Gaming Phòng Ngủ, Máy Trạm...", height=32, font=ctk.CTkFont(size=12))
        self.entry_name.grid(row=1, column=1, padx=(0, 15), pady=6, sticky="ew")

        # Dòng Địa chỉ MAC
        ctk.CTkLabel(form_box, text="Địa chỉ MAC (*):", font=ctk.CTkFont(size=12, weight="bold"), anchor="w").grid(row=2, column=0, padx=(15, 10), pady=6, sticky="w")
        self.entry_mac = ctk.CTkEntry(form_box, placeholder_text="AA:BB:CC:DD:EE:FF hoặc AABBCCDDEEFF", height=32, font=ctk.CTkFont(family="Consolas", size=13))
        self.entry_mac.grid(row=2, column=1, padx=(0, 15), pady=6, sticky="ew")

        # Dòng Địa chỉ IP (tuỳ chọn)
        ctk.CTkLabel(form_box, text="IP gợi nhớ (tuỳ chọn):", font=ctk.CTkFont(size=12), text_color=("#6B7280", "#94A3B8"), anchor="w").grid(row=3, column=0, padx=(15, 10), pady=6, sticky="w")
        self.entry_ip = ctk.CTkEntry(form_box, placeholder_text="Ví dụ: 192.168.1.50", height=32, font=ctk.CTkFont(size=12))
        self.entry_ip.grid(row=3, column=1, padx=(0, 15), pady=6, sticky="ew")

        # Các nút lưu / xóa danh bạ
        btn_saved_box = ctk.CTkFrame(form_box, fg_color="transparent")
        btn_saved_box.grid(row=4, column=0, columnspan=2, padx=15, pady=(4, 12), sticky="e")

        btn_save = ctk.CTkButton(
            btn_saved_box,
            text="⭐ Lưu vào danh bạ",
            width=130,
            height=28,
            font=ctk.CTkFont(size=11),
            fg_color=("#E5E7EB", "#374151"),
            text_color=("#111827", "#F9FAFB"),
            hover_color=("#D1D5DB", "#4B5563"),
            command=self._save_current_device,
        )
        btn_save.pack(side="left", padx=4)

        btn_del = ctk.CTkButton(
            btn_saved_box,
            text="🗑 Xóa khỏi danh bạ",
            width=130,
            height=28,
            font=ctk.CTkFont(size=11),
            fg_color=("#E5E7EB", "#374151"),
            text_color=("#111827", "#F9FAFB"),
            hover_color=("#D1D5DB", "#4B5563"),
            command=self._delete_current_device,
        )
        btn_del.pack(side="left", padx=4)

        # 3. Nút hành động BẮN MAGIC PACKET to rõ
        act_box = ctk.CTkFrame(self, fg_color="transparent")
        act_box.grid(row=2, column=0, padx=20, pady=(0, 8), sticky="ew")
        act_box.grid_columnconfigure(0, weight=1)

        self.btn_send_wol = ctk.CTkButton(
            act_box,
            text="⚡ GỬI LỆNH ĐÁNH THỨC MÁY (BẮN GÓI TIN MAGIC PACKET)",
            font=ctk.CTkFont(size=13, weight="bold"),
            height=42,
            fg_color="#D97706",
            hover_color="#B45309",
            command=self._send_wol,
        )
        self.btn_send_wol.pack(fill="x", pady=(0, 6))

        self.lbl_wol_status = ctk.CTkLabel(
            act_box,
            text="Sẵn sàng gửi gói tin đánh thức máy tính qua mạng.",
            font=ctk.CTkFont(size=12),
            text_color=("#4B5563", "#94A3B8"),
            anchor="w",
        )
        self.lbl_wol_status.pack(fill="x", anchor="w")

        # 4. Khung hướng dẫn cấu hình BIOS & Windows (Scrollable)
        guide_box = ctk.CTkScrollableFrame(self, fg_color=("#FFFFFF", "#1E293B"), corner_radius=8)
        guide_box.grid(row=3, column=0, padx=20, pady=(0, 15), sticky="nsew")
        guide_box.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            guide_box,
            text="📖 Hướng dẫn cấu hình BIOS & Windows nếu máy chưa tự bật được:",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=("#1F2937", "#F9FAFB"),
            anchor="w",
        ).pack(padx=10, pady=(8, 4), anchor="w")

        # BIOS Steps
        bios_card = ctk.CTkFrame(guide_box, fg_color=("#F3F4F6", "#0F172A"), corner_radius=6)
        bios_card.pack(padx=10, pady=4, fill="x")
        ctk.CTkLabel(
            bios_card,
            text="1️⃣ Cấu hình BIOS/UEFI của máy tính đích:",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#0284C7",
            anchor="w",
        ).pack(padx=10, pady=(6, 2), anchor="w")

        for s in self.guide["bios_steps"]:
            ctk.CTkLabel(
                bios_card,
                text=f"• {s}",
                font=ctk.CTkFont(size=11),
                text_color=("#374151", "#E5E7EB"),
                anchor="w",
                wraplength=620,
                justify="left",
            ).pack(padx=15, pady=1, anchor="w")

        # Windows Steps
        win_card = ctk.CTkFrame(guide_box, fg_color=("#F3F4F6", "#0F172A"), corner_radius=6)
        win_card.pack(padx=10, pady=(6, 8), fill="x")
        ctk.CTkLabel(
            win_card,
            text="2️⃣ Cấu hình Card mạng trên Windows 10 / 11:",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#10B981",
            anchor="w",
        ).pack(padx=10, pady=(6, 2), anchor="w")

        for s in self.guide["windows_steps"]:
            ctk.CTkLabel(
                win_card,
                text=f"• {s}",
                font=ctk.CTkFont(size=11),
                text_color=("#374151", "#E5E7EB"),
                anchor="w",
                wraplength=620,
                justify="left",
            ).pack(padx=15, pady=1, anchor="w")

    def _on_select_saved(self, choice: str):
        for d in self.saved_devices:
            if d.get("mac") in choice:
                self.entry_name.delete(0, "end")
                self.entry_name.insert(0, d.get("name", ""))
                self.entry_mac.delete(0, "end")
                self.entry_mac.insert(0, d.get("mac", ""))
                self.entry_ip.delete(0, "end")
                self.entry_ip.insert(0, d.get("ip", ""))
                break

    def _save_current_device(self):
        name = self.entry_name.get().strip()
        mac = self.entry_mac.get().strip()
        ip = self.entry_ip.get().strip()
        if not mac:
            messagebox.showwarning("Thiếu thông tin", "Vui lòng nhập địa chỉ MAC trước khi lưu!")
            return
        try:
            self.saved_devices = save_wol_device(name, mac, ip)
            new_vals = [f"{d.get('name', 'PC')} ({d.get('mac')})" for d in self.saved_devices]
            self.opt_saved.configure(values=new_vals)
            messagebox.showinfo("Đã lưu", f"Đã lưu máy tính '{name}' vào danh bạ WoL!")
        except Exception as e:
            messagebox.showerror("Lỗi", f"Không thể lưu máy tính: {e}")

    def _delete_current_device(self):
        mac = self.entry_mac.get().strip()
        if not mac:
            return
        self.saved_devices = delete_saved_wol_device(mac)
        new_vals = [f"{d.get('name', 'PC')} ({d.get('mac')})" for d in self.saved_devices] or ["(Chưa có máy nào được lưu)"]
        self.opt_saved.configure(values=new_vals)
        self.opt_saved.set(new_vals[0])
        messagebox.showinfo("Đã xóa", "Đã xóa máy tính khỏi danh bạ.")

    def _send_wol(self):
        mac = self.entry_mac.get().strip()
        if not mac:
            messagebox.showwarning("Thiếu MAC", "Vui lòng nhập địa chỉ MAC của máy tính cần đánh thức!")
            return

        app = self.winfo_toplevel()
        gateway_ip = getattr(app, "scanner", None).gateway_ip if hasattr(app, "scanner") else "192.168.1.1"
        subnet_ip = "192.168.1.255"
        if gateway_ip and gateway_ip.count(".") == 3:
            parts = gateway_ip.split(".")
            subnet_ip = f"{parts[0]}.{parts[1]}.{parts[2]}.255"

        res = send_magic_packet(mac, broadcast_ip="255.255.255.255", subnet_ip=subnet_ip)
        if res.get("success"):
            msg = f"✅ {res.get('message')}\n💡 Vui lòng chờ 15 - 30 giây để máy tính khởi động vào hệ điều hành."
            self.lbl_wol_status.configure(text=msg, text_color="#10B981")
            messagebox.showinfo("Thành công", f"Đã phát sóng lệnh đánh thức Magic Packet!\n\nĐích đến: {res.get('mac')}\nSố gói tin: {res.get('sent_packets')} gói qua UDP 9 & 7\n\nNếu máy tính chưa khởi động, hãy tham khảo mục 'Hướng dẫn cấu hình BIOS & Windows' bên dưới.")
        else:
            err = res.get("error", "Lỗi không xác định")
            self.lbl_wol_status.configure(text=f"❌ Thất bại: {err}", text_color="#EF4444")
            messagebox.showerror("Lỗi", f"Không thể gửi gói tin Magic Packet:\n{err}")


class DeviceDetailWindow(ctk.CTkToplevel):
    """Cửa sổ Popup chi tiết soi cổng dịch vụ & nhận diện Camera / Web / SMB / RDP."""

    def __init__(self, master, device_data: dict):
        super().__init__(master)
        self.device = device_data
        ip = device_data.get("ip", "")
        name = device_data.get("name", "Thiết bị")
        self.title(f"🔍 Soi cổng dịch vụ - {ip} ({name})")
        self.geometry("720x600")
        self.minsize(620, 500)

        # Căn giữa cửa sổ con so với cửa sổ cha
        self.transient(master)
        self.after(50, self.lift)

        self.open_ports = []
        self.is_scanning = False

        self._build_ui()
        self.after(300, self._start_port_scan)

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        # 1. Header Card
        header_card = ctk.CTkFrame(self, fg_color=("#F3F4F6", "#1E293B"), corner_radius=8)
        header_card.grid(row=0, column=0, padx=20, pady=(15, 10), sticky="ew")
        header_card.grid_columnconfigure(1, weight=1)

        cat = self.device.get("category", "unknown")
        icon = CATEGORY_ICONS.get(cat, "📱")
        lbl_icon = ctk.CTkLabel(header_card, text=icon, font=ctk.CTkFont(size=32), width=50)
        lbl_icon.grid(row=0, column=0, rowspan=2, padx=(15, 10), pady=12)

        name_text = self.device.get("name", "Thiết bị")
        lbl_name = ctk.CTkLabel(
            header_card,
            text=name_text,
            font=ctk.CTkFont(size=16, weight="bold"),
            anchor="w",
        )
        lbl_name.grid(row=0, column=1, padx=5, pady=(12, 2), sticky="w")

        ip_mac = f"IP: {self.device.get('ip')}   •   MAC: {self.device.get('mac')}   •   Hãng: {self.device.get('vendor')}"
        lbl_sub = ctk.CTkLabel(
            header_card,
            text=ip_mac,
            font=ctk.CTkFont(size=12),
            text_color=("#6B7280", "#94A3B8"),
            anchor="w",
        )
        lbl_sub.grid(row=1, column=1, padx=5, pady=(0, 12), sticky="w")

        # 2. Khung huy hiệu vai trò nhận diện (Roles)
        self.role_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.role_frame.grid(row=1, column=0, padx=20, pady=(0, 6), sticky="ew")

        # 3. Khung cấu hình & Điều khiển Soi Cổng (Scan Configuration Card)
        scan_cfg_box = ctk.CTkFrame(self, fg_color=("#FFFFFF", "#1E293B"), corner_radius=8)
        scan_cfg_box.grid(row=2, column=0, padx=20, pady=(0, 10), sticky="ew")
        scan_cfg_box.grid_columnconfigure(1, weight=1)

        # Hàng 1: Chế độ quét & Nút hành động
        row1 = ctk.CTkFrame(scan_cfg_box, fg_color="transparent")
        row1.pack(padx=14, pady=(10, 4), fill="x")
        row1.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(row1, text="Chế độ quét:", font=ctk.CTkFont(size=12, weight="bold")).grid(row=0, column=0, padx=(0, 8), sticky="w")

        self.opt_scan_mode = ctk.CTkOptionMenu(
            row1,
            values=[
                "🛡️ Mở Rộng (Top 100 cổng - Khuyên dùng)",
                "⚡ Nhanh (Top 30 cổng)",
                "🔬 Toàn Bộ Cổng Chuẩn (1 - 1024)",
                "✏️ Tùy Chỉnh Dải Cổng (Custom Range)",
            ],
            command=self._on_change_scan_mode,
            width=260,
            height=30,
            font=ctk.CTkFont(size=12),
        )
        self.opt_scan_mode.set("🛡️ Mở Rộng (Top 100 cổng - Khuyên dùng)")
        self.opt_scan_mode.grid(row=0, column=1, padx=(0, 10), sticky="w")

        self.btn_rescan = ctk.CTkButton(
            row1,
            text="🔍 BẮT ĐẦU SOI CỔNG",
            width=150,
            height=30,
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#8B5CF6",
            hover_color="#7C3AED",
            command=self._start_port_scan,
        )
        self.btn_rescan.grid(row=0, column=2, padx=(0, 8), sticky="e")

        if not self.device.get("is_gateway") and not self.device.get("is_self"):
            btn_block = ctk.CTkButton(
                row1,
                text="🚫 Chặn MAC",
                width=90,
                height=30,
                font=ctk.CTkFont(size=11, weight="bold"),
                fg_color="#DC2626",
                hover_color="#B91C1C",
                command=self._open_block_mac,
            )
            btn_block.grid(row=0, column=3, padx=(0, 4), sticky="e")

            btn_wol = ctk.CTkButton(
                row1,
                text="⚡ WoL",
                width=75,
                height=30,
                font=ctk.CTkFont(size=11, weight="bold"),
                fg_color="#D97706",
                hover_color="#B45309",
                command=self._open_wol,
            )
            btn_wol.grid(row=0, column=4, sticky="e")
        elif self.device.get("is_self"):
            btn_mac_privacy = ctk.CTkButton(
                row1,
                text="🎭 Đổi Danh Tính MAC",
                width=150,
                height=30,
                font=ctk.CTkFont(size=11, weight="bold"),
                fg_color="#10B981",
                hover_color="#059669",
                command=lambda: MacRandomizerWindow(self.winfo_toplevel()),
            )
            btn_mac_privacy.grid(row=0, column=3, padx=(0, 4), sticky="e")

        # Hàng 2: Ô nhập dải cổng tùy chỉnh (Custom Port Range Input)
        self.custom_row = ctk.CTkFrame(scan_cfg_box, fg_color="transparent")
        self.custom_row.pack(padx=14, pady=(2, 6), fill="x")

        ctk.CTkLabel(self.custom_row, text="Dải cổng tự chọn:", font=ctk.CTkFont(size=11, weight="bold"), text_color=("#6B7280", "#94A3B8")).pack(side="left", padx=(0, 8))

        self.entry_custom_ports = ctk.CTkEntry(
            self.custom_row,
            height=28,
            placeholder_text="Ví dụ: 1-1000 hoặc 80, 443, 554, 8000-8080, 37777",
            font=ctk.CTkFont(family="Consolas", size=11),
        )
        self.entry_custom_ports.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self.entry_custom_ports.insert(0, "80, 443, 554, 8000, 8080, 8554, 37777, 34567, 3389, 445")

        # Các nút bấm điền nhanh dải cổng thông dụng
        btn_quick_cam = ctk.CTkButton(
            self.custom_row,
            text="📷 Cổng Camera",
            width=90,
            height=26,
            font=ctk.CTkFont(size=10),
            fg_color=("#E5E7EB", "#334155"),
            text_color=("#1F2937", "#F3F4F6"),
            hover_color=("#D1D5DB", "#475569"),
            command=lambda: self._set_custom_text("554, 8554, 1935, 8000, 8899, 34567, 37777, 8080, 80"),
        )
        btn_quick_cam.pack(side="left", padx=2)

        btn_quick_web = ctk.CTkButton(
            self.custom_row,
            text="🌐 Web/Dev",
            width=75,
            height=26,
            font=ctk.CTkFont(size=10),
            fg_color=("#E5E7EB", "#334155"),
            text_color=("#1F2937", "#F3F4F6"),
            hover_color=("#D1D5DB", "#475569"),
            command=lambda: self._set_custom_text("80, 443, 3000, 5000, 8000, 8080, 8443, 8888, 9000"),
        )
        btn_quick_web.pack(side="left", padx=2)

        btn_quick_range = ctk.CTkButton(
            self.custom_row,
            text="1 - 1000",
            width=65,
            height=26,
            font=ctk.CTkFont(size=10),
            fg_color=("#E5E7EB", "#334155"),
            text_color=("#1F2937", "#F3F4F6"),
            hover_color=("#D1D5DB", "#475569"),
            command=lambda: self._set_custom_text("1-1000"),
        )
        btn_quick_range.pack(side="left", padx=2)

        # Hàng 3: Trạng thái & Thanh tiến trình
        stat_row = ctk.CTkFrame(scan_cfg_box, fg_color="transparent")
        stat_row.pack(padx=14, pady=(2, 10), fill="x")

        self.lbl_status = ctk.CTkLabel(
            stat_row,
            text="Sẵn sàng quét các cổng dịch vụ...",
            font=ctk.CTkFont(size=11),
            text_color=("#4B5563", "#94A3B8"),
            anchor="w",
        )
        self.lbl_status.pack(fill="x", anchor="w")

        self.progress_bar = ctk.CTkProgressBar(stat_row, height=5)
        self.progress_bar.pack(fill="x", pady=(4, 0))
        self.progress_bar.set(0)

        # 4. Danh sách các cổng mở (Scrollable)
        self.ports_container = ctk.CTkScrollableFrame(
            self,
            fg_color=("#FFFFFF", "#111827"),
            corner_radius=8,
        )
        self.ports_container.grid(row=3, column=0, padx=20, pady=(0, 15), sticky="nsew")
        self.ports_container.grid_columnconfigure(0, weight=1)

        self.lbl_empty = ctk.CTkLabel(
            self.ports_container,
            text="Đang kết nối kiểm tra các cổng dịch vụ...",
            font=ctk.CTkFont(size=13),
            text_color=("#6B7280", "#9CA3AF"),
            pady=40,
        )
        self.lbl_empty.pack()

    def _on_change_scan_mode(self, choice: str):
        if "Tùy Chỉnh" in choice:
            self.entry_custom_ports.focus()
            self.lbl_status.configure(text="Chế độ Tùy Chỉnh: Hãy nhập dải cổng (ví dụ: 1-1000 hoặc các cổng cụ thể) rồi bấm BẮT ĐẦU SOI CỔNG.")
        elif "Top 30" in choice:
            self.lbl_status.configure(text="Chế độ Top 30: Quét 30 cổng thông dụng nhất (~0.3 giây).")
        elif "Top 100" in choice:
            self.lbl_status.configure(text="Chế độ Top 100: Quét mở rộng Web, Cam, NAS, Remote, Database, IoT (~0.8 giây).")
        elif "1 - 1024" in choice:
            self.lbl_status.configure(text="Chế độ 1 - 1024: Quét toàn bộ 1.024 cổng dịch vụ tiêu chuẩn Nmap (~1.5 giây).")

    def _set_custom_text(self, text: str):
        self.opt_scan_mode.set("✏️ Tùy Chỉnh Dải Cổng (Custom Range)")
        self.entry_custom_ports.delete(0, "end")
        self.entry_custom_ports.insert(0, text)
        self.entry_custom_ports.focus()
        self._start_port_scan()

    def _start_port_scan(self):
        if self.is_scanning:
            return

        mode = self.opt_scan_mode.get()
        if "Top 30" in mode:
            ports_to_scan = PORT_PRESETS["top30"]["ports"]
            desc_scan = "30 cổng phổ biến"
        elif "Top 100" in mode:
            ports_to_scan = PORT_PRESETS["top100"]["ports"]
            desc_scan = "100 cổng mở rộng"
        elif "1 - 1024" in mode:
            ports_to_scan = PORT_PRESETS["well_known_1024"]["ports"]
            desc_scan = "1.024 cổng tiêu chuẩn (1 - 1024)"
        else:
            raw = self.entry_custom_ports.get().strip()
            ports_to_scan = parse_custom_ports(raw)
            if not ports_to_scan:
                messagebox.showwarning("Dải cổng không hợp lệ", "Vui lòng nhập dải cổng hợp lệ (ví dụ: 1-1000 hoặc 80, 443, 554, 8000-8080)!")
                return
            desc_scan = f"{len(ports_to_scan)} cổng tùy chọn"

        self.is_scanning = True
        self.btn_rescan.configure(state="disabled", text="⏳ ĐANG SOI...")
        self.progress_bar.set(0)
        self.lbl_status.configure(text=f"Đang chuẩn bị quét {desc_scan} trên {self.device.get('ip')}...")

        for w in self.ports_container.winfo_children():
            w.destroy()
        for w in self.role_frame.winfo_children():
            w.destroy()

        self._placeholder_loading = ctk.CTkLabel(
            self.ports_container,
            text=f"⏳ Đang rà soát {desc_scan}... Cổng mở sẽ xuất hiện ngay tại đây khi phát hiện!",
            font=ctk.CTkFont(size=13),
            text_color=("#6B7280", "#9CA3AF"),
            pady=40,
        )
        self._placeholder_loading.pack()

        ip = self.device.get("ip", "")
        self.open_ports = []

        def worker():
            total_count = len(ports_to_scan)

            def on_progress(checked, total):
                self.after(0, lambda c=checked, t=total: (
                    self.progress_bar.set(c / t),
                    self.lbl_status.configure(
                        text=f"⚡ Đang quét: {c}/{t} cổng ({int(c*100/t)}%) • Phát hiện: {len(self.open_ports)} cổng mở"
                    )
                ))

            def on_found(port_info):
                self.open_ports.append(port_info)
                self.after(0, lambda p=port_info: self._render_live_port_row(p))

            final_open_ports = scan_device_ports(
                ip,
                ports=ports_to_scan,
                on_port_checked=on_progress,
                on_port_found=on_found,
            )
            roles = analyze_device_roles(final_open_ports)
            self.after(0, lambda: self._on_scan_finished(final_open_ports, roles, total_count))

        threading.Thread(target=worker, daemon=True).start()

    def _render_live_port_row(self, port_info: dict):
        if hasattr(self, "_placeholder_loading") and self._placeholder_loading:
            try:
                self._placeholder_loading.destroy()
                self._placeholder_loading = None
            except Exception:
                pass
        ip = self.device.get("ip", "")
        row = self._create_port_row(self.ports_container, ip, port_info)
        row.pack(fill="x", padx=5, pady=4)

    def _on_scan_finished(self, open_ports: list, roles: dict, total_scanned: int):
        self.is_scanning = False
        self.btn_rescan.configure(state="normal", text="🔍 BẮT ĐẦU SOI CỔNG")
        self.progress_bar.set(1.0)
        self.open_ports = open_ports

        # Hiển thị các banner vai trò nhận diện
        for w in self.role_frame.winfo_children():
            w.destroy()

        if roles.get("roles"):
            for role_text in roles["roles"]:
                bg_color = ("#EDE9FE", "#2E1065") if "Camera" in role_text else (
                    ("#DCFCE7", "#052E16") if "SMB" in role_text else (
                        ("#DBEAFE", "#1E3A8A") if "Web" in role_text else ("#FEF3C7", "#451A03")
                    )
                )
                txt_color = ("#6B21A8", "#E9D5FF") if "Camera" in role_text else (
                    ("#166534", "#86EFAC") if "SMB" in role_text else (
                        ("#1E40AF", "#93C5FD") if "Web" in role_text else ("#92400E", "#FDE68A")
                    )
                )
                badge = ctk.CTkLabel(
                    self.role_frame,
                    text=f"✨ {role_text}",
                    font=ctk.CTkFont(size=12, weight="bold"),
                    fg_color=bg_color,
                    text_color=txt_color,
                    corner_radius=6,
                    padx=12,
                    pady=4,
                )
                badge.pack(side="left", padx=4, pady=2)

        count = len(open_ports)
        if count > 0:
            self.lbl_status.configure(text=f"✅ Hoàn tất! Đã quét {total_scanned} cổng — Phát hiện {count} cổng đang MỞ (Active).")
        else:
            self.lbl_status.configure(text=f"✅ Hoàn tất! Không phát hiện cổng mở nào trong {total_scanned} cổng đã kiểm tra.")
            for w in self.ports_container.winfo_children():
                w.destroy()
            lbl_safe = ctk.CTkLabel(
                self.ports_container,
                text=f"🔒 Thiết bị đóng toàn bộ {total_scanned} cổng đã kiểm tra.\n"
                     "Hầu hết điện thoại iPhone, Android và máy tính bật tường lửa mặc định sẽ chặn các cổng này.",
                font=ctk.CTkFont(size=13),
                text_color=("#10B981", "#34D399"),
                pady=50,
            )
            lbl_safe.pack()

    def _create_port_row(self, master, ip: str, port_info: dict) -> ctk.CTkFrame:
        row = ctk.CTkFrame(master, fg_color=("#F9FAFB", "#1E222B"), corner_radius=6)
        row.grid_columnconfigure(2, weight=1)

        port_num = port_info["port"]
        service = port_info["service"]
        desc = port_info["desc"]
        cat = port_info["cat"]
        banner = port_info.get("banner", "")

        badge_color = "#3B82F6" if cat == "web" else (
            "#8B5CF6" if cat == "camera" else (
                "#10B981" if cat == "share" else (
                    "#F59E0B" if cat == "remote" else "#6B7280"
                )
            )
        )
        lbl_port = ctk.CTkLabel(
            row,
            text=f"Port {port_num}",
            font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
            fg_color=badge_color,
            text_color="white",
            corner_radius=4,
            width=85,
            pady=3,
        )
        lbl_port.grid(row=0, column=0, rowspan=2, padx=10, pady=8)

        lbl_service = ctk.CTkLabel(
            row,
            text=service,
            font=ctk.CTkFont(size=13, weight="bold"),
            width=90,
            anchor="w",
        )
        lbl_service.grid(row=0, column=1, padx=5, pady=(8, 2), sticky="w")

        lbl_state = ctk.CTkLabel(
            row,
            text="🟢 ĐANG MỞ",
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color="#10B981",
            anchor="w",
        )
        lbl_state.grid(row=1, column=1, padx=5, pady=(0, 8), sticky="w")

        info_frame = ctk.CTkFrame(row, fg_color="transparent")
        info_frame.grid(row=0, column=2, rowspan=2, padx=10, pady=6, sticky="ew")

        desc_text = desc
        if banner:
            desc_text += f"   •   Tiêu đề: {banner}"
        lbl_desc = ctk.CTkLabel(
            info_frame,
            text=desc_text,
            font=ctk.CTkFont(size=12),
            text_color=("#4B5563", "#94A3B8"),
            anchor="w",
        )
        lbl_desc.pack(fill="x", anchor="w")

        btn_box = ctk.CTkFrame(row, fg_color="transparent")
        btn_box.grid(row=0, column=3, rowspan=2, padx=10, pady=6, sticky="e")

        if cat == "web":
            btn_act = ctk.CTkButton(
                btn_box,
                text="🌐 Mở Web",
                width=85,
                height=26,
                font=ctk.CTkFont(size=11, weight="bold"),
                fg_color="#0284C7",
                hover_color="#0369A1",
                command=lambda p=port_num: webbrowser.open(f"http{'s' if p in (443, 8443) else ''}://{ip}:{p}"),
            )
            btn_act.pack(side="right")
        elif cat == "share" and port_num in (445, 139):
            btn_act = ctk.CTkButton(
                btn_box,
                text="📁 Mở Ổ Mạng",
                width=90,
                height=26,
                font=ctk.CTkFont(size=11, weight="bold"),
                fg_color="#059669",
                hover_color="#047857",
                command=lambda: subprocess.Popen(["explorer", f"\\\\{ip}"]),
            )
            btn_act.pack(side="right")
        elif cat == "remote" and port_num == 3389:
            btn_act = ctk.CTkButton(
                btn_box,
                text="💻 Kết Nối RDP",
                width=95,
                height=26,
                font=ctk.CTkFont(size=11, weight="bold"),
                fg_color="#D97706",
                hover_color="#B45309",
                command=lambda: subprocess.Popen(["mstsc", f"/v:{ip}"]),
            )
            btn_act.pack(side="right")
        elif cat == "camera" and port_num in (554, 8554):
            btn_stream = ctk.CTkButton(
                btn_box,
                text="📺 Xem Video Stream",
                width=135,
                height=26,
                font=ctk.CTkFont(size=11, weight="bold"),
                fg_color="#8B5CF6",
                hover_color="#7C3AED",
                command=lambda p=port_num: CameraStreamWindow(self.winfo_toplevel(), self.device, initial_port=p),
            )
            btn_stream.pack(side="right", padx=(4, 0))

            btn_auth = ctk.CTkButton(
                btn_box,
                text="🛡️ Kiểm Tra Pass",
                width=115,
                height=26,
                font=ctk.CTkFont(size=11, weight="bold"),
                fg_color="#059669",
                hover_color="#047857",
                command=lambda: CameraAuthWindow(self.winfo_toplevel(), self.device),
            )
            btn_auth.pack(side="right", padx=(4, 0))

            def copy_rtsp():
                url = f"rtsp://{ip}:{port_num}/"
                self.clipboard_clear()
                self.clipboard_append(url)
                messagebox.showinfo("Đã sao chép", f"Đã sao chép link RTSP Camera:\n{url}\n\nBạn có thể dán link này vào phần mềm xem video (VLC Player).")

            btn_act = ctk.CTkButton(
                btn_box,
                text="📋 Copy RTSP",
                width=85,
                height=26,
                font=ctk.CTkFont(size=11),
                fg_color=("#E5E7EB", "#374151"),
                text_color=("#111827", "#F9FAFB"),
                hover_color=("#D1D5DB", "#4B5563"),
                command=copy_rtsp,
            )
            btn_act.pack(side="right")
        elif cat == "camera" and port_num in (37777, 34567, 8000, 8899):
            btn_stream = ctk.CTkButton(
                btn_box,
                text="📺 Soi Luồng Cam",
                width=120,
                height=26,
                font=ctk.CTkFont(size=11, weight="bold"),
                fg_color="#8B5CF6",
                hover_color="#7C3AED",
                command=lambda: CameraStreamWindow(self.winfo_toplevel(), self.device, initial_port=554),
            )
            btn_stream.pack(side="right", padx=(4, 0))

            btn_auth = ctk.CTkButton(
                btn_box,
                text="🛡️ Kiểm Tra Pass",
                width=115,
                height=26,
                font=ctk.CTkFont(size=11, weight="bold"),
                fg_color="#059669",
                hover_color="#047857",
                command=lambda: CameraAuthWindow(self.winfo_toplevel(), self.device),
            )
            btn_auth.pack(side="right")
        elif port_num == 22:
            btn_ssh = ctk.CTkButton(
                btn_box,
                text="⌨️ SSH",
                width=75,
                height=26,
                font=ctk.CTkFont(size=11, weight="bold"),
                fg_color="#0F766E",
                hover_color="#115E59",
                command=lambda: subprocess.Popen(["cmd.exe", "/c", f"start ssh {ip}"]),
            )
            btn_ssh.pack(side="right")
        elif port_num in (5900, 5901):
            btn_vnc = ctk.CTkButton(
                btn_box,
                text="🖥️ VNC",
                width=75,
                height=26,
                font=ctk.CTkFont(size=11, weight="bold"),
                fg_color="#D97706",
                hover_color="#B45309",
                command=lambda p=port_num: webbrowser.open(f"vnc://{ip}:{p}"),
            )
            btn_vnc.pack(side="right")
        elif cat == "media" and port_num in (32400, 8096, 5000, 5001):
            btn_media = ctk.CTkButton(
                btn_box,
                text="🎬 Mở Media",
                width=90,
                height=26,
                font=ctk.CTkFont(size=11, weight="bold"),
                fg_color="#0284C7",
                hover_color="#0369A1",
                command=lambda p=port_num: webbrowser.open(f"http{'s' if p == 5001 else ''}://{ip}:{p}"),
            )
            btn_media.pack(side="right")

        return row

    def _open_block_mac(self):
        """Mở hướng dẫn chặn thiết bị lạ qua MAC Filtering trên Modem."""
        app = self.master
        gateway_ip = "192.168.1.1"
        router_vendor = "ZTE"
        if hasattr(app, "scanner") and getattr(app.scanner, "gateway_ip", None):
            gateway_ip = app.scanner.gateway_ip
        if hasattr(app, "all_devices"):
            for d in app.all_devices:
                if d.get("is_gateway"):
                    router_vendor = d.get("vendor", "ZTE")
                    break
        BlockMacGuideWindow(self, self.device, gateway_ip=gateway_ip, router_vendor=router_vendor)

    def _open_wol(self):
        """Mở cửa sổ Wake-on-LAN để đánh thức máy tính này."""
        WakeOnLanWindow(self, target_device=self.device)


class DeviceMetadataWindow(ctk.CTkToplevel):
    """Small editor for a device alias, room, notes, and trusted flag."""

    def __init__(self, master, device: dict, on_saved):
        super().__init__(master)
        self.device = device
        self.on_saved = on_saved
        self.title("Thông tin thiết bị")
        self.geometry("430x330")
        self.minsize(380, 300)
        self.transient(master)
        self.grab_set()
        self.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(self, text="Địa chỉ", font=ctk.CTkFont(size=11, weight="bold")).grid(row=0, column=0, padx=14, pady=(16, 6), sticky="w")
        ctk.CTkLabel(self, text=f"{device.get('ip', '')}  •  {device.get('mac', '')}", anchor="w").grid(row=0, column=1, padx=8, pady=(16, 6), sticky="w")
        ctk.CTkLabel(self, text="Tên tùy chỉnh", font=ctk.CTkFont(size=11, weight="bold")).grid(row=1, column=0, padx=14, pady=6, sticky="w")
        self.entry_alias = ctk.CTkEntry(self, placeholder_text="Ví dụ: TV phòng khách")
        self.entry_alias.insert(0, device.get("alias", ""))
        self.entry_alias.grid(row=1, column=1, padx=8, pady=6, sticky="ew")
        ctk.CTkLabel(self, text="Phòng / khu vực", font=ctk.CTkFont(size=11, weight="bold")).grid(row=2, column=0, padx=14, pady=6, sticky="w")
        self.entry_room = ctk.CTkEntry(self, placeholder_text="Phòng khách, văn phòng...")
        self.entry_room.insert(0, device.get("room", ""))
        self.entry_room.grid(row=2, column=1, padx=8, pady=6, sticky="ew")
        ctk.CTkLabel(self, text="Ghi chú", font=ctk.CTkFont(size=11, weight="bold")).grid(row=3, column=0, padx=14, pady=6, sticky="nw")
        self.entry_notes = ctk.CTkTextbox(self, height=75)
        self.entry_notes.insert("1.0", device.get("notes", ""))
        self.entry_notes.grid(row=3, column=1, padx=8, pady=6, sticky="ew")
        self.trusted_var = tk.BooleanVar(value=bool(device.get("trusted")))
        ctk.CTkCheckBox(self, text="Đánh dấu thiết bị tin cậy", variable=self.trusted_var).grid(row=4, column=1, padx=8, pady=6, sticky="w")
        btns = ctk.CTkFrame(self, fg_color="transparent")
        btns.grid(row=5, column=0, columnspan=2, padx=14, pady=(8, 14), sticky="e")
        ctk.CTkButton(btns, text="Hủy", width=80, fg_color=("#E5E7EB", "#374151"), text_color=("#111827", "#F9FAFB"), command=self.destroy).pack(side="left", padx=4)
        ctk.CTkButton(btns, text="Lưu", width=90, fg_color="#0F766E", hover_color="#115E59", command=self._save).pack(side="left", padx=4)

    def _save(self):
        values = {
            "alias": self.entry_alias.get().strip(),
            "room": self.entry_room.get().strip(),
            "notes": self.entry_notes.get("1.0", "end").strip(),
            "trusted": bool(self.trusted_var.get()),
        }
        try:
            self.on_saved(self.device, values)
        finally:
            self.destroy()


class DeviceRow(ctk.CTkFrame):
    """Một dòng hiển thị thông tin 1 thiết bị trong danh sách."""

    CATEGORY_ICONS = {
        "router": "🌐",
        "pc": "💻",
        "mobile": "📱",
        "iot": "⚡",
        "camera": "📷",
        "private": "🔒",
        "system": "📡",
        "unknown": "❓",
    }

    def __init__(self, master, device_data: dict, on_copy_callback=None, **kwargs):
        super().__init__(master, **kwargs)
        self.device = device_data
        self.on_copy = on_copy_callback

        # Màu sắc viền và nền tùy loại thiết bị
        if device_data.get("is_gateway"):
            self.configure(fg_color=("#E3F2FD", "#102A43"), border_width=1, border_color="#2196F3")
        elif device_data.get("is_self"):
            self.configure(fg_color=("#E8F5E9", "#0B3D20"), border_width=1, border_color="#4CAF50")
        else:
            self.configure(fg_color=("#F5F5F7", "#1E222B"), border_width=0)

        self._build_ui()
        # Nhấp đúp vào dòng để mở soi cổng dịch vụ
        self.bind("<Double-Button-1>", lambda e: self._open_port_scanner())

    def _build_ui(self):
        # Cấu hình grid
        self.grid_columnconfigure(2, weight=1)  # Cột tên & hãng mở rộng

        # 1. Icon phân loại
        cat = self.device.get("category", "unknown")
        icon = self.CATEGORY_ICONS.get(cat, "📱")
        lbl_icon = ctk.CTkLabel(self, text=icon, font=ctk.CTkFont(size=20), width=35)
        lbl_icon.grid(row=0, column=0, rowspan=2, padx=(10, 5), pady=8, sticky="w")

        # 2. Địa chỉ IP & Huy hiệu (Badge)
        ip_frame = ctk.CTkFrame(self, fg_color="transparent")
        ip_frame.grid(row=0, column=1, rowspan=2, padx=10, pady=6, sticky="w")

        lbl_ip = ctk.CTkLabel(
            ip_frame,
            text=self.device.get("ip") or self.device.get("ipv6", ""),
            font=ctk.CTkFont(size=14, weight="bold"),
            anchor="w",
        )
        lbl_ip.pack(anchor="w")

        # Tag định danh đặc biệt
        if self.device.get("is_gateway"):
            tag = ctk.CTkLabel(
                ip_frame,
                text="ROUTER / MODEM",
                font=ctk.CTkFont(size=10, weight="bold"),
                fg_color="#1976D2",
                text_color="white",
                corner_radius=4,
                padx=6,
                pady=1,
            )
            tag.pack(anchor="w", pady=(2, 0))
        elif self.device.get("is_self"):
            tag = ctk.CTkLabel(
                ip_frame,
                text="MÁY NÀY",
                font=ctk.CTkFont(size=10, weight="bold"),
                fg_color="#388E3C",
                text_color="white",
                corner_radius=4,
                padx=6,
                pady=1,
            )
            tag.pack(anchor="w", pady=(2, 0))
        elif self.device.get("is_random_mac"):
            tag = ctk.CTkLabel(
                ip_frame,
                text="MAC BẢO MẬT (iOS/Android)",
                font=ctk.CTkFont(size=9),
                fg_color=("#D1D5DB", "#374151"),
                text_color=("#111827", "#E5E7EB"),
                corner_radius=4,
                padx=5,
                pady=1,
            )
            tag.pack(anchor="w", pady=(2, 0))

        # 3. Tên thiết bị & Hãng sản xuất
        info_frame = ctk.CTkFrame(self, fg_color="transparent")
        info_frame.grid(row=0, column=2, rowspan=2, padx=10, pady=6, sticky="ew")

        name_text = self.device.get("alias") or self.device.get("name", "—")
        vendor_text = self.device.get("vendor", "Chưa rõ")
        cat = self.device.get("category", "unknown")

        if name_text == "—" or not name_text:
            if self.device.get("is_gateway"):
                name_text = "Router Wi-Fi / Cục phát Internet"
            elif self.device.get("is_self"):
                name_text = "Máy tính của bạn"
            elif self.device.get("is_random_mac"):
                name_text = "Thiết bị di động (iPhone / Android / Tablet)"
            elif cat == "mobile":
                name_text = f"Điện thoại / Thiết bị {vendor_text}"
            elif cat == "pc":
                name_text = f"Máy tính / Laptop ({vendor_text})"
            elif cat == "camera":
                name_text = f"Camera quan sát ({vendor_text})"
            elif cat == "iot":
                name_text = f"Thiết bị thông minh / Smart Home ({vendor_text})"
            elif vendor_text and vendor_text not in ("Chưa rõ", "Không xác định"):
                name_text = f"Thiết bị mạng {vendor_text}"
            else:
                name_text = "Thiết bị đang kết nối Wi-Fi"
        lbl_name = ctk.CTkLabel(
            info_frame,
            text=name_text,
            font=ctk.CTkFont(size=13, weight="bold"),
            anchor="w",
        )
        lbl_name.pack(fill="x", anchor="w")

        vendor_text = self.device.get("vendor", "Chưa rõ")
        hint_text = self.device.get("hint", "")
        desc = f"{vendor_text} • {hint_text}" if hint_text else vendor_text
        discovery_text = self.device.get("discovery", "")
        hostname_source = self.device.get("hostname_source", "")
        if discovery_text:
            desc += f" • Discovery: {discovery_text}"
        if hostname_source:
            desc += f" • Tên từ {hostname_source}"
        elif self.device.get("dhcp_hostname"):
            desc += f" • DHCP: {self.device.get('dhcp_hostname')}"
        lbl_vendor = ctk.CTkLabel(
            info_frame,
            text=desc,
            font=ctk.CTkFont(size=11),
            text_color=("#6B7280", "#9CA3AF"),
            anchor="w",
        )
        lbl_vendor.pack(fill="x", anchor="w")

        badges = []
        if self.device.get("room"):
            badges.append(f"📍 {self.device.get('room')}")
        if self.device.get("trusted"):
            badges.append("✅ Tin cậy")
        if self.device.get("historical"):
            badges.append("🕘 Snapshot cũ")
        risk_level = str(self.device.get("risk_level") or "").lower()
        if risk_level in ("critical", "high", "medium"):
            badges.append(f"⚠️ Rủi ro {risk_level}")
        if self.device.get("confidence") is not None:
            try:
                badges.append(f"Độ tin cậy {float(self.device.get('confidence')) * 100:.0f}%")
            except (TypeError, ValueError):
                pass
        if badges:
            ctk.CTkLabel(
                info_frame,
                text="  •  ".join(badges),
                font=ctk.CTkFont(size=10),
                text_color=("#0F766E", "#5EEAD4"),
                anchor="w",
            ).pack(fill="x", anchor="w")

        # 4. Địa chỉ MAC & Độ trễ phản hồi
        mac_frame = ctk.CTkFrame(self, fg_color="transparent")
        mac_frame.grid(row=0, column=3, rowspan=2, padx=10, pady=6, sticky="e")

        lbl_mac = ctk.CTkLabel(
            mac_frame,
            text=self.device.get("mac", ""),
            font=ctk.CTkFont(family="Consolas", size=12),
            text_color=("#374151", "#D1D5DB"),
            anchor="e",
        )
        lbl_mac.pack(anchor="e")

        if self.device.get("ip") and self.device.get("ipv6"):
            ctk.CTkLabel(
                mac_frame,
                text=f"IPv6 {self.device.get('ipv6')}",
                font=ctk.CTkFont(family="Consolas", size=9),
                text_color=("#64748B", "#94A3B8"),
                anchor="e",
            ).pack(anchor="e")

        rtt = self.device.get("rtt_ms", 0)
        lbl_rtt = ctk.CTkLabel(
            mac_frame,
            text=f"⚡ {rtt} ms",
            font=ctk.CTkFont(size=10),
            text_color=("#10B981" if rtt < 10 else "#F59E0B"),
            anchor="e",
        )
        lbl_rtt.pack(anchor="e")

        # 5. Nút thao tác nhanh
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.grid(row=0, column=4, rowspan=2, padx=(5, 12), pady=6, sticky="e")

        btn_copy = ctk.CTkButton(
            btn_frame,
            text="Copy IP",
            width=65,
            height=26,
            font=ctk.CTkFont(size=11),
            fg_color=("#E5E7EB", "#374151"),
            text_color=("#111827", "#F9FAFB"),
            hover_color=("#D1D5DB", "#4B5563"),
            command=self._copy_ip,
        )
        btn_copy.pack(side="left", padx=2)

        # Nút Soi cổng dịch vụ (Web, Camera RTSP, SMB, RDP)
        btn_scan_ports = ctk.CTkButton(
            btn_frame,
            text="🔍 Soi Cổng",
            width=78,
            height=26,
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color="#8B5CF6",
            hover_color="#7C3AED",
            command=self._open_port_scanner,
        )
        btn_scan_ports.pack(side="left", padx=2)

        btn_meta = ctk.CTkButton(
            btn_frame,
            text="✎ Ghi chú",
            width=70,
            height=26,
            font=ctk.CTkFont(size=11),
            fg_color=("#E5E7EB", "#374151"),
            text_color=("#111827", "#F9FAFB"),
            hover_color=("#D1D5DB", "#4B5563"),
            command=self._edit_metadata,
        )
        btn_meta.pack(side="left", padx=2)

        if not self.device.get("is_gateway") and not self.device.get("is_self"):
            v_low = (self.device.get("vendor") or "").lower()
            if self.device.get("category") == "camera" or any(k in v_low for k in ["hikvision", "dahua", "xiongmai", "tuya", "ezviz", "imou", "yoosee"]):
                btn_stream = ctk.CTkButton(
                    btn_frame,
                    text="📺 Cam",
                    width=55,
                    height=26,
                    font=ctk.CTkFont(size=11, weight="bold"),
                    fg_color="#8B5CF6",
                    hover_color="#7C3AED",
                    command=lambda: CameraStreamWindow(self.winfo_toplevel(), self.device),
                )
                btn_stream.pack(side="left", padx=2)

            btn_block = ctk.CTkButton(
                btn_frame,
                text="🚫 Chặn",
                width=68,
                height=26,
                font=ctk.CTkFont(size=11, weight="bold"),
                fg_color="#DC2626",
                hover_color="#B91C1C",
                command=self._open_block_mac,
            )
            btn_block.pack(side="left", padx=2)

            btn_wol = ctk.CTkButton(
                btn_frame,
                text="⚡ WoL",
                width=55,
                height=26,
                font=ctk.CTkFont(size=11, weight="bold"),
                fg_color="#D97706",
                hover_color="#B45309",
                command=self._open_wol,
            )
            btn_wol.pack(side="left", padx=2)

        if self.device.get("is_gateway"):
            btn_web = ctk.CTkButton(
                btn_frame,
                text="Vào Modem",
                width=80,
                height=26,
                font=ctk.CTkFont(size=11, weight="bold"),
                fg_color="#0284C7",
                hover_color="#0369A1",
                command=self._open_gateway_web,
            )
            btn_web.pack(side="left", padx=2)

    def _open_port_scanner(self):
        """Mở cửa sổ soi cổng dịch vụ của thiết bị này."""
        DeviceDetailWindow(self.winfo_toplevel(), self.device)

    def _edit_metadata(self):
        app = self.winfo_toplevel()
        if hasattr(app, "_edit_device_metadata"):
            app._edit_device_metadata(self.device)

    def _open_wol(self):
        """Mở cửa sổ Wake-on-LAN để đánh thức máy tính này."""
        WakeOnLanWindow(self.winfo_toplevel(), target_device=self.device)

    def _open_block_mac(self):
        """Mở hướng dẫn chặn thiết bị lạ qua MAC Filtering trên Modem."""
        app = self.winfo_toplevel()
        gateway_ip = "192.168.1.1"
        router_vendor = "ZTE"
        if hasattr(app, "scanner") and getattr(app.scanner, "gateway_ip", None):
            gateway_ip = app.scanner.gateway_ip
        if hasattr(app, "all_devices"):
            for d in app.all_devices:
                if d.get("is_gateway"):
                    router_vendor = d.get("vendor", "ZTE")
                    break
        BlockMacGuideWindow(self.winfo_toplevel(), self.device, gateway_ip=gateway_ip, router_vendor=router_vendor)

    def _copy_ip(self):
        ip = self.device.get("ip") or self.device.get("ipv6", "")
        self.clipboard_clear()
        self.clipboard_append(ip)
        if self.on_copy:
            self.on_copy(f"Đã sao chép IP: {ip}")

    def _open_gateway_web(self):
        ip = self.device.get("ip", "")
        webbrowser.open(f"http://{ip}")


class WifiScannerApp(ctk.CTk):
    """Cửa sổ ứng dụng chính Wi-Fi Device Scanner."""

    def __init__(self):
        super().__init__()

        self.title("Wi-Fi Device Scanner - Quản lý thiết bị & Đo độ trễ mạng")
        self.geometry("1100x780")
        self.minsize(920, 620)

        # Thiết lập Icon ứng dụng cho Titlebar và Taskbar
        icon_path = os.path.join(CURRENT_DIR, "assets", "app_icon.ico")
        if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
            icon_path = os.path.join(sys._MEIPASS, "assets", "app_icon.ico")
        if os.path.exists(icon_path):
            try:
                self.iconbitmap(icon_path)
            except Exception:
                pass

        # Trạng thái dữ liệu quét thiết bị
        self.scanner = NetworkScanner()
        self.all_devices: list[dict] = []
        self.device_queue = queue.Queue()
        self.is_scanning = False
        self.scan_mode = "full"
        self.scan_adapter_indices: list = []
        self.last_scan_result: dict = {}
        self.last_security_dashboard: dict = {}
        try:
            self.history = NetworkHistory()
        except Exception as exc:
            # UI vẫn chạy nếu profile bị khóa; lịch sử chỉ bị vô hiệu hóa.
            print(f"Không thể mở lịch sử SQLite: {exc}")
            self.history = None

        # Khởi tạo bộ đo ping thời gian thực
        self.ping_monitor = PingMonitor(router_ip=self.scanner.gateway_ip, internet_ip="8.8.8.8")
        self.ping_stats = None
        self.ping_diag = None

        # Trạng thái đánh giá an ninh
        self.is_auditing = False
        self.audit_results = None

        # Trạng thái quét camera giấu kín
        self.is_spy_scanning = False
        self.spy_results: list[dict] = []

        # Khởi tạo giao diện
        self._setup_ui()

        # Bắt đầu vòng lặp đọc hàng đợi thiết bị từ background thread
        self.after(100, self._process_queue)

        # Cập nhật thông tin mạng ban đầu
        self._refresh_network_badges()
        if self.history is not None:
            try:
                self.all_devices = self.history.latest_devices()
                if self.all_devices:
                    self._refresh_room_filter_values()
                    self._apply_filter()
                    self.lbl_status.configure(text=f"Đã tải snapshot gần nhất ({len(self.all_devices)} thiết bị). Hãy quét để cập nhật trạng thái.")
            except Exception as exc:
                print(f"Không thể tải snapshot lịch sử: {exc}")

        # Bắt đầu chạy ngầm đo ping Router & Internet
        self.ping_monitor.start(on_update=self._on_ping_update)

        # Xử lý đóng ứng dụng an toàn
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _setup_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)  # Tabview co giãn toàn bộ màn hình

        # --- 1. HEADER BAR ---
        self.header_frame = ctk.CTkFrame(self, corner_radius=0, height=75, fg_color=("#F3F4F6", "#111827"))
        self.header_frame.grid(row=0, column=0, sticky="ew")
        self.header_frame.grid_columnconfigure(1, weight=1)

        # Tiêu đề bên trái
        title_box = ctk.CTkFrame(self.header_frame, fg_color="transparent")
        title_box.grid(row=0, column=0, padx=20, pady=12, sticky="w")

        lbl_app_title = ctk.CTkLabel(
            title_box,
            text="📡 Wi-Fi Device Scanner",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color=("#111827", "#F9FAFB"),
        )
        lbl_app_title.pack(anchor="w")

        lbl_sub = ctk.CTkLabel(
            title_box,
            text="Kiểm tra thiết bị mạng & Đo độ ổn định Wi-Fi thời gian thực",
            font=ctk.CTkFont(size=12),
            text_color=("#6B7280", "#9CA3AF"),
        )
        lbl_sub.pack(anchor="w")

        # Badges thông tin mạng ở giữa
        self.network_badges_frame = ctk.CTkFrame(self.header_frame, fg_color="transparent")
        self.network_badges_frame.grid(row=0, column=1, padx=10, pady=12, sticky="e")

        self.lbl_wifi_ssid = self._create_badge(self.network_badges_frame, "📶 Wi-Fi: Đang nhận diện...")
        self.lbl_local_ip = self._create_badge(self.network_badges_frame, "💻 IP: ...")
        self.lbl_gateway = self._create_badge(self.network_badges_frame, "🌐 Router: ...")

        # Nút Trình Đổi Danh Tính Card Mạng (MAC Randomizer)
        btn_mac_top = ctk.CTkButton(
            self.header_frame,
            text="🎭 Đổi MAC / Randomizer",
            font=ctk.CTkFont(size=12, weight="bold"),
            height=32,
            width=180,
            fg_color="#10B981",
            hover_color="#059669",
            command=self._open_mac_randomizer_window,
        )
        btn_mac_top.grid(row=0, column=2, padx=(10, 5), pady=12, sticky="e")

        # Nút bật máy tính từ xa (Wake-on-LAN)
        btn_wol_top = ctk.CTkButton(
            self.header_frame,
            text="⚡ Bật máy từ xa (WoL)",
            font=ctk.CTkFont(size=12, weight="bold"),
            height=32,
            width=165,
            fg_color="#D97706",
            hover_color="#B45309",
            command=self._open_wol_window,
        )
        btn_wol_top.grid(row=0, column=3, padx=(5, 10), pady=12, sticky="e")

        # Nút chuyển chế độ Sáng / Tối
        theme_box = ctk.CTkFrame(self.header_frame, fg_color="transparent")
        theme_box.grid(row=0, column=4, padx=(5, 20), pady=12, sticky="e")

        self.theme_switch = ctk.CTkSwitch(
            theme_box,
            text="Dark Mode",
            command=self._toggle_theme,
            font=ctk.CTkFont(size=12),
        )
        self.theme_switch.select()
        self.theme_switch.pack()

        # --- 2. THANH ĐIỀU HƯỚNG 2 HÀNG (TWO-ROW NAVIGATION BAR) ---
        self.nav_frame = ctk.CTkFrame(self, fg_color=("#E5E7EB", "#1F2937"), corner_radius=10)
        self.nav_frame.grid(row=1, column=0, padx=20, pady=(6, 2), sticky="ew")
        self.nav_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self.nav_buttons = {}
        tab_definitions = [
            ("📱 Quét thiết bị Wi-Fi", 0, 0),
            ("🕸️ Sơ đồ mạng (Topology Map)", 0, 1),
            ("📁 Ổ Chia Sẻ LAN (Shared Folders)", 0, 2),
            ("⚡ Đo Tốc Độ LAN (Speedtest)", 0, 3),
            ("📡 Kênh Sóng Wi-Fi (Channel Analyzer)", 1, 0),
            ("📈 Biểu đồ độ trễ (Ping Graph)", 1, 1),
            ("🛡️ Đánh giá An ninh (Security Audit)", 1, 2),
            ("🕵️ Quét Camera Giấu Kín", 1, 3),
        ]

        for tab_title, r, c in tab_definitions:
            is_active = (r == 0 and c == 0)
            btn = ctk.CTkButton(
                self.nav_frame,
                text=tab_title,
                height=32,
                corner_radius=6,
                font=ctk.CTkFont(size=12, weight="bold"),
                fg_color="#0284C7" if is_active else ("#F3F4F6", "#111827"),
                text_color="#FFFFFF" if is_active else ("#4B5563", "#9CA3AF"),
                hover_color="#0369A1" if is_active else ("#E5E7EB", "#374151"),
                command=lambda t=tab_title: self._switch_tab(t),
            )
            btn.grid(row=r, column=c, padx=3, pady=3, sticky="ew")
            self.nav_buttons[tab_title] = btn

        # --- 3. MAIN TABVIEW ---
        self.tabview = ctk.CTkTabview(self, corner_radius=8, command=self._on_tab_changed)
        self.tabview.grid(row=2, column=0, padx=20, pady=(2, 5), sticky="nsew")

        self.tab_scan = self.tabview.add("📱 Quét thiết bị Wi-Fi")
        self.tab_topology = self.tabview.add("🕸️ Sơ đồ mạng (Topology Map)")
        self.tab_smb = self.tabview.add("📁 Ổ Chia Sẻ LAN (Shared Folders)")
        self.tab_speedtest = self.tabview.add("⚡ Đo Tốc Độ LAN (Speedtest)")
        self.tab_spectrum = self.tabview.add("📡 Kênh Sóng Wi-Fi (Channel Analyzer)")
        self.tab_ping = self.tabview.add("📈 Biểu đồ độ trễ (Ping Graph)")
        self.tab_security = self.tabview.add("🛡️ Đánh giá An ninh (Security Audit)")
        self.tab_spy = self.tabview.add("🕵️ Quét Camera Giấu Kín")

        # Ẩn thanh tab 1 hàng mặc định của CTkTabview để nhường chỗ cho thanh điều hướng 2 hàng không bao giờ bị tràn chữ
        self.tabview._segmented_button.grid_remove()

        self._setup_tab_scan()
        self._setup_tab_topology()
        self._setup_tab_smb()
        self._setup_tab_speedtest()
        self._setup_tab_spectrum()
        self._setup_tab_ping()
        self._setup_tab_security()
        self._setup_tab_spy()

        # --- 4. FOOTER STATUS BAR ---
        self.footer_frame = ctk.CTkFrame(self, height=32, corner_radius=0, fg_color=("#F3F4F6", "#0F172A"))
        self.footer_frame.grid(row=3, column=0, sticky="ew")
        self.footer_frame.grid_columnconfigure(0, weight=1)

        self.lbl_status = ctk.CTkLabel(
            self.footer_frame,
            text="Sẵn sàng quét mạng Wi-Fi và đo độ trễ đường truyền.",
            font=ctk.CTkFont(size=12),
            text_color=("#4B5563", "#94A3B8"),
            anchor="w",
            padx=20,
        )
        self.lbl_status.grid(row=0, column=0, sticky="w")

        self.lbl_timestamp = ctk.CTkLabel(
            self.footer_frame,
            text="",
            font=ctk.CTkFont(size=11),
            text_color=("#6B7280", "#64748B"),
            anchor="e",
            padx=20,
        )
        self.lbl_timestamp.grid(row=0, column=1, sticky="e")

    def _setup_tab_scan(self):
        """Thiết lập nội dung Tab 1: Danh sách thiết bị & Quét mạng."""
        self.tab_scan.grid_columnconfigure(0, weight=1)
        self.tab_scan.grid_rowconfigure(4, weight=1)

        # 1. Thẻ thống kê số lượng thiết bị
        stats_frame = ctk.CTkFrame(self.tab_scan, fg_color="transparent")
        stats_frame.grid(row=0, column=0, padx=5, pady=(5, 4), sticky="ew")
        for i in range(4):
            stats_frame.grid_columnconfigure(i, weight=1)

        self.card_total = self._create_stat_card(stats_frame, 0, "📱 Tổng thiết bị", "0 máy", "#3B82F6")
        self.card_router = self._create_stat_card(stats_frame, 1, "🌐 Router / Gateway", "0", "#06B6D4")
        self.card_identified = self._create_stat_card(stats_frame, 2, "🏷️ Đã nhận diện hãng", "0", "#10B981")
        self.card_private = self._create_stat_card(stats_frame, 3, "🔒 MAC Riêng tư (Điện thoại)", "0", "#8B5CF6")

        # 2. Thanh điều khiển quét, tìm kiếm, lọc
        ctrl_frame = ctk.CTkFrame(self.tab_scan, fg_color="transparent")
        ctrl_frame.grid(row=1, column=0, padx=5, pady=(2, 4), sticky="ew")
        ctrl_frame.grid_columnconfigure(3, weight=1)

        self.btn_scan = ctk.CTkButton(
            ctrl_frame,
            text="🚀 Bắt đầu quét mạng",
            font=ctk.CTkFont(size=14, weight="bold"),
            height=38,
            width=180,
            fg_color="#2563EB",
            hover_color="#1D4ED8",
            command=self._start_scan,
        )
        self.btn_scan.grid(row=0, column=0, padx=(0, 10), sticky="w")

        self.btn_stop = ctk.CTkButton(
            ctrl_frame,
            text="⏹ Dừng",
            font=ctk.CTkFont(size=13, weight="bold"),
            height=38,
            width=80,
            fg_color="#EF4444",
            hover_color="#DC2626",
            state="disabled",
            command=self._stop_scan,
        )
        self.btn_stop.grid(row=0, column=1, padx=(0, 15), sticky="w")

        self.scan_mode_menu = ctk.CTkOptionMenu(
            ctrl_frame,
            values=["⚡ Quét nhanh", "🔎 Quét đầy đủ", "🆕 Chỉ thiết bị mới"],
            command=self._on_scan_mode_changed,
            height=38,
            width=145,
            font=ctk.CTkFont(size=11, weight="bold"),
        )
        self.scan_mode_menu.set("🔎 Quét đầy đủ")
        self.scan_mode_menu.grid(row=0, column=2, padx=(0, 10), sticky="w")

        self.search_entry = ctk.CTkEntry(
            ctrl_frame,
            placeholder_text="🔍 Tìm theo IP, Tên máy, Hãng (Apple, Samsung...), MAC...",
            height=38,
            font=ctk.CTkFont(size=13),
        )
        self.search_entry.grid(row=0, column=3, padx=(0, 10), sticky="ew")
        self.search_entry.bind("<KeyRelease>", self._on_search_key)

        self.filter_combobox = ctk.CTkOptionMenu(
            ctrl_frame,
            values=["Tất cả thiết bị", "Chỉ Router/Gateway", "Chỉ Điện thoại / Di động", "Chỉ Máy tính", "Chỉ MAC Bảo mật"],
            command=lambda v: self._apply_filter(),
            height=38,
            width=170,
            font=ctk.CTkFont(size=12),
        )
        self.filter_combobox.set("Tất cả thiết bị")
        self.filter_combobox.grid(row=0, column=4, padx=(0, 8), sticky="e")

        self.risk_filter_combobox = ctk.CTkOptionMenu(
            ctrl_frame,
            values=["Mọi mức rủi ro", "Rủi ro cao", "Có cảnh báo", "An toàn / tin cậy"],
            command=lambda v: self._apply_filter(),
            height=38,
            width=115,
            font=ctk.CTkFont(size=11),
        )
        self.risk_filter_combobox.set("Mọi mức rủi ro")
        self.risk_filter_combobox.grid(row=0, column=5, padx=(0, 8), sticky="e")

        self.btn_export = ctk.CTkButton(
            ctrl_frame,
            text="📥 Xuất Excel/CSV",
            font=ctk.CTkFont(size=13),
            height=38,
            width=130,
            fg_color=("#E5E7EB", "#374151"),
            text_color=("#111827", "#F9FAFB"),
            hover_color=("#D1D5DB", "#4B5563"),
            command=self._export_data,
        )
        self.btn_export.grid(row=0, column=6, padx=(0, 6), sticky="e")

        self.btn_history = ctk.CTkButton(
            ctrl_frame,
            text="🕘 Lịch sử",
            font=ctk.CTkFont(size=12),
            height=38,
            width=92,
            fg_color=("#E5E7EB", "#374151"),
            text_color=("#111827", "#F9FAFB"),
            hover_color=("#D1D5DB", "#4B5563"),
            command=self._open_history_window,
        )
        self.btn_history.grid(row=0, column=7, sticky="e")

        # 3. Thanh tùy chỉnh dải mạng quét Subnet Mask / CIDR
        self.subnet_frame = ctk.CTkFrame(self.tab_scan, fg_color=("#E5E7EB", "#1F2937"), corner_radius=6, height=70)
        self.subnet_frame.grid(row=2, column=0, padx=5, pady=(2, 4), sticky="ew")
        self.subnet_frame.grid_columnconfigure(3, weight=1)
        self.subnet_frame.grid_columnconfigure(4, weight=1)

        lbl_sub_icon = ctk.CTkLabel(
            self.subnet_frame,
            text="🌐 Dải mạng quét:",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=("#374151", "#E5E7EB"),
        )
        lbl_sub_icon.grid(row=0, column=0, padx=(12, 8), pady=4, sticky="w")

        self.opt_subnet = ctk.CTkOptionMenu(
            self.subnet_frame,
            values=[
                "Tự động (Theo card mạng)",
                "Dải /24 (254 hosts)",
                "Dải /23 (510 hosts)",
                "Dải /22 (1022 hosts)",
                "Tùy chỉnh CIDR...",
            ],
            command=self._on_subnet_choice_changed,
            height=28,
            width=205,
            font=ctk.CTkFont(size=12),
        )
        self.opt_subnet.set("Tự động (Theo card mạng)")
        self.opt_subnet.grid(row=0, column=1, padx=(0, 10), pady=4, sticky="w")

        self.entry_cidr = ctk.CTkEntry(
            self.subnet_frame,
            width=160,
            height=28,
            font=ctk.CTkFont(family="Consolas", size=12),
        )
        self.entry_cidr.grid(row=0, column=2, padx=(0, 10), pady=4, sticky="w")
        self.entry_cidr.insert(0, self.scanner.network_cidr)
        self.entry_cidr.bind("<KeyRelease>", lambda e: self._on_cidr_typed())

        self.lbl_cidr_info = ctk.CTkLabel(
            self.subnet_frame,
            text=f"• Đang áp dụng: {self.scanner.network_cidr} (tối đa 254 hosts)",
            font=ctk.CTkFont(size=11),
            text_color=("#4B5563", "#9CA3AF"),
            anchor="w",
            wraplength=560,
        )
        self.lbl_cidr_info.grid(row=0, column=3, padx=(0, 12), pady=4, sticky="w")

        self.btn_adapters = ctk.CTkButton(
            self.subnet_frame,
            text="🧩 Chọn adapter",
            width=112,
            height=28,
            font=ctk.CTkFont(size=11),
            fg_color=("#E5E7EB", "#374151"),
            text_color=("#111827", "#F9FAFB"),
            hover_color=("#D1D5DB", "#4B5563"),
            command=self._open_adapter_selector,
        )
        self.btn_adapters.grid(row=1, column=0, padx=(12, 8), pady=(0, 4), sticky="w")

        self.room_filter_combobox = ctk.CTkOptionMenu(
            self.subnet_frame,
            values=["Mọi phòng"],
            command=lambda v: self._apply_filter(),
            width=110,
            height=28,
            font=ctk.CTkFont(size=11),
        )
        self.room_filter_combobox.set("Mọi phòng")
        self.room_filter_combobox.grid(row=1, column=1, padx=(0, 8), pady=(0, 4), sticky="w")

        self.retry_menu = ctk.CTkOptionMenu(
            self.subnet_frame,
            values=["Retry 1", "Retry 2", "Retry 3"],
            width=92,
            height=26,
            font=ctk.CTkFont(size=10),
        )
        self.retry_menu.set("Retry 2")
        self.retry_menu.grid(row=1, column=2, padx=(0, 4), pady=(0, 4), sticky="w")
        self.rate_menu = ctk.CTkOptionMenu(
            self.subnet_frame,
            values=["Rate 0 ms", "Rate 2 ms", "Rate 10 ms", "Rate 25 ms"],
            width=108,
            height=26,
            font=ctk.CTkFont(size=10),
        )
        self.rate_menu.set("Rate 2 ms")
        self.rate_menu.grid(row=1, column=3, padx=(0, 4), pady=(0, 4), sticky="w")
        ctk.CTkLabel(
            self.subnet_frame,
            text="retry / rate-limit",
            font=ctk.CTkFont(size=10),
            text_color=("#6B7280", "#94A3B8"),
        ).grid(row=1, column=4, padx=4, pady=(0, 4), sticky="w")

        # 4. Thanh tiến trình quét
        self.progress_bar = ctk.CTkProgressBar(self.tab_scan, height=5)
        self.progress_bar.grid(row=3, column=0, padx=5, pady=(2, 4), sticky="ew")
        self.progress_bar.set(0)

        # 5. Danh sách thiết bị (Scrollable)
        self.list_container = ctk.CTkScrollableFrame(
            self.tab_scan,
            fg_color=("#FFFFFF", "#111827"),
            corner_radius=8,
        )
        self.list_container.grid(row=4, column=0, padx=5, pady=(4, 5), sticky="nsew")
        self.list_container.grid_columnconfigure(0, weight=1)

        self.lbl_empty_state = ctk.CTkLabel(
            self.list_container,
            text="Nhấn nút '🚀 Bắt đầu quét mạng' để tìm tất cả thiết bị đang kết nối Wi-Fi.",
            font=ctk.CTkFont(size=15),
            text_color=("#6B7280", "#9CA3AF"),
            pady=80,
        )
        self.lbl_empty_state.grid(row=0, column=0, sticky="ew")

    def _setup_tab_topology(self):
        """Thiết lập nội dung Tab: Sơ đồ cấu trúc mạng hình sao tương tác trực quan."""
        self.tab_topology.grid_columnconfigure(0, weight=1)
        self.tab_topology.grid_rowconfigure(0, weight=1)

        self.topology_view = NetworkTopologyView(
            self.tab_topology,
            on_open_port_scan=self._open_port_scanner_from_topology,
            on_open_mac_blocker=self._open_mac_blocker_from_topology,
            on_open_wol=self._open_wol_from_topology,
        )
        self.topology_view.grid(row=0, column=0, sticky="nsew")

    def _open_port_scanner_from_topology(self, device: dict):
        DeviceDetailWindow(self, device)

    def _open_mac_blocker_from_topology(self, device: dict):
        gw = self.scanner.gateway_ip if hasattr(self, "scanner") else "192.168.1.1"
        BlockMacGuideWindow(self, device, gateway_ip=gw)

    def _open_wol_from_topology(self, device: dict):
        WakeOnLanWindow(self, target_device=device)

    def _setup_tab_smb(self):
        """Thiết lập nội dung Tab Khám phá & Dò tìm Ổ Đĩa Chia Sẻ Mạng LAN (SMB Explorer)."""
        self.tab_smb.grid_columnconfigure(0, weight=1)
        self.tab_smb.grid_rowconfigure(0, weight=1)

        self.smb_view = LanSharedFoldersView(
            self.tab_smb,
            get_active_devices_fn=lambda: self.all_devices,
            on_open_port_scan=self._open_port_scanner_from_topology,
        )
        self.smb_view.grid(row=0, column=0, sticky="nsew")

    def _setup_tab_speedtest(self):
        """Thiết lập nội dung Tab Đo Tốc Độ Băng Thông LAN (Speedometer Gauge)."""
        self.tab_speedtest.grid_columnconfigure(0, weight=1)
        self.tab_speedtest.grid_rowconfigure(0, weight=1)

        self.speedtest_view = LanSpeedtestView(
            self.tab_speedtest,
            get_gateway_fn=lambda: self.scanner.gateway_ip if hasattr(self, "scanner") else "192.168.1.1",
        )
        self.speedtest_view.grid(row=0, column=0, sticky="nsew")

    def _setup_tab_spectrum(self):
        """Thiết lập nội dung Tab Phân Tích Kênh Sóng Wi-Fi (Channel Analyzer)."""
        self.tab_spectrum.grid_columnconfigure(0, weight=1)
        self.tab_spectrum.grid_rowconfigure(0, weight=1)

        self.spectrum_view = WifiChannelAnalyzerView(self.tab_spectrum)
        self.spectrum_view.grid(row=0, column=0, sticky="nsew")

    def _setup_tab_ping(self):
        """Thiết lập nội dung Tab Biểu đồ độ trễ và chẩn đoán sóng mạng."""
        self.tab_ping.grid_columnconfigure(0, weight=1)
        self.tab_ping.grid_rowconfigure(2, weight=1)  # Canvas đồ thị co giãn

        # 1. Thẻ số liệu Ping (Router vs Internet)
        p_stats_frame = ctk.CTkFrame(self.tab_ping, fg_color="transparent")
        p_stats_frame.grid(row=0, column=0, padx=5, pady=(5, 5), sticky="ew")
        for i in range(4):
            p_stats_frame.grid_columnconfigure(i, weight=1)

        # Thẻ 1: Ping Router
        c_r = ctk.CTkFrame(p_stats_frame, fg_color=("#FFFFFF", "#1E293B"), corner_radius=8)
        c_r.grid(row=0, column=0, padx=4, sticky="ew")
        ctk.CTkLabel(c_r, text="🌐 Đến Router Wi-Fi (LAN)", font=ctk.CTkFont(size=12), text_color=("#6B7280", "#94A3B8")).pack(padx=14, pady=(8, 1), anchor="w")
        self.lbl_p_router_cur = ctk.CTkLabel(c_r, text="-- ms", font=ctk.CTkFont(size=22, weight="bold"), text_color="#06B6D4")
        self.lbl_p_router_cur.pack(padx=14, pady=0, anchor="w")
        self.lbl_p_router_sub = ctk.CTkLabel(c_r, text="Min: -- • Max: -- • Avg: --", font=ctk.CTkFont(size=11), text_color=("#9CA3AF", "#64748B"))
        self.lbl_p_router_sub.pack(padx=14, pady=(0, 8), anchor="w")

        # Thẻ 2: Ping Internet
        c_i = ctk.CTkFrame(p_stats_frame, fg_color=("#FFFFFF", "#1E293B"), corner_radius=8)
        c_i.grid(row=0, column=1, padx=4, sticky="ew")
        ctk.CTkLabel(c_i, text="🌍 Ra Internet (WAN)", font=ctk.CTkFont(size=12), text_color=("#6B7280", "#94A3B8")).pack(padx=14, pady=(8, 1), anchor="w")
        self.lbl_p_inet_cur = ctk.CTkLabel(c_i, text="-- ms", font=ctk.CTkFont(size=22, weight="bold"), text_color="#A855F7")
        self.lbl_p_inet_cur.pack(padx=14, pady=0, anchor="w")
        self.lbl_p_inet_sub = ctk.CTkLabel(c_i, text="Min: -- • Max: -- • Avg: --", font=ctk.CTkFont(size=11), text_color=("#9CA3AF", "#64748B"))
        self.lbl_p_inet_sub.pack(padx=14, pady=(0, 8), anchor="w")

        # Thẻ 3: Packet Loss
        c_l = ctk.CTkFrame(p_stats_frame, fg_color=("#FFFFFF", "#1E293B"), corner_radius=8)
        c_l.grid(row=0, column=2, padx=4, sticky="ew")
        ctk.CTkLabel(c_l, text="📉 Tỉ lệ rớt gói (Packet Loss)", font=ctk.CTkFont(size=12), text_color=("#6B7280", "#94A3B8")).pack(padx=14, pady=(8, 1), anchor="w")
        self.lbl_p_loss_cur = ctk.CTkLabel(c_l, text="0.0 %", font=ctk.CTkFont(size=22, weight="bold"), text_color="#10B981")
        self.lbl_p_loss_cur.pack(padx=14, pady=0, anchor="w")
        self.lbl_p_loss_sub = ctk.CTkLabel(c_l, text="Chất lượng kết nối hoàn hảo", font=ctk.CTkFont(size=11), text_color=("#9CA3AF", "#64748B"))
        self.lbl_p_loss_sub.pack(padx=14, pady=(0, 8), anchor="w")

        # Thẻ 4: Jitter
        c_j = ctk.CTkFrame(p_stats_frame, fg_color=("#FFFFFF", "#1E293B"), corner_radius=8)
        c_j.grid(row=0, column=3, padx=4, sticky="ew")
        ctk.CTkLabel(c_j, text="⚡ Độ trồi sụt (Jitter)", font=ctk.CTkFont(size=12), text_color=("#6B7280", "#94A3B8")).pack(padx=14, pady=(8, 1), anchor="w")
        self.lbl_p_jitter_cur = ctk.CTkLabel(c_j, text="-- ms", font=ctk.CTkFont(size=22, weight="bold"), text_color="#F59E0B")
        self.lbl_p_jitter_cur.pack(padx=14, pady=0, anchor="w")
        self.lbl_p_jitter_sub = ctk.CTkLabel(c_j, text="Biến thiên độ trễ liên tục", font=ctk.CTkFont(size=11), text_color=("#9CA3AF", "#64748B"))
        self.lbl_p_jitter_sub.pack(padx=14, pady=(0, 8), anchor="w")

        # 2. Hộp Chẩn đoán thông minh (Smart Diagnosis Banner)
        self.diag_card = ctk.CTkFrame(self.tab_ping, fg_color=("#E0F2FE", "#0C4A6E"), border_width=1, border_color="#0284C7", corner_radius=8)
        self.diag_card.grid(row=1, column=0, padx=5, pady=(5, 6), sticky="ew")

        self.lbl_diag_title = ctk.CTkLabel(
            self.diag_card,
            text="Đang phân tích tín hiệu đường truyền...",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=("#0369A1", "#38BDF8"),
            anchor="w",
        )
        self.lbl_diag_title.pack(padx=16, pady=(6, 2), fill="x", anchor="w")

        self.lbl_diag_desc = ctk.CTkLabel(
            self.diag_card,
            text="Hệ thống đang liên tục gửi tín hiệu kiểm tra đến Router Wi-Fi và Internet...",
            font=ctk.CTkFont(size=12),
            text_color=("#075985", "#BAE6FD"),
            anchor="w",
            wraplength=850,
        )
        self.lbl_diag_desc.pack(padx=16, pady=(0, 6), fill="x", anchor="w")

        # 3. Canvas vẽ biểu đồ sóng (Graph Canvas)
        graph_box = ctk.CTkFrame(self.tab_ping, fg_color=("#FFFFFF", "#0F172A"), corner_radius=8)
        graph_box.grid(row=2, column=0, padx=5, pady=(0, 6), sticky="nsew")
        graph_box.grid_columnconfigure(0, weight=1)
        graph_box.grid_rowconfigure(0, weight=1)

        self.canvas = tk.Canvas(
            graph_box,
            bg="#0F172A",
            bd=0,
            highlightthickness=0,
            relief="ridge",
        )
        self.canvas.grid(row=0, column=0, padx=4, pady=4, sticky="nsew")
        self.canvas.bind("<Configure>", lambda e: self._render_ping_canvas(self.ping_stats) if self.ping_stats else None)

        # 4. Thanh công cụ phía dưới Tab Ping
        p_ctrl = ctk.CTkFrame(self.tab_ping, fg_color="transparent")
        p_ctrl.grid(row=3, column=0, padx=5, pady=(0, 5), sticky="ew")
        p_ctrl.grid_columnconfigure(2, weight=1)

        self.btn_ping_pause = ctk.CTkButton(
            p_ctrl,
            text="⏸ Tạm dừng đo",
            font=ctk.CTkFont(size=12, weight="bold"),
            width=120,
            height=32,
            fg_color=("#E5E7EB", "#374151"),
            text_color=("#111827", "#F9FAFB"),
            hover_color=("#D1D5DB", "#4B5563"),
            command=self._toggle_ping_pause,
        )
        self.btn_ping_pause.grid(row=0, column=0, padx=(0, 10), sticky="w")

        self.btn_ping_reset = ctk.CTkButton(
            p_ctrl,
            text="🗑 Đặt lại biểu đồ",
            font=ctk.CTkFont(size=12),
            width=110,
            height=32,
            fg_color=("#E5E7EB", "#374151"),
            text_color=("#111827", "#F9FAFB"),
            hover_color=("#D1D5DB", "#4B5563"),
            command=self._reset_ping,
        )
        self.btn_ping_reset.grid(row=0, column=1, padx=(0, 15), sticky="w")

        ctk.CTkLabel(p_ctrl, text="Máy chủ Internet thử nghiệm:", font=ctk.CTkFont(size=12), text_color=("#6B7280", "#94A3B8")).grid(row=0, column=2, padx=(0, 8), sticky="e")

        self.opt_ping_target = ctk.CTkOptionMenu(
            p_ctrl,
            values=[
                "Cloudflare DNS (1.1.1.1)",
                "Google DNS (8.8.8.8)",
                "Google Web (google.com)",
                "VnExpress (vnexpress.net)",
                "OpenDNS (208.67.222.222)",
            ],
            command=self._change_ping_target,
            width=220,
            height=32,
            font=ctk.CTkFont(size=12),
        )
        self.opt_ping_target.set("Cloudflare DNS (1.1.1.1)")
        self.opt_ping_target.grid(row=0, column=3, sticky="e")

    def _switch_tab(self, tab_title: str):
        """Chuyển đổi tab và cập nhật màu sắc thanh điều hướng 2 hàng."""
        self._update_nav_button_styles(tab_title)
        self.tabview.set(tab_title)
        self._on_tab_changed()

    def _update_nav_button_styles(self, active_title: str):
        """Cập nhật giao diện sáng của nút đang chọn và tối của các nút còn lại."""
        if not hasattr(self, "nav_buttons"):
            return
        for title, btn in self.nav_buttons.items():
            if title == active_title:
                btn.configure(
                    fg_color="#0284C7",
                    text_color="#FFFFFF",
                    hover_color="#0369A1",
                )
            else:
                btn.configure(
                    fg_color=("#F3F4F6", "#111827"),
                    text_color=("#4B5563", "#9CA3AF"),
                    hover_color=("#E5E7EB", "#374151"),
                )

    def _on_tab_changed(self):
        """Xử lý khi người dùng chuyển qua lại giữa các tab để không giật lag."""
        try:
            tab = self.tabview.get()
            self._update_nav_button_styles(tab)
            if tab == "🕸️ Sơ đồ mạng (Topology Map)":
                if hasattr(self, "topology_view"):
                    # Tự động bố trí nếu lần đầu mở tab hoặc đồng bộ danh sách thiết bị
                    need_layout = len(self.topology_view.nodes) == 0 and len(self.all_devices) > 0
                    self.topology_view.update_devices(self.all_devices, auto_layout=need_layout)
            elif tab == "📁 Ổ Chia Sẻ LAN (Shared Folders)":
                pass
            elif tab == "⚡ Đo Tốc Độ LAN (Speedtest)":
                pass
            elif tab == "📡 Kênh Sóng Wi-Fi (Channel Analyzer)":
                if hasattr(self, "spectrum_view") and len(self.spectrum_view.all_networks) == 0:
                    self.spectrum_view.refresh_scan()
            elif tab == "📈 Biểu đồ độ trễ (Ping Graph)":
                self._update_ping_ui()
        except Exception:
            pass

    def _on_ping_update(self, stats: dict, diag: dict):
        """Nhận dữ liệu từ background ping monitor thread và đẩy về UI thread."""
        self.ping_stats = stats
        self.ping_diag = diag
        # TỐI ƯU HIỆU NĂNG: Chỉ lên lịch vẽ UI nếu đang mở Tab Ping, giải phóng hoàn toàn CPU khi ở Tab Quét
        if hasattr(self, "tabview"):
            try:
                if self.tabview.get() == "📈 Biểu đồ độ trễ (Ping Graph)":
                    self.after(0, self._update_ping_ui)
            except Exception:
                pass

    def _update_ping_ui(self):
        """Cập nhật giao diện Tab Ping."""
        if not self.ping_stats or not self.ping_diag:
            return

        # Tuyệt đối không vẽ biểu đồ khi người dùng đang ở Tab khác để chống đơ/lag
        if hasattr(self, "tabview"):
            try:
                if self.tabview.get() != "📈 Biểu đồ độ trễ (Ping Graph)":
                    return
            except Exception:
                return

        stats = self.ping_stats
        diag = self.ping_diag

        r = stats["router"]
        i = stats["internet"]

        # Cập nhật thẻ Router
        r_cur_text = f"{r['cur']} ms" if r["cur"] is not None else "Timeout"
        self.lbl_p_router_cur.configure(text=r_cur_text)
        self.lbl_p_router_sub.configure(text=f"Min: {r['min']}ms • Max: {r['max']}ms • Avg: {r['avg']}ms")

        # Cập nhật thẻ Internet
        i_cur_text = f"{i['cur']} ms" if i["cur"] is not None else "Timeout"
        self.lbl_p_inet_cur.configure(text=i_cur_text)
        i_method = i.get("method", "ICMP")
        method_badge = f" • [{i_method}]" if i_method and i_method != "ICMP" else ""
        self.lbl_p_inet_sub.configure(text=f"Min: {i['min']}ms • Max: {i['max']}ms • Avg: {i['avg']}ms{method_badge}")

        # Cập nhật thẻ Packet Loss
        loss = i["loss_rate"]
        self.lbl_p_loss_cur.configure(text=f"{loss} %")
        if loss == 0:
            self.lbl_p_loss_cur.configure(text_color="#10B981")
            self.lbl_p_loss_sub.configure(text="Chất lượng kết nối hoàn hảo (0% mất)")
        elif loss < 10:
            self.lbl_p_loss_cur.configure(text_color="#F59E0B")
            self.lbl_p_loss_sub.configure(text="Mất nhẹ một số gói tin mạng")
        else:
            self.lbl_p_loss_cur.configure(text_color="#EF4444")
            self.lbl_p_loss_sub.configure(text="Cảnh báo: Mất nhiều gói tin!")

        # Cập nhật thẻ Jitter
        jitter = i["jitter"]
        self.lbl_p_jitter_cur.configure(text=f"{jitter} ms")
        if jitter < 5:
            self.lbl_p_jitter_sub.configure(text="Mạng mượt mà, độ trễ ổn định")
        else:
            self.lbl_p_jitter_sub.configure(text="Độ trễ biến thiên, chập chờn")

        # Cập nhật banner chẩn đoán
        self.lbl_diag_title.configure(text=f"{diag['badge']} — {diag['title']}", text_color=diag["color"])
        self.lbl_diag_desc.configure(text=diag["desc"])
        self.diag_card.configure(border_color=diag["color"])

        # Vẽ biểu đồ sóng Canvas
        self._render_ping_canvas(stats)

    def _render_ping_canvas(self, stats: dict):
        """Vẽ biểu đồ sóng độ trễ thời gian thực trên Canvas."""
        if not hasattr(self, "canvas") or not self.canvas.winfo_exists():
            return
        w = self.canvas.winfo_width()
        h = self.canvas.winfo_height()
        if w < 100 or h < 80:
            return

        self.canvas.delete("all")

        pad_l = 60
        pad_r = 30
        pad_t = 35
        pad_b = 30

        plot_w = w - pad_l - pad_r
        plot_h = h - pad_t - pad_b
        if plot_w <= 10 or plot_h <= 10:
            return

        r_hist = stats["history_router"]
        i_hist = stats["history_internet"]

        all_vals = [v for v in (r_hist + i_hist) if v is not None]
        max_rtt = max(all_vals) if all_vals else 50
        max_y = max(80, int(math.ceil((max_rtt + 20) / 40.0) * 40))

        grid_color = "#1E293B"
        text_color = "#94A3B8"
        y_steps = [0, int(max_y * 0.25), int(max_y * 0.5), int(max_y * 0.75), max_y]

        # Đường lưới ngang và nhãn mili-giây
        for y_val in y_steps:
            y_pos = pad_t + plot_h - (y_val / max_y) * plot_h
            self.canvas.create_line(pad_l, y_pos, w - pad_r, y_pos, fill=grid_color, dash=(3, 3) if y_val > 0 else ())
            self.canvas.create_text(pad_l - 10, y_pos, text=f"{y_val}ms", anchor="e", fill=text_color, font=("Consolas", 9))

        # Chú thích góc trên (Legends)
        self.canvas.create_rectangle(w - pad_r - 280, 12, w - pad_r - 265, 22, fill="#06B6D4", outline="")
        self.canvas.create_text(w - pad_r - 260, 17, text=f"Router LAN ({stats['router_ip']})", fill="#06B6D4", anchor="w", font=("Segoe UI", 10, "bold"))

        self.canvas.create_rectangle(w - pad_r - 120, 12, w - pad_r - 105, 22, fill="#A855F7", outline="")
        self.canvas.create_text(w - pad_r - 100, 17, text=f"Internet ({stats['internet_ip']})", fill="#A855F7", anchor="w", font=("Segoe UI", 10, "bold"))

        # Hàm vẽ đường sóng
        max_pts = PingMonitor.MAX_POINTS
        dx = plot_w / (max_pts - 1) if max_pts > 1 else plot_w

        def draw_wave(history, line_color, dot_color):
            if not history:
                return
            pts = []
            offset = max_pts - len(history)
            for idx, val in enumerate(history):
                x = pad_l + (offset + idx) * dx
                if val is not None:
                    clamped = min(val, max_y)
                    y = pad_t + plot_h - (clamped / max_y) * plot_h
                    pts.append((x, y, val))

            if len(pts) > 1:
                coord_list = []
                for x, y, _ in pts:
                    coord_list.extend([x, y])

                # Đường nối mượt
                self.canvas.create_line(coord_list, fill=line_color, width=2, smooth=True, capstyle=tk.ROUND)

                # Các điểm chấm tròn
                for x, y, _ in pts:
                    self.canvas.create_oval(x - 2, y - 2, x + 2, y + 2, fill=dot_color, outline=line_color)

                # Điểm hiện tại gần nhất có vòng sáng & nhãn số
                last_x, last_y, last_val = pts[-1]
                self.canvas.create_oval(last_x - 4, last_y - 4, last_x + 4, last_y + 4, fill=dot_color, outline="white", width=1)
                self.canvas.create_text(last_x + 6, last_y - 8, text=f"{last_val}ms", fill=line_color, font=("Segoe UI", 9, "bold"), anchor="w")

        draw_wave(r_hist, "#06B6D4", "#22D3EE")
        draw_wave(i_hist, "#A855F7", "#C084FC")

    def _toggle_ping_pause(self):
        """Tạm dừng hoặc tiếp tục đo ping."""
        if self.ping_monitor.is_paused:
            self.ping_monitor.resume()
            self.btn_ping_pause.configure(text="⏸ Tạm dừng đo")
        else:
            self.ping_monitor.pause()
            self.btn_ping_pause.configure(text="▶ Tiếp tục đo")

    def _reset_ping(self):
        """Xóa trắng lịch sử để đo lại từ đầu."""
        self.ping_monitor.reset_data()
        if self.canvas:
            self.canvas.delete("all")

    def _change_ping_target(self, choice: str):
        """Đổi máy chủ kiểm tra Internet."""
        ip = "8.8.8.8"
        if "Cloudflare" in choice:
            ip = "1.1.1.1"
        elif "OpenDNS" in choice:
            ip = "208.67.222.222"
        elif "Google Web" in choice:
            ip = "google.com"
        elif "VnExpress" in choice:
            ip = "vnexpress.net"
        self.ping_monitor.set_targets(internet_ip=ip)
        self._reset_ping()

    def _on_close(self):
        """Đóng an toàn luồng ping monitor khi tắt app."""
        try:
            self.scanner.stop_scan()
        except Exception:
            pass
        self.ping_monitor.stop()
        self.destroy()

    def _create_badge(self, master, text: str) -> ctk.CTkLabel:
        lbl = ctk.CTkLabel(
            master,
            text=text,
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color=("#E5E7EB", "#1F2937"),
            text_color=("#1F2937", "#E5E7EB"),
            corner_radius=6,
            padx=10,
            pady=4,
        )
        lbl.pack(side="left", padx=4)
        return lbl

    def _create_stat_card(self, master, col: int, title: str, init_val: str, accent_color: str) -> ctk.CTkLabel:
        card = ctk.CTkFrame(master, fg_color=("#FFFFFF", "#1E293B"), corner_radius=8)
        card.grid(row=0, column=col, padx=5, sticky="ew")

        lbl_t = ctk.CTkLabel(
            card,
            text=title,
            font=ctk.CTkFont(size=12),
            text_color=("#6B7280", "#94A3B8"),
            anchor="w",
        )
        lbl_t.pack(padx=14, pady=(10, 2), anchor="w")

        lbl_val = ctk.CTkLabel(
            card,
            text=init_val,
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color=accent_color,
            anchor="w",
        )
        lbl_val.pack(padx=14, pady=(0, 10), anchor="w")
        return lbl_val

    def _on_subnet_choice_changed(self, choice: str):
        """Xử lý khi người dùng thay đổi lựa chọn dải Subnet trong OptionMenu."""
        local_ip = self.scanner.local_ip
        if choice == "Tự động (Theo card mạng)":
            cidr = self.scanner.network_cidr
        elif choice == "Dải /24 (254 hosts)":
            cidr = str(ipaddress.IPv4Network(f"{local_ip}/24", strict=False))
        elif choice == "Dải /23 (510 hosts)":
            cidr = str(ipaddress.IPv4Network(f"{local_ip}/23", strict=False))
        elif choice == "Dải /22 (1022 hosts)":
            cidr = str(ipaddress.IPv4Network(f"{local_ip}/22", strict=False))
        else:
            # Tùy chỉnh CIDR...
            self.entry_cidr.focus()
            return

        self.entry_cidr.delete(0, "end")
        self.entry_cidr.insert(0, cidr)
        self._update_cidr_info_label(cidr)

    def _on_cidr_typed(self):
        """Cập nhật nhãn thông tin khi người dùng nhập tay CIDR."""
        cidr = self.entry_cidr.get().strip()
        self._update_cidr_info_label(cidr)

    def _update_cidr_info_label(self, cidr: str):
        """Tính toán và hiển thị số lượng host của CIDR được chọn."""
        try:
            net = ipaddress.IPv4Network(cidr, strict=False)
            hosts_count = min(net.num_addresses - 2 if net.num_addresses > 2 else 1, 2048)
            self.lbl_cidr_info.configure(
                text=f"• Mục tiêu: {net.with_prefixlen} (khoảng {hosts_count} máy)",
                text_color=("#4B5563", "#9CA3AF"),
            )
        except Exception:
            self.lbl_cidr_info.configure(
                text="⚠️ Định dạng CIDR chưa đúng (VD: 192.168.1.0/24 hoặc 192.168.0.0/23)",
                text_color="#EF4444",
            )

    def _refresh_network_badges(self):
        """Cập nhật các nhãn thông tin Wi-Fi và Router."""
        self.scanner.refresh_network_info()
        ssid = self.scanner.wifi_ssid or "Mạng LAN có dây"
        self.lbl_wifi_ssid.configure(text=f"📶 Wi-Fi: {ssid}")
        self.lbl_local_ip.configure(text=f"💻 IP: {self.scanner.local_ip} ({self.scanner.network_cidr})")
        self.lbl_gateway.configure(text=f"🌐 Router: {self.scanner.gateway_ip}")
        if hasattr(self, "opt_subnet") and self.opt_subnet.get() == "Tự động (Theo card mạng)":
            self.entry_cidr.delete(0, "end")
            self.entry_cidr.insert(0, self.scanner.network_cidr)
            self._update_cidr_info_label(self.scanner.network_cidr)

    def _toggle_theme(self):
        if self.theme_switch.get() == 1:
            ctk.set_appearance_mode("Dark")
        else:
            ctk.set_appearance_mode("Light")

    def _open_wol_window(self):
        """Mở cửa sổ Wake-on-LAN để đánh thức máy tính từ xa."""
        WakeOnLanWindow(self)

    def _open_mac_randomizer_window(self):
        """Mở cửa sổ quản lý MAC riêng tư cho adapter do người dùng quản lý."""
        MacRandomizerWindow(self)

    def _on_scan_mode_changed(self, choice: str):
        if "nhanh" in (choice or "").lower():
            self.scan_mode = "quick"
        elif "mới" in (choice or "").lower():
            self.scan_mode = "new-only"
        else:
            self.scan_mode = "full"
        self.lbl_status.configure(text=f"Chế độ quét: {choice}. Kết quả vẫn được lưu vào lịch sử.")

    def _open_adapter_selector(self):
        """Open a multi-select list of active adapters."""
        adapters = list(getattr(self.scanner, "adapters", []) or [])
        if not adapters:
            adapters = get_network_adapters()
        dialog = ctk.CTkToplevel(self)
        dialog.title("Chọn adapter mạng")
        dialog.geometry("520x360")
        dialog.transient(self)
        dialog.grab_set()
        ctk.CTkLabel(dialog, text="Chọn một hoặc nhiều adapter để quét", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=18, pady=(16, 4))
        ctk.CTkLabel(dialog, text="Adapter khác VLAN/broadcast domain có thể không nhìn thấy nhau.", text_color=("#6B7280", "#94A3B8"), wraplength=470, justify="left").pack(anchor="w", padx=18, pady=(0, 10))
        body = ctk.CTkScrollableFrame(dialog, height=210)
        body.pack(fill="both", expand=True, padx=14, pady=4)
        vars_by_index = {}
        selected = set(self.scan_adapter_indices or [])
        for pos, adapter in enumerate(adapters):
            idx = adapter.get("index", adapter.get("interface_index", pos))
            var = tk.BooleanVar(value=(not selected or idx in selected))
            vars_by_index[idx] = var
            addresses = ", ".join(str(x) for x in (adapter.get("ipv4") or [])) or "Không có IPv4"
            label = f"{adapter.get('name') or 'Adapter'}  •  {addresses}"
            ctk.CTkCheckBox(body, text=label, variable=var).pack(anchor="w", padx=8, pady=6)

        def save_selection():
            picked = [idx for idx, var in vars_by_index.items() if var.get()]
            self.scan_adapter_indices = picked
            try:
                self.scanner.set_selected_adapters(picked)
            except Exception:
                pass
            if picked:
                self.btn_adapters.configure(text=f"🧩 Adapter ({len(picked)})")
            else:
                self.btn_adapters.configure(text="🧩 Chọn adapter")
            dialog.destroy()

        footer = ctk.CTkFrame(dialog, fg_color="transparent")
        footer.pack(fill="x", padx=14, pady=(6, 14))
        ctk.CTkButton(footer, text="Hủy", width=80, fg_color=("#E5E7EB", "#374151"), text_color=("#111827", "#F9FAFB"), command=dialog.destroy).pack(side="right", padx=4)
        ctk.CTkButton(footer, text="Áp dụng", width=100, fg_color="#0F766E", hover_color="#115E59", command=save_selection).pack(side="right", padx=4)

    def _edit_device_metadata(self, device: dict):
        if self.history is None:
            messagebox.showwarning("Lịch sử không khả dụng", "Không thể mở cơ sở dữ liệu lịch sử trong profile hiện tại.")
            return
        DeviceMetadataWindow(self, device, self._on_device_metadata_saved)

    def _on_device_metadata_saved(self, device: dict, values: dict):
        if self.history is None:
            return
        metadata = self.history.set_device_metadata(device, **values)
        device.update({k: metadata.get(k) for k in ("alias", "notes", "room", "trusted")})
        self._refresh_room_filter_values()
        self._apply_filter()
        self.lbl_status.configure(text="✅ Đã lưu tên, phòng, ghi chú và trạng thái tin cậy cho thiết bị.")

    def _refresh_room_filter_values(self):
        if not hasattr(self, "room_filter_combobox"):
            return
        rooms = sorted({str(d.get("room")).strip() for d in self.all_devices if str(d.get("room", "")).strip()})
        values = ["Mọi phòng"] + rooms
        self.room_filter_combobox.configure(values=values)
        if self.room_filter_combobox.get() not in values:
            self.room_filter_combobox.set("Mọi phòng")

    def _open_history_window(self):
        if self.history is None:
            messagebox.showwarning("Lịch sử không khả dụng", "Không thể mở cơ sở dữ liệu lịch sử.")
            return
        dialog = ctk.CTkToplevel(self)
        dialog.title("Lịch sử mạng và cảnh báo")
        dialog.geometry("820x600")
        dialog.transient(self)
        dialog.grid_columnconfigure(0, weight=1)
        dialog.grid_rowconfigure(1, weight=1)
        ctk.CTkLabel(dialog, text="Snapshot, thiết bị mới/mất và thay đổi địa chỉ", font=ctk.CTkFont(size=15, weight="bold")).grid(row=0, column=0, padx=18, pady=(16, 8), sticky="w")
        scroll = ctk.CTkScrollableFrame(dialog)
        scroll.grid(row=1, column=0, padx=14, pady=4, sticky="nsew")
        scans = self.history.list_scans(30)
        events = self.history.list_events(100)
        if not scans:
            ctk.CTkLabel(scroll, text="Chưa có snapshot. Hãy chạy một lần quét.", pady=40).pack()
        for scan in scans:
            row = ctk.CTkFrame(scroll, fg_color=("#F8FAFC", "#1E293B"), corner_radius=8)
            row.pack(fill="x", padx=6, pady=4)
            ctk.CTkLabel(row, text=f"#{scan.get('id')}  {scan.get('completed_at', '')}  •  {scan.get('mode', 'full')}  •  {scan.get('device_count', 0)} thiết bị", font=ctk.CTkFont(size=12, weight="bold"), anchor="w").pack(fill="x", padx=12, pady=(8, 2))
            vis = scan.get("visibility") or {}
            ctk.CTkLabel(row, text=f"Quan sát: {vis.get('status', '—')}  |  CIDR: {scan.get('cidr') or '—'}", font=ctk.CTkFont(size=10), text_color=("#64748B", "#94A3B8"), anchor="w").pack(fill="x", padx=12, pady=(0, 8))
        if events:
            ctk.CTkLabel(scroll, text="Cảnh báo gần đây", font=ctk.CTkFont(size=13, weight="bold"), anchor="w").pack(fill="x", padx=8, pady=(16, 4))
            for event in events[:50]:
                details = event.get("details") or {}
                device = details.get("device") or {}
                text = f"{event.get('created_at', '')}  •  {event.get('event_type', '')}  •  {device.get('alias') or device.get('name') or device.get('ip') or event.get('fingerprint')}"
                ctk.CTkLabel(scroll, text=text, anchor="w", wraplength=730).pack(fill="x", padx=12, pady=2)
        ctk.CTkButton(dialog, text="Đóng", width=90, command=dialog.destroy).grid(row=2, column=0, padx=14, pady=12, sticky="e")

    def _start_scan(self):
        if self.is_scanning:
            return

        # Đọc dải Subnet từ ô cấu hình
        target_cidr = self.entry_cidr.get().strip() if hasattr(self, "entry_cidr") else self.scanner.network_cidr
        if not target_cidr:
            target_cidr = self.scanner.network_cidr
        auto_subnet = hasattr(self, "opt_subnet") and self.opt_subnet.get() == "Tự động (Theo card mạng)"

        self.is_scanning = True
        self._active_scan_mode = self.scan_mode
        self.btn_scan.configure(state="disabled", text="⏳ Đang quét...")
        self.btn_stop.configure(state="normal")
        self.progress_bar.set(0)
        self._new_only_devices = []
        mode_label = {"quick": "quét nhanh", "new-only": "chỉ thiết bị mới", "full": "quét đầy đủ"}.get(self.scan_mode, "quét đầy đủ")
        self.lbl_status.configure(text=f"Đang thực hiện {mode_label} trên {target_cidr}...")

        # Xóa danh sách hiển thị cũ
        for widget in self.list_container.winfo_children():
            widget.destroy()
        self.all_devices = []
        self._live_devices = self.all_devices
        self._update_stat_counts()

        # Cập nhật thông tin mạng
        self._refresh_network_badges()

        # Đọc tùy chọn UI trước khi rời main thread (Tkinter không thread-safe).
        configured_retries = 1 if self._active_scan_mode == "quick" else 2
        try:
            configured_retries = int(str(self.retry_menu.get()).split()[-1])
        except (AttributeError, ValueError):
            pass
        try:
            configured_rate_limit = float(str(self.rate_menu.get()).split()[-2])
        except (AttributeError, ValueError, IndexError):
            configured_rate_limit = 0.0
        selected_adapter_indices = {str(index) for index in (self.scan_adapter_indices or [])}

        # Bắt đầu quét trên luồng riêng biệt
        def scan_worker():
            def on_device_found(dev):
                self.device_queue.put(("device", dev))

            def on_progress(current, total):
                self.device_queue.put(("progress", (current, total)))

            try:
                max_hosts = 256 if self._active_scan_mode == "quick" else 2048
                retries = configured_retries
                rate_limit_ms = configured_rate_limit
                devices = self.scanner.scan_subnet(
                    # Để engine tổng hợp các subnet khi chọn nhiều adapter;
                    # CIDR tùy chỉnh vẫn được tôn trọng tuyệt đối.
                    base_subnet=None if auto_subnet else target_cidr,
                    on_device_found=on_device_found,
                    on_progress=on_progress,
                    on_completed=None,
                    retries=retries,
                    rate_limit_ms=rate_limit_ms,
                    max_hosts=max_hosts,
                    include_ipv6=False,
                    scan_mode=self._active_scan_mode,
                    # Let the scanner use the freshly refreshed adapter list;
                    # selected indexes are retained on the scanner instance.
                    adapter_configs=None,
                )

                if self.scanner.should_stop:
                    self.device_queue.put(("cancelled", {"devices": devices}))
                    return

                # Discovery protocols bổ sung thông tin nhưng không thay thế
                # kết quả ARP; mọi trường hợp đều được gắn độ tin cậy.
                try:
                    raw_discovery = run_local_discovery(timeout=0.65)
                    devices = enrich_devices(
                        devices,
                        ssdp_results=raw_discovery.get("ssdp"),
                        mdns_results=raw_discovery.get("mdns"),
                        ipv6_neighbors=raw_discovery.get("ipv6"),
                        dhcp_hostnames=raw_discovery.get("dhcp"),
                    )
                except Exception as discovery_error:
                    raw_discovery = {"ssdp": [], "mdns": [], "ipv6": [], "dhcp": {}, "error": str(discovery_error)}

                if auto_subnet:
                    # Mirror the scanner's bounded /24 fallback for broad
                    # adapter prefixes so visibility ratios are meaningful.
                    expected_networks = {}
                    active_configs = list(getattr(self.scanner, "adapters", []) or [])
                    if selected_adapter_indices:
                        active_configs = [
                            config for config in active_configs
                            if str(config.get("index", config.get("interface_index"))) in selected_adapter_indices
                        ]
                    for config in active_configs:
                        for address in config.get("ipv4", []) or []:
                            try:
                                if isinstance(address, dict):
                                    ip_value = address.get("IPv4Address") or address.get("IPAddress") or ""
                                    prefix = address.get("PrefixLength")
                                else:
                                    parts = str(address).split("/", 1)
                                    ip_value = parts[0]
                                    prefix = parts[1] if len(parts) > 1 else None
                                network = ipaddress.IPv4Network(f"{ip_value}/{prefix or self.scanner.subnet_mask}", strict=False)
                                if network.num_addresses > 1024:
                                    network = ipaddress.IPv4Network(f"{ip_value}/24", strict=False)
                                expected_networks[network.with_prefixlen] = network
                            except (TypeError, ValueError):
                                continue
                    expected = min(
                        max_hosts,
                        sum(max(0, int(network.num_addresses) - 2) for network in expected_networks.values()),
                    ) if expected_networks else len(devices)
                else:
                    try:
                        expected = max(0, ipaddress.IPv4Network(target_cidr, strict=False).num_addresses - 2)
                    except Exception:
                        expected = len(devices)
                visibility = assess_visibility(
                    expected_hosts=expected,
                    devices=devices,
                    gateway_reachable=any(d.get("is_gateway") for d in devices),
                    adapter_count=len(self.scan_adapter_indices or getattr(self.scanner, "adapters", []) or [1]),
                )
                changes = self.history.record_scan(
                    devices,
                    mode=self._active_scan_mode,
                    cidr=target_cidr,
                    adapters=getattr(self.scanner, "adapters", []),
                    visibility=visibility,
                ) if self.history is not None else {"new": [], "removed": [], "changed": [], "events": []}
                if self.history is not None:
                    devices = self.history.apply_metadata_many(devices)
                self.device_queue.put(("completed", {"devices": devices, "changes": changes, "visibility": visibility, "discovery": raw_discovery}))
            except Exception as exc:
                self.device_queue.put(("error", str(exc)))

        thread = threading.Thread(target=scan_worker, daemon=True)
        thread.start()

    def _stop_scan(self):
        if self.is_scanning:
            self.scanner.stop_scan()
            self.lbl_status.configure(text="Đang dừng tiến trình quét theo yêu cầu...")
            self.btn_stop.configure(state="disabled")

    def _process_queue(self):
        """Đọc kết quả từ hàng đợi queue và cập nhật UI mượt mà, không bao giờ giật lag."""
        try:
            latest_progress = None
            new_devices = []
            is_completed = False
            completed_payload = None
            cancelled_payload = None
            scan_error = None

            # Xử lý tối đa 40 item mỗi đợt để luôn nhường tài nguyên cho Windows xử lý click chuột/chuyển tab
            processed = 0
            while not self.device_queue.empty() and processed < 40:
                processed += 1
                msg_type, data = self.device_queue.get_nowait()

                if msg_type == "device":
                    new_devices.append(data)
                elif msg_type == "progress":
                    # Giữ giá trị tiến trình mới nhất, không vẽ lại thanh tiến trình lặp lại hàng chục lần
                    latest_progress = data
                elif msg_type == "completed":
                    is_completed = True
                    completed_payload = data
                elif msg_type == "error":
                    scan_error = data
                elif msg_type == "cancelled":
                    cancelled_payload = data

            if scan_error:
                self.is_scanning = False
                self.btn_scan.configure(state="normal", text="🚀 Bắt đầu quét mạng")
                self.btn_stop.configure(state="disabled")
                self.lbl_status.configure(text=f"❌ Quét thất bại: {scan_error}")

            # 1. Hiển thị các thiết bị mới tìm thấy
            if new_devices:
                if hasattr(self, "lbl_empty_state") and self.lbl_empty_state.winfo_exists():
                    self.lbl_empty_state.grid_forget()

                if self.history is not None:
                    new_devices = self.history.apply_metadata_many(new_devices)
                for dev in new_devices:
                    self._live_devices.append(dev)
                    if self._active_scan_mode != "new-only" and self._matches_filter(dev):
                        row = DeviceRow(
                            self.list_container,
                            dev,
                            on_copy_callback=self._show_toast,
                        )
                        row.pack(fill="x", padx=5, pady=3)

                # Chỉ tính toán số liệu thống kê 1 lần cho cả lô thiết bị mới
                self._update_stat_counts()

            # 2. Cập nhật thanh tiến trình 1 lần duy nhất cho giá trị mới nhất
            if latest_progress:
                current, total = latest_progress
                frac = current / total if total > 0 else 0
                self.progress_bar.set(frac)
                self.lbl_status.configure(
                    text=f"Đang quét IP: {current}/{total} • Đã tìm thấy {len(self.all_devices)} thiết bị đang online"
                )

            # 3. Dừng giữa chừng: giữ kết quả tạm nhưng không ghi snapshot/diff.
            if cancelled_payload is not None:
                partial_devices = list((cancelled_payload or {}).get("devices") or self.all_devices)
                if self.history is not None:
                    partial_devices = self.history.apply_metadata_many(partial_devices)
                self.all_devices = partial_devices
                self._new_only_devices = partial_devices
                self.is_scanning = False
                self.btn_scan.configure(state="normal", text="🚀 Bắt đầu quét mạng")
                self.btn_stop.configure(state="disabled")
                self.lbl_status.configure(text=f"⏹ Đã dừng quét. Hiển thị {len(self.all_devices)} kết quả tạm; snapshot lịch sử không được cập nhật.")
                self._refresh_room_filter_values()
                self._apply_filter()
                if hasattr(self, "topology_view"):
                    self.topology_view.update_devices(self.all_devices, auto_layout=True)

            # 4. Khi quét hoàn tất
            elif is_completed:
                if isinstance(completed_payload, dict):
                    final_devices = list(completed_payload.get("devices") or [])
                    self.last_scan_result = dict(completed_payload)
                    changes = completed_payload.get("changes") or {}
                    self.all_devices = final_devices
                    self._refresh_room_filter_values()
                    if self._active_scan_mode == "new-only":
                        new_keys = {d.get("fingerprint") or device_fingerprint(d) for d in changes.get("new", [])}
                        self._new_only_devices = [d for d in self.all_devices if (d.get("fingerprint") or device_fingerprint(d)) in new_keys]
                    else:
                        self._new_only_devices = []
                    if changes:
                        try:
                            notify_changes(changes)
                        except Exception:
                            pass
                self.is_scanning = False
                self.btn_scan.configure(state="normal", text="🚀 Bắt đầu quét mạng")
                self.btn_stop.configure(state="disabled")
                self.progress_bar.set(1.0)
                now_str = datetime.now().strftime("%H:%M:%S")
                self.lbl_timestamp.configure(text=f"Quét lần cuối: {now_str}")
                visibility = (completed_payload or {}).get("visibility") if isinstance(completed_payload, dict) else None
                suffix = f" • {visibility.get('status')}" if isinstance(visibility, dict) and visibility.get("status") else ""
                if isinstance(visibility, dict) and hasattr(self, "lbl_cidr_info"):
                    evidence = " | ".join(visibility.get("evidence") or [])
                    self.lbl_cidr_info.configure(
                        text=f"• Quan sát: {visibility.get('found_hosts', len(self.all_devices))} host • {visibility.get('status', '—')}" + (f" — {evidence}" if evidence else ""),
                        text_color="#F59E0B" if visibility.get("evidence") else ("#4B5563", "#9CA3AF"),
                    )
                shown_count = len(getattr(self, "_new_only_devices", []) or self.all_devices) if self._active_scan_mode == "new-only" else len(self.all_devices)
                self.lbl_status.configure(text=f"✅ Hoàn tất! {shown_count} thiết bị hiển thị (tổng quan sát {len(self.all_devices)}).{suffix}")
                # Chỉ sắp xếp lại toàn bộ bảng nếu có nhiều hơn 1 thiết bị
                if len(self.all_devices) > 1 or self._active_scan_mode == "new-only":
                    self._apply_filter()

                # Tự động đồng bộ hóa sơ đồ mạng hình sao
                if hasattr(self, "topology_view"):
                    self.topology_view.update_devices(self.all_devices, auto_layout=True)

        except Exception as e:
            print(f"Lỗi hàng đợi: {e}")

        # Tần suất đọc queue: 70ms khi đang quét, 150ms khi nhàn rỗi (giảm tải CPU triệt để)
        delay = 70 if self.is_scanning else 150
        self.after(delay, self._process_queue)

    def _on_search_key(self, event=None):
        """Trì hoãn lọc kết quả 150ms khi người dùng gõ phím để giao diện không bị giật."""
        if hasattr(self, "_search_timer") and self._search_timer:
            try:
                self.after_cancel(self._search_timer)
            except Exception:
                pass
        self._search_timer = self.after(150, self._apply_filter)

    def _update_stat_counts(self):
        """Cập nhật các số liệu thống kê trên các thẻ card."""
        total = len(self.all_devices)
        routers = sum(1 for d in self.all_devices if d.get("is_gateway") or d.get("category") == "router")
        privates = sum(1 for d in self.all_devices if d.get("is_random_mac"))
        identified = sum(1 for d in self.all_devices if d.get("vendor") not in ("Chưa rõ", "Không xác định", "Broadcast / Hệ thống"))

        self.card_total.configure(text=f"{total} máy")
        self.card_router.configure(text=str(routers))
        self.card_identified.configure(text=str(identified))
        self.card_private.configure(text=str(privates))

    def _matches_filter(self, d: dict) -> bool:
        """Kiểm tra thiết bị có thỏa mãn từ khóa tìm kiếm và danh mục lọc không."""
        # 1. Kiểm tra danh mục
        sel_cat = self.filter_combobox.get()
        if sel_cat == "Chỉ Router/Gateway" and not (d.get("is_gateway") or d.get("category") == "router"):
            return False
        if sel_cat == "Chỉ Điện thoại / Di động" and d.get("category") not in ("mobile", "private"):
            return False
        if sel_cat == "Chỉ Máy tính" and d.get("category") != "pc" and not d.get("is_self"):
            return False
        if sel_cat == "Chỉ MAC Bảo mật" and not d.get("is_random_mac"):
            return False

        room_filter = self.room_filter_combobox.get() if hasattr(self, "room_filter_combobox") else "Mọi phòng"
        if room_filter != "Mọi phòng" and (d.get("room") or "").strip() != room_filter:
            return False

        risk_filter = self.risk_filter_combobox.get() if hasattr(self, "risk_filter_combobox") else "Mọi mức rủi ro"
        risk = str(d.get("risk_level") or d.get("risk") or "").lower()
        if risk_filter == "Rủi ro cao" and risk not in ("critical", "high", "confirmed", "suspicious"):
            return False
        if risk_filter == "Có cảnh báo" and risk in ("", "safe", "low", "none"):
            return False
        if risk_filter == "An toàn / tin cậy" and not (d.get("trusted") or risk in ("", "safe", "low")):
            return False

        # 2. Kiểm tra từ khóa tìm kiếm
        query = self.search_entry.get().strip().lower()
        if not query:
            return True

        ip = d.get("ip", "").lower()
        mac = d.get("mac", "").lower()
        name = (d.get("alias") or d.get("name", "")).lower()
        vendor = d.get("vendor", "").lower()
        hint = d.get("hint", "").lower()
        notes = d.get("notes", "").lower()

        return (query in ip or query in mac or query in name or query in vendor or query in hint or query in notes)

    def _apply_filter(self):
        """Vẽ lại toàn bộ danh sách thiết bị khi tìm kiếm hoặc đổi bộ lọc."""
        for widget in self.list_container.winfo_children():
            widget.destroy()

        # Sắp xếp: Gateway -> Máy này -> IP
        def sort_key(d):
            if d.get("is_gateway"):
                return -2
            if d.get("is_self"):
                return -1
            try:
                return int(d["ip"].split(".")[-1])
            except Exception:
                return 999

        source_devices = getattr(self, "_new_only_devices", None) if getattr(self, "_active_scan_mode", "full") == "new-only" else self.all_devices
        source_devices = source_devices if source_devices is not None else self.all_devices
        sorted_devs = sorted(source_devices, key=sort_key)
        matched = [d for d in sorted_devs if self._matches_filter(d)]

        if not matched:
            lbl_none = ctk.CTkLabel(
                self.list_container,
                text="Không tìm thấy thiết bị nào phù hợp với bộ lọc.",
                font=ctk.CTkFont(size=14),
                text_color=("#6B7280", "#9CA3AF"),
                pady=50,
            )
            lbl_none.pack()
            return

        for dev in matched:
            row = DeviceRow(
                self.list_container,
                dev,
                on_copy_callback=self._show_toast,
            )
            row.pack(fill="x", padx=5, pady=3)

    def _show_toast(self, message: str):
        """Hiển thị thông báo ngắn dưới thanh trạng thái."""
        self.lbl_status.configure(text=f"📋 {message}")

    def _export_data(self):
        """Xuất CSV/JSON hoặc báo cáo HTML/PDF có bằng chứng."""
        if not self.all_devices:
            messagebox.showinfo("Thông báo", "Chưa có dữ liệu thiết bị nào để xuất. Hãy quét mạng trước!")
            return

        filepath = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[
                ("Báo cáo HTML", "*.html"),
                ("Báo cáo PDF", "*.pdf"),
                ("Tệp CSV (Excel)", "*.csv"),
                ("Tệp JSON", "*.json"),
            ],
            initialfile=f"Wifi_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
            title="Lưu danh sách thiết bị",
        )
        if not filepath:
            return

        lower_path = filepath.lower()
        result_message = ""
        if lower_path.endswith(".json"):
            ok = export_to_json(self.all_devices, filepath, scan_result=self.last_scan_result, security_result=self.last_security_dashboard)
            result_message = f"Đã xuất JSON: {filepath}"
        elif lower_path.endswith(".html"):
            ok = export_report_html(self.all_devices, filepath, scan_result=self.last_scan_result, security_result=self.last_security_dashboard)
            result_message = f"Đã xuất HTML: {filepath}"
        elif lower_path.endswith(".pdf"):
            pdf_result = export_report_pdf(self.all_devices, filepath, scan_result=self.last_scan_result, security_result=self.last_security_dashboard)
            ok = bool(pdf_result.get("ok"))
            result_message = f"Đã xuất PDF: {filepath}" if ok else f"Không thể tạo PDF: {pdf_result.get('error', 'lỗi không xác định')}"
        else:
            ok = export_to_csv(self.all_devices, filepath)
            result_message = f"Đã xuất CSV: {filepath}"

        if ok:
            messagebox.showinfo("Thành công", result_message)
        else:
            messagebox.showerror("Lỗi", result_message or "Không thể xuất file. Vui lòng kiểm tra quyền ghi tệp.")

    # =========================================================================
    # TAB 3: ĐÁNH GIÁ AN NINH WI-FI & ROUTER (SECURITY AUDIT)
    # =========================================================================
    def _setup_tab_security(self):
        """Thiết lập nội dung Tab 3: Đánh giá An ninh mạng Wi-Fi & Router."""
        self.tab_security.grid_columnconfigure(0, weight=1)
        self.tab_security.grid_rowconfigure(2, weight=1)

        # 1. Thanh điều khiển trên cùng
        ctrl_frame = ctk.CTkFrame(self.tab_security, fg_color="transparent")
        ctrl_frame.grid(row=0, column=0, padx=5, pady=(5, 4), sticky="ew")
        ctrl_frame.grid_columnconfigure(2, weight=1)

        self.btn_run_audit = ctk.CTkButton(
            ctrl_frame,
            text="🛡️ Bắt đầu Đánh Giá An Ninh",
            font=ctk.CTkFont(size=13, weight="bold"),
            height=36,
            width=210,
            fg_color="#059669",
            hover_color="#047857",
            command=self._start_security_audit,
        )
        self.btn_run_audit.grid(row=0, column=0, padx=(0, 10), sticky="w")

        btn_open_router = ctk.CTkButton(
            ctrl_frame,
            text="🌐 Vào Trang Quản Trị Modem",
            font=ctk.CTkFont(size=12, weight="bold"),
            height=36,
            width=190,
            fg_color=("#E5E7EB", "#374151"),
            text_color=("#111827", "#F9FAFB"),
            hover_color=("#D1D5DB", "#4B5563"),
            command=lambda: webbrowser.open(f"http://{self.scanner.gateway_ip}"),
        )
        btn_open_router.grid(row=0, column=1, padx=(0, 15), sticky="w")

        self.lbl_sec_status = ctk.CTkLabel(
            ctrl_frame,
            text="Bấm 'Bắt đầu Đánh Giá An Ninh' để kiểm tra chuẩn mã hóa Wi-Fi, cổng nhạy cảm Router và DNS.",
            font=ctk.CTkFont(size=12),
            text_color=("#4B5563", "#94A3B8"),
            anchor="w",
        )
        self.lbl_sec_status.grid(row=0, column=2, sticky="w")

        self.sec_progress_bar = ctk.CTkProgressBar(self.tab_security, height=5)
        self.sec_progress_bar.grid(row=0, column=0, padx=5, pady=(45, 0), sticky="ew")
        self.sec_progress_bar.set(0)

        # 2. Khung Điểm An Ninh Tổng Thể (Score Banner Card)
        self.sec_score_card = ctk.CTkFrame(
            self.tab_security,
            fg_color=("#F0FDF4", "#062817"),
            border_width=1,
            border_color="#10B981",
            corner_radius=8,
        )
        self.sec_score_card.grid(row=1, column=0, padx=5, pady=(10, 6), sticky="ew")
        self.sec_score_card.grid_columnconfigure(1, weight=1)

        # Điểm số bên trái
        score_left = ctk.CTkFrame(self.sec_score_card, fg_color="transparent")
        score_left.grid(row=0, column=0, padx=20, pady=12)

        self.lbl_sec_score = ctk.CTkLabel(
            score_left,
            text="— / 100",
            font=ctk.CTkFont(size=30, weight="bold"),
            text_color="#10B981",
        )
        self.lbl_sec_score.pack()

        ctk.CTkLabel(
            score_left,
            text="ĐIỂM AN NINH",
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color=("#4B5563", "#94A3B8"),
        ).pack()

        # Thông tin đánh giá bên phải
        score_right = ctk.CTkFrame(self.sec_score_card, fg_color="transparent")
        score_right.grid(row=0, column=1, padx=10, pady=12, sticky="ew")

        self.lbl_sec_grade_badge = ctk.CTkLabel(
            score_right,
            text="🛡️ CHƯA THỰC HIỆN ĐÁNH GIÁ",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=("#065F46", "#34D399"),
            anchor="w",
        )
        self.lbl_sec_grade_badge.pack(anchor="w")

        self.lbl_sec_summary = ctk.CTkLabel(
            score_right,
            text="Hệ thống sẽ kiểm tra xem Wi-Fi của bạn có dễ bị bẻ khóa hay không, Router có đang mở cổng nguy hiểm như Telnet hay UPnP không, và kiểm tra tính toàn vẹn của máy chủ DNS.",
            font=ctk.CTkFont(size=12),
            text_color=("#374151", "#E5E7EB"),
            anchor="w",
            wraplength=750,
            justify="left",
        )
        self.lbl_sec_summary.pack(anchor="w", pady=(2, 0))

        # 3. Khung cuộn hiển thị 4 Hạng mục chi tiết (Scrollable Container)
        self.sec_scroll = ctk.CTkScrollableFrame(self.tab_security, fg_color=("#FFFFFF", "#111827"), corner_radius=8)
        self.sec_scroll.grid(row=2, column=0, padx=5, pady=(0, 6), sticky="nsew")
        self.sec_scroll.grid_columnconfigure(0, weight=1)

        # Placeholder ban đầu trước khi quét
        self.lbl_sec_placeholder = ctk.CTkLabel(
            self.sec_scroll,
            text="🔒 Nhấn nút 'Bắt đầu Đánh Giá An Ninh' ở trên để tiến hành kiểm tra toàn diện.",
            font=ctk.CTkFont(size=13),
            text_color=("#6B7280", "#9CA3AF"),
            pady=80,
        )
        self.lbl_sec_placeholder.pack()

    def _start_security_audit(self):
        """Bắt đầu chạy luồng kiểm tra an ninh mạng."""
        if self.is_auditing:
            return
        self.is_auditing = True
        self.btn_run_audit.configure(state="disabled", text="⏳ Đang kiểm tra an ninh...")
        self.sec_progress_bar.set(0.1)
        self.lbl_sec_status.configure(text="Đang phân tích chuẩn mã hóa Wi-Fi và các cổng nhạy cảm Router...")

        gateway_ip = self.scanner.gateway_ip if hasattr(self, "scanner") and self.scanner.gateway_ip else "192.168.1.1"

        def worker():
            # 1. Kiểm tra Wi-Fi
            wifi_info = get_wifi_security_info()
            self.after(0, lambda: self.sec_progress_bar.set(0.35))

            # 2. Quét cổng nhạy cảm Router
            def on_port_prog(checked, total):
                prog = 0.35 + (checked / total) * 0.4
                self.after(0, lambda: self.sec_progress_bar.set(prog))

            router_ports = audit_router_ports(gateway_ip, on_progress=on_port_prog)

            # 3. Kiểm tra DNS & Canary
            self.after(0, lambda: self.sec_progress_bar.set(0.85))
            dns_info = audit_dns_security()

            # 4. Kiểm tra dịch vụ trên gateway và một số peer đã phát hiện.
            dashboard = run_security_dashboard(gateway_ip, self.all_devices[:8], timeout=0.45, dns_info=dns_info)

            # 5. Tính toán điểm số & đánh giá
            eval_res = evaluate_security_audit(wifi_info, router_ports, dns_info, dashboard)

            self.after(0, lambda: self.sec_progress_bar.set(1.0))
            self.after(0, lambda: self._on_audit_finished(wifi_info, router_ports, dns_info, eval_res, dashboard))

        threading.Thread(target=worker, daemon=True).start()

    def _on_audit_finished(self, wifi_info: dict, router_ports: list, dns_info: dict, eval_res: dict, dashboard=None):
        """Hiển thị kết quả đánh giá an ninh lên giao diện."""
        self.is_auditing = False
        self.last_security_dashboard = dashboard or {}
        self._apply_security_findings_to_devices(self.last_security_dashboard)
        self.btn_run_audit.configure(state="normal", text="🛡️ Đánh Giá Lại An Ninh")
        self.lbl_sec_status.configure(text=f"✅ Hoàn tất đánh giá an ninh! Điểm số: {eval_res['score']}/100 (Hạng {eval_res['grade']})")

        # Cập nhật khung điểm số
        self.lbl_sec_score.configure(text=f"{eval_res['score']} / 100", text_color=eval_res["badge_color"])
        self.lbl_sec_grade_badge.configure(text=f"{eval_res['badge_text']} — HẠNG {eval_res['grade']}", text_color=eval_res["badge_color"])
        self.sec_score_card.configure(border_color=eval_res["badge_color"])

        summary_txt = f"Mạng Wi-Fi ({wifi_info.get('ssid')}) sử dụng xác thực {wifi_info.get('auth')} ({wifi_info.get('cipher')}). "
        open_ports_count = sum(1 for p in router_ports if p["is_open"])
        risky_count = sum(1 for p in router_ports if p["is_open"] and p["risk"] in ("critical", "high"))
        service_risk_count = sum(1 for f in (dashboard or {}).get("findings", []) if f.get("risk") in ("critical", "high", "medium") and f.get("status") in ("open", "endpoint_reachable", "ssdp_response", "guest_confirmed"))
        if risky_count > 0 or service_risk_count > 0:
            summary_txt += f"⚠️ Có {risky_count + service_risk_count} quan sát dịch vụ cần kiểm tra (kèm bằng chứng/banners bên dưới)."
        else:
            summary_txt += "Các cổng nguy hiểm (Telnet, FTP, UPnP) trên Router đều đã được đóng an toàn. Máy chủ DNS hoạt động chính xác."
        self.lbl_sec_summary.configure(text=summary_txt)

        # Xóa nội dung cũ trong scroll container
        for w in self.sec_scroll.winfo_children():
            w.destroy()

        gateway_ip = self.scanner.gateway_ip if hasattr(self, "scanner") and self.scanner.gateway_ip else "192.168.1.1"

        # Vẽ các thẻ hạng mục chi tiết
        self._render_audit_card_wifi(self.sec_scroll, wifi_info)
        self._render_audit_card_ports(self.sec_scroll, router_ports, gateway_ip)
        self._render_audit_card_dns(self.sec_scroll, dns_info)
        if dashboard:
            self._render_audit_card_dashboard(self.sec_scroll, dashboard)
        self._render_audit_card_recommendations(self.sec_scroll, eval_res, gateway_ip)

    def _apply_security_findings_to_devices(self, dashboard: dict):
        """Attach the strongest observed service risk to matching device rows."""
        priority = {"critical": 4, "high": 3, "medium": 2, "low": 1, "safe": 0}
        by_host = {}
        for finding in dashboard.get("findings", []) if isinstance(dashboard, dict) else []:
            host = str(finding.get("host", "")).lower()
            risk = str(finding.get("risk", "safe")).lower()
            status = str(finding.get("status", "")).lower()
            if not host or status not in ("open", "endpoint_reachable", "ssdp_response", "guest_confirmed"):
                continue
            if priority.get(risk, 0) >= priority.get(str(by_host.get(host, {}).get("risk", "safe")), 0):
                by_host[host] = finding
        for device in self.all_devices:
            host = str(device.get("ip", "")).lower()
            finding = by_host.get(host)
            if finding:
                device["risk_level"] = finding.get("risk", "medium")
                device["risk_evidence"] = finding.get("evidence", "")
                device["risk_remediation"] = finding.get("remediation", "")
            elif not device.get("risk_level"):
                device["risk_level"] = "safe" if device.get("trusted") or device.get("is_gateway") or device.get("is_self") else "unknown"
        self._apply_filter()

    def _render_audit_card_wifi(self, master, wifi_info: dict):
        """Vẽ thẻ 1: Chuẩn mã hóa Wi-Fi."""
        card = ctk.CTkFrame(master, fg_color=("#F9FAFB", "#1E222B"), corner_radius=8)
        card.pack(fill="x", padx=6, pady=6)
        card.grid_columnconfigure(1, weight=1)

        lbl_t = ctk.CTkLabel(card, text="📶 1. Chuẩn bảo mật & Mã hóa sóng Wi-Fi", font=ctk.CTkFont(size=14, weight="bold"), anchor="w")
        lbl_t.pack(padx=14, pady=(10, 6), anchor="w")

        info_box = ctk.CTkFrame(card, fg_color="transparent")
        info_box.pack(padx=14, pady=(0, 6), fill="x")
        for i in range(4):
            info_box.grid_columnconfigure(i, weight=1)

        def add_sub(col, title, val, color=None):
            f = ctk.CTkFrame(info_box, fg_color=("#FFFFFF", "#111827"), corner_radius=6)
            f.grid(row=0, column=col, padx=4, pady=2, sticky="ew")
            ctk.CTkLabel(f, text=title, font=ctk.CTkFont(size=10, weight="bold"), text_color=("#6B7280", "#94A3B8")).pack(padx=8, pady=(6, 1), anchor="w")
            lbl_v = ctk.CTkLabel(f, text=val, font=ctk.CTkFont(size=12, weight="bold"), text_color=color or ("#111827", "#F9FAFB"))
            lbl_v.pack(padx=8, pady=(0, 6), anchor="w")

        level = wifi_info.get("security_level", "good")
        auth_color = "#10B981" if level in ("good", "excellent") else ("#EF4444" if level == "dangerous" else "#F59E0B")
        add_sub(0, "TÊN MẠNG (SSID)", wifi_info.get("ssid", "Chưa rõ"))
        add_sub(1, "CHUẨN XÁC THỰC", wifi_info.get("auth", "—"), auth_color)
        add_sub(2, "THUẬT TOÁN MÃ HÓA", wifi_info.get("cipher", "—"), "#0284C7")
        band_str = f"{wifi_info.get('band')} • {wifi_info.get('radio')}"
        add_sub(3, "BĂNG TẦN & TÍN HIỆU", f"{band_str} ({wifi_info.get('signal')}%)")

        note_card = ctk.CTkFrame(card, fg_color=("#EFF6FF", "#172554"), corner_radius=6)
        note_card.pack(padx=14, pady=(4, 10), fill="x")
        ctk.CTkLabel(
            note_card,
            text=f"💡 Đánh giá: {wifi_info.get('security_note')}",
            font=ctk.CTkFont(size=11),
            text_color=("#1E40AF", "#93C5FD"),
            anchor="w",
            wraplength=800,
            justify="left",
        ).pack(padx=10, pady=6, anchor="w")

    def _render_audit_card_ports(self, master, router_ports: list, gateway_ip: str):
        """Vẽ thẻ 2: Quét các cổng nhạy cảm trên Router."""
        card = ctk.CTkFrame(master, fg_color=("#F9FAFB", "#1E222B"), corner_radius=8)
        card.pack(fill="x", padx=6, pady=6)

        lbl_t = ctk.CTkLabel(card, text=f"🌐 2. Cổng dịch vụ nhạy cảm trên Router / Gateway ({gateway_ip})", font=ctk.CTkFont(size=14, weight="bold"), anchor="w")
        lbl_t.pack(padx=14, pady=(10, 6), anchor="w")

        p_grid = ctk.CTkFrame(card, fg_color="transparent")
        p_grid.pack(padx=14, pady=(0, 10), fill="x")
        p_grid.grid_columnconfigure(0, weight=1)
        p_grid.grid_columnconfigure(1, weight=1)

        for idx, p in enumerate(router_ports):
            row_idx = idx // 2
            col_idx = idx % 2

            p_box = ctk.CTkFrame(p_grid, fg_color=("#FFFFFF", "#111827"), corner_radius=6)
            p_box.grid(row=row_idx, column=col_idx, padx=4, pady=3, sticky="nsew")
            p_box.grid_columnconfigure(1, weight=1)

            port_num = p["port"]
            name = p["name"]
            is_open = p["is_open"]
            risk = p["risk"]

            if is_open:
                if risk == "critical":
                    b_text = "🔴 NGUY HIỂM (MỞ)"
                    b_color = "#EF4444"
                elif risk == "high":
                    b_text = "🟠 RỦI RO CAO (MỞ)"
                    b_color = "#F97316"
                elif risk == "medium":
                    b_text = "🟡 CẢNH BÁO (MỞ)"
                    b_color = "#F59E0B"
                elif risk == "safe":
                    b_text = "🟢 HOẠT ĐỘNG"
                    b_color = "#10B981"
                else:
                    b_text = "🟢 ĐANG MỞ"
                    b_color = "#0284C7"
            else:
                b_text = "🟢 ĐÃ ĐÓNG (AN TOÀN)"
                b_color = "#059669"

            lbl_badge = ctk.CTkLabel(
                p_box,
                text=b_text,
                font=ctk.CTkFont(size=10, weight="bold"),
                fg_color=b_color,
                text_color="white",
                corner_radius=4,
                padx=6,
                pady=2,
            )
            lbl_badge.grid(row=0, column=0, padx=8, pady=(6, 2), sticky="w")

            lbl_pname = ctk.CTkLabel(
                p_box,
                text=f"Port {port_num} — {name}",
                font=ctk.CTkFont(size=12, weight="bold"),
                anchor="w",
            )
            lbl_pname.grid(row=0, column=1, padx=4, pady=(6, 2), sticky="w")

            lbl_desc = ctk.CTkLabel(
                p_box,
                text=p["risk_desc"],
                font=ctk.CTkFont(size=10),
                text_color=("#6B7280", "#94A3B8"),
                anchor="w",
                wraplength=380,
                justify="left",
            )
            lbl_desc.grid(row=1, column=0, columnspan=2, padx=8, pady=(0, 6), sticky="w")
            if is_open and p.get("recommendation"):
                ctk.CTkLabel(
                    p_box,
                    text=f"Khắc phục: {p.get('recommendation')}",
                    font=ctk.CTkFont(size=10),
                    text_color=("#92400E", "#FCD34D") if risk in ("critical", "high", "medium") else ("#4B5563", "#CBD5E1"),
                    anchor="w",
                    wraplength=380,
                    justify="left",
                ).grid(row=2, column=0, columnspan=2, padx=8, pady=(0, 7), sticky="w")

    def _render_audit_card_dns(self, master, dns_info: dict):
        """Vẽ thẻ 3: Máy chủ DNS & Chống giả mạo."""
        card = ctk.CTkFrame(master, fg_color=("#F9FAFB", "#1E222B"), corner_radius=8)
        card.pack(fill="x", padx=6, pady=6)

        lbl_t = ctk.CTkLabel(card, text="🔒 3. Máy chủ DNS & Chống điều hướng độc hại (DNS Hijacking)", font=ctk.CTkFont(size=14, weight="bold"), anchor="w")
        lbl_t.pack(padx=14, pady=(10, 6), anchor="w")

        box = ctk.CTkFrame(card, fg_color=("#FFFFFF", "#111827"), corner_radius=6)
        box.pack(padx=14, pady=(0, 10), fill="x")

        dns_list = ", ".join(dns_info.get("dns_servers", []))
        primary = dns_info.get("primary_dns", "") or "Chưa xác định"
        pname = dns_info.get("provider_name", "") or "Không xác định"

        row1 = ctk.CTkFrame(box, fg_color="transparent")
        row1.pack(padx=10, pady=(8, 2), fill="x")
        ctk.CTkLabel(row1, text="Máy chủ DNS hiện tại:", font=ctk.CTkFont(size=12, weight="bold"), width=160, anchor="w").pack(side="left")
        ctk.CTkLabel(row1, text=f"{primary} ({pname})", font=ctk.CTkFont(family="Consolas", size=12), text_color="#0284C7").pack(side="left")

        row2 = ctk.CTkFrame(box, fg_color="transparent")
        row2.pack(padx=10, pady=2, fill="x")
        ctk.CTkLabel(row2, text="Kiểm tra Canary (google.com):", font=ctk.CTkFont(size=12, weight="bold"), width=160, anchor="w").pack(side="left")

        if dns_info.get("canary_test_ok"):
            res_txt = f"✅ PHÂN GIẢI THÀNH CÔNG (Độ trễ: {dns_info.get('canary_latency_ms')} ms)"
            res_color = "#10B981"
        else:
            res_txt = "🔴 THẤT BẠI — Không thể phân giải tên miền thử nghiệm!"
            res_color = "#EF4444"

        ctk.CTkLabel(row2, text=res_txt, font=ctk.CTkFont(size=11, weight="bold"), text_color=res_color).pack(side="left")

        row3 = ctk.CTkFrame(box, fg_color="transparent")
        row3.pack(padx=10, pady=(2, 8), fill="x")
        ctk.CTkLabel(row3, text="Đánh giá toàn vẹn:", font=ctk.CTkFont(size=12, weight="bold"), width=160, anchor="w").pack(side="left")
        ctk.CTkLabel(row3, text=("Tên miền được phân giải thành công; đây là bằng chứng quan sát, không phải bảo đảm tuyệt đối." if dns_info.get("canary_test_ok") else "Chưa phân giải được tên miền thử nghiệm; cần kiểm tra cấu hình DNS."), font=ctk.CTkFont(size=11), text_color=("#4B5563", "#94A3B8"), wraplength=620, justify="left").pack(side="left")
        ipv6_servers = ", ".join(dns_info.get("dns_servers_v6", []))
        if ipv6_servers:
            row4 = ctk.CTkFrame(box, fg_color="transparent")
            row4.pack(padx=10, pady=(0, 2), fill="x")
            ctk.CTkLabel(row4, text="DNS IPv6:", font=ctk.CTkFont(size=12, weight="bold"), width=160, anchor="w").pack(side="left")
            ctk.CTkLabel(row4, text=ipv6_servers, font=ctk.CTkFont(family="Consolas", size=10), text_color="#0284C7", anchor="w", wraplength=620).pack(side="left")
        evidence = "; ".join(dns_info.get("evidence", []))
        if evidence:
            ctk.CTkLabel(box, text=f"Bằng chứng: {evidence}", font=ctk.CTkFont(size=10), text_color=("#4B5563", "#CBD5E1"), wraplength=760, justify="left", anchor="w").pack(padx=10, pady=(0, 4), anchor="w")
        remediation = "; ".join(dns_info.get("remediation", []))
        if remediation:
            ctk.CTkLabel(box, text=f"Khắc phục: {remediation}", font=ctk.CTkFont(size=10), text_color=("#92400E", "#FCD34D"), wraplength=760, justify="left", anchor="w").pack(padx=10, pady=(0, 8), anchor="w")

    def _render_audit_card_dashboard(self, master, dashboard: dict):
        """Vẽ findings dịch vụ với bằng chứng, độ tin cậy và hướng khắc phục."""
        card = ctk.CTkFrame(master, fg_color=("#F9FAFB", "#1E222B"), corner_radius=8)
        card.pack(fill="x", padx=6, pady=6)
        ctk.CTkLabel(card, text="🧪 4. Security dashboard — bằng chứng dịch vụ quan sát", font=ctk.CTkFont(size=14, weight="bold"), anchor="w").pack(padx=14, pady=(10, 4), anchor="w")
        ctk.CTkLabel(card, text="Cổng mở/banner chỉ là dấu hiệu. SMB guest và camera cần xác minh giao thức hoặc quyền truy cập trước khi kết luận.", font=ctk.CTkFont(size=10), text_color=("#6B7280", "#94A3B8"), wraplength=820, justify="left", anchor="w").pack(padx=14, pady=(0, 8), anchor="w")
        findings = dashboard.get("findings") or []
        if not findings:
            ctk.CTkLabel(card, text="Không có endpoint phản hồi trong phạm vi kiểm tra.", text_color="#10B981").pack(padx=14, pady=8, anchor="w")
        for finding in findings:
            risk = str(finding.get("risk", "safe")).lower()
            color = {"critical": "#DC2626", "high": "#EA580C", "medium": "#D97706", "safe": "#059669"}.get(risk, "#0284C7")
            row = ctk.CTkFrame(card, fg_color=("#FFFFFF", "#111827"), corner_radius=6)
            row.pack(fill="x", padx=14, pady=3)
            title = f"{finding.get('check', 'service')} • {finding.get('host', '')}:{finding.get('port', '')} • {finding.get('status', '')}"
            ctk.CTkLabel(row, text=title, font=ctk.CTkFont(size=11, weight="bold"), text_color=color, anchor="w").pack(fill="x", padx=10, pady=(7, 2))
            confidence = finding.get("confidence")
            try:
                conf_text = f"Độ tin cậy: {float(confidence) * 100:.0f}%"
            except (TypeError, ValueError):
                conf_text = "Độ tin cậy: —"
            ctk.CTkLabel(row, text=f"Bằng chứng: {finding.get('evidence', '—')}  |  {conf_text}", font=ctk.CTkFont(size=10), anchor="w", wraplength=800, justify="left").pack(fill="x", padx=10, pady=2)
            ctk.CTkLabel(row, text=f"Khắc phục: {finding.get('remediation', '—')}", font=ctk.CTkFont(size=10), text_color=("#4B5563", "#CBD5E1"), anchor="w", wraplength=800, justify="left").pack(fill="x", padx=10, pady=(0, 7))

    def _render_audit_card_recommendations(self, master, eval_res: dict, gateway_ip: str):
        """Vẽ thẻ 4: Khuyến nghị hành động tăng cường bảo mật."""
        card = ctk.CTkFrame(master, fg_color=("#F9FAFB", "#1E222B"), corner_radius=8)
        card.pack(fill="x", padx=6, pady=6)

        lbl_t = ctk.CTkLabel(card, text="🛠️ 4. Khuyến nghị hành động để đạt 100/100 điểm an ninh", font=ctk.CTkFont(size=14, weight="bold"), anchor="w")
        lbl_t.pack(padx=14, pady=(10, 6), anchor="w")

        recs = eval_res.get("recommendations", [])
        for rec in recs:
            r_row = ctk.CTkFrame(card, fg_color=("#FFFFFF", "#111827"), corner_radius=6)
            r_row.pack(fill="x", padx=14, pady=3)

            ctk.CTkLabel(
                r_row,
                text=rec,
                font=ctk.CTkFont(size=12),
                text_color=("#1F2937", "#F3F4F6"),
                anchor="w",
                wraplength=800,
                justify="left",
            ).pack(padx=12, pady=8, anchor="w")

        # Nút mở trang modem nhanh
        btn_action = ctk.CTkButton(
            card,
            text=f"🌐 Mở Trang Quản Trị Modem Để Tùy Chỉnh (http://{gateway_ip})",
            font=ctk.CTkFont(size=12, weight="bold"),
            height=34,
            fg_color="#0284C7",
            hover_color="#0369A1",
            command=lambda: webbrowser.open(f"http://{gateway_ip}"),
        )
        btn_action.pack(padx=14, pady=(8, 12), anchor="w")

    # =========================================================================
    # TAB 4: QUÉT TÌM CAMERA GIẤU KÍN & THIẾT BỊ QUAY LÉN (SPY CAMERA DETECTOR)
    # =========================================================================
    def _setup_tab_spy(self):
        """Thiết lập nội dung Tab 4: Quét tìm Camera giấu kín & Thiết bị quay lén."""
        self.tab_spy.grid_columnconfigure(0, weight=1)
        self.tab_spy.grid_rowconfigure(2, weight=1)

        # 1. Thanh điều khiển trên cùng
        ctrl_frame = ctk.CTkFrame(self.tab_spy, fg_color="transparent")
        ctrl_frame.grid(row=0, column=0, padx=5, pady=(5, 4), sticky="ew")
        ctrl_frame.grid_columnconfigure(2, weight=1)

        self.btn_spy_scan = ctk.CTkButton(
            ctrl_frame,
            text="🚨 BẮT ĐẦU QUÉT TÌM CAMERA GIẤU KÍN",
            font=ctk.CTkFont(size=13, weight="bold"),
            height=36,
            width=290,
            fg_color="#DC2626",
            hover_color="#B91C1C",
            command=self._start_spy_scan,
        )
        self.btn_spy_scan.grid(row=0, column=0, padx=(0, 15), sticky="w")

        self.chk_alarm_sound = ctk.CTkCheckBox(
            ctrl_frame,
            text="🔊 Bật còi báo động âm thanh khi phát hiện",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=("#111827", "#F9FAFB"),
        )
        self.chk_alarm_sound.select()
        self.chk_alarm_sound.grid(row=0, column=1, padx=(0, 15), sticky="w")

        self.lbl_spy_status = ctk.CTkLabel(
            ctrl_frame,
            text="Sẵn sàng rà soát toàn bộ dải mạng để phát hiện camera giấu kín, chip Tuya, Xiongmai, RTSP...",
            font=ctk.CTkFont(size=12),
            text_color=("#4B5563", "#94A3B8"),
            anchor="w",
        )
        self.lbl_spy_status.grid(row=0, column=2, sticky="w")

        self.spy_progress_bar = ctk.CTkProgressBar(self.tab_spy, height=5)
        self.spy_progress_bar.grid(row=0, column=0, padx=5, pady=(45, 0), sticky="ew")
        self.spy_progress_bar.set(0)

        # 2. Khung Tình Trạng An Toàn Phòng (Room Safety Banner)
        self.spy_status_card = ctk.CTkFrame(
            self.tab_spy,
            fg_color=("#FEF2F2", "#450A0A"),
            border_width=1,
            border_color="#EF4444",
            corner_radius=8,
        )
        self.spy_status_card.grid(row=1, column=0, padx=5, pady=(10, 6), sticky="ew")
        self.spy_status_card.grid_columnconfigure(1, weight=1)

        self.lbl_spy_badge_icon = ctk.CTkLabel(self.spy_status_card, text="🛡️", font=ctk.CTkFont(size=30), width=45)
        self.lbl_spy_badge_icon.grid(row=0, column=0, rowspan=2, padx=(15, 10), pady=10)

        self.lbl_spy_banner_title = ctk.CTkLabel(
            self.spy_status_card,
            text="CHẾ ĐỘ RÀ SOÁT BẢO VỆ RIÊNG TƯ — KHU VỰC NHẠY CẢM",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=("#991B1B", "#FCA5A5"),
            anchor="w",
        )
        self.lbl_spy_banner_title.grid(row=0, column=1, padx=5, pady=(10, 2), sticky="w")

        self.lbl_spy_banner_desc = ctk.CTkLabel(
            self.spy_status_card,
            text="Bấm nút 'BẮT ĐẦU QUÉT' để kiểm tra xem có camera giấu kín ngụy trang (đồng hồ, báo cháy, cúc áo...) đang kết nối Wi-Fi và truyền video lén hay không.",
            font=ctk.CTkFont(size=12),
            text_color=("#B91C1C", "#F87171"),
            anchor="w",
            wraplength=800,
            justify="left",
        )
        self.lbl_spy_banner_desc.grid(row=1, column=1, padx=5, pady=(0, 10), sticky="w")

        # 3. Khung cuộn hiển thị danh sách thiết bị nghi vấn
        self.spy_scroll = ctk.CTkScrollableFrame(self.tab_spy, fg_color=("#FFFFFF", "#111827"), corner_radius=8)
        self.spy_scroll.grid(row=2, column=0, padx=5, pady=(0, 6), sticky="nsew")
        self.spy_scroll.grid_columnconfigure(0, weight=1)

        self.lbl_spy_placeholder = ctk.CTkLabel(
            self.spy_scroll,
            text="🕵️ Chưa thực hiện quét. Bấm nút đỏ phía trên để bắt đầu rà soát mạng tìm camera quay lén.",
            font=ctk.CTkFont(size=13),
            text_color=("#6B7280", "#9CA3AF"),
            pady=80,
        )
        self.lbl_spy_placeholder.pack()

    def _start_spy_scan(self):
        """Bắt đầu quét tìm camera giấu kín với phản hồi trực tiếp thời gian thực."""
        if self.is_spy_scanning:
            return
        self.is_spy_scanning = True
        self.btn_spy_scan.configure(state="disabled", text="⏳ ĐANG RÀ SOÁT CAMERA GIẤU KÍN...")
        self.spy_progress_bar.set(0.05)
        self.lbl_spy_status.configure(text="Đang chuẩn bị danh sách thiết bị cần quét...")

        # Xóa nội dung cũ và hiển thị thông báo tiến trình trực tiếp
        for w in self.spy_scroll.winfo_children():
            w.destroy()

        self._spy_placeholder = ctk.CTkLabel(
            self.spy_scroll,
            text="⚡ Đang rà soát mạng Wi-Fi... Thiết bị camera & chip nghi vấn sẽ xuất hiện ngay tại đây khi phát hiện!",
            font=ctk.CTkFont(size=13),
            text_color=("#6B7280", "#9CA3AF"),
            pady=30,
        )
        self._spy_placeholder.pack()

        def worker():
            devices_to_check = list(self.all_devices)
            # Nếu chưa có thiết bị nào trong bộ nhớ tạm, tự động dò tìm ARP trước
            if not devices_to_check:
                def on_prog(c, t):
                    self.after(0, lambda c=c, t=t: (
                        self.spy_progress_bar.set((c / t) * 0.35),
                        self.lbl_spy_status.configure(
                            text=f"🔍 [1/2] Đang dò tìm thiết bị Wi-Fi... Đã thấy {len(devices_to_check)} máy ({c}/{t})"
                        )
                    ))
                devices_to_check = []
                self.scanner.scan_subnet(
                    on_device_found=lambda d: devices_to_check.append(d),
                    on_progress=on_prog,
                )
                # Lưu vào cache chung để không phải quét lại
                self.all_devices = list(devices_to_check)
                self.after(0, self._update_stat_counts)

            total = len(devices_to_check)
            if total == 0:
                self.after(0, lambda: self._on_spy_scan_finished([]))
                return

            # Sắp xếp ưu tiên: Chip camera & thiết bị không rõ hãng quét TRƯỚC TIÊN
            def priority_key(dev):
                v = (dev.get("vendor") or "").lower()
                n = (dev.get("name") or "").lower()
                if any(sig in v or sig in n for sig in CAMERA_CHIP_SIGNATURES):
                    return 0  # Ưu tiên số 1: Khớp chip camera đã biết
                if "không rõ" in v or "chưa rõ" in v or not v:
                    return 1  # Ưu tiên số 2: Hãng không rõ
                if dev.get("is_random_mac"):
                    return 2  # Ưu tiên số 3: MAC ngẫu nhiên
                return 3      # Thiết bị thông thường

            devices_to_check.sort(key=priority_key)

            results = []
            checked = 0
            threat_count = 0

            self.after(0, lambda: self.lbl_spy_status.configure(
                text=f"⚡ [2/2] Đang kiểm tra cổng video RTSP / ONVIF trên {total} thiết bị..."
            ))

            # Quét đa luồng kiểm tra cổng video với báo cáo thời gian thực
            with ThreadPoolExecutor(max_workers=20) as executor:
                future_to_dev = {executor.submit(analyze_spy_camera_risk, dev): dev for dev in devices_to_check}
                for f in as_completed(future_to_dev):
                    res = f.result()
                    results.append(res)
                    checked += 1
                    prog = 0.35 + (checked / total) * 0.63

                    cur_ip = res["device"].get("ip", "")
                    cur_v = res["device"].get("vendor", "Chưa rõ")
                    lvl = res.get("risk_level", "safe")

                    # Nếu phát hiện nghi vấn hoặc camera -> Đẩy card lên màn hình NGAY LẬP TỨC!
                    if lvl in ("confirmed", "suspicious", "potential"):
                        threat_count += 1
                        self.after(0, lambda r=res: self._render_live_threat_card(r))
                        if lvl == "confirmed" and self.chk_alarm_sound.get() == 1:
                            play_alarm_sound()

                    # Cập nhật thanh tiến trình và thông tin IP vừa rà soát
                    threat_badge = f" • 🚨 Phát hiện: {threat_count} nghi vấn!" if threat_count > 0 else ""
                    self.after(0, lambda p=prog, c=checked, tot=total, ip=cur_ip, v=cur_v, tb=threat_badge: (
                        self.spy_progress_bar.set(p),
                        self.lbl_spy_status.configure(text=f"⚡ [2/2] Đang rà cổng video ({c}/{tot}) • Vừa quét: {ip} ({v}){tb}")
                    ))

            # Sắp xếp theo mức độ nguy cơ: Confirmed -> Suspicious -> Potential -> Safe
            order = {"confirmed": 0, "suspicious": 1, "potential": 2, "safe": 3}
            results.sort(key=lambda x: (order.get(x["risk_level"], 9), -x["threat_score"]))

            self.after(0, lambda: self.spy_progress_bar.set(1.0))
            self.after(0, lambda: self._on_spy_scan_finished(results))

        threading.Thread(target=worker, daemon=True).start()

    def _render_live_threat_card(self, res: dict):
        """Hiển thị thẻ thiết bị camera / nghi vấn ngay lập tức lên UI khi vừa phát hiện."""
        if hasattr(self, "_spy_placeholder") and self._spy_placeholder:
            try:
                self._spy_placeholder.destroy()
                self._spy_placeholder = None
            except Exception:
                pass
        self._render_spy_device_card(self.spy_scroll, res)

    def _on_spy_scan_finished(self, results: list):
        self.is_spy_scanning = False
        self.btn_spy_scan.configure(state="normal", text="🚨 QUÉT LẠI CAMERA GIẤU KÍN")
        self.spy_results = results

        confirmed_cams = [r for r in results if r["risk_level"] == "confirmed"]
        suspicious_cams = [r for r in results if r["risk_level"] == "suspicious"]
        total_threats = len(confirmed_cams) + len(suspicious_cams)

        if total_threats > 0:
            # Chỉ báo động khi có bằng chứng camera đã được xác minh.
            if confirmed_cams and self.chk_alarm_sound.get() == 1:
                play_alarm_sound()

            self.spy_status_card.configure(
                fg_color=("#FEF2F2", "#450A0A"),
                border_color="#EF4444",
            )
            self.lbl_spy_badge_icon.configure(text="🚨")
            self.lbl_spy_banner_title.configure(
                text=(
                    f"KẾT QUẢ QUÉT: {len(confirmed_cams)} DỊCH VỤ CAMERA ĐÃ XÁC MINH, "
                    f"{len(suspicious_cams)} THIẾT BỊ CẦN KIỂM TRA"
                ),
                text_color=("#991B1B", "#FCA5A5"),
            )
            self.lbl_spy_banner_desc.configure(
                text=(
                    "Cổng mở hoặc tên hãng chỉ là dấu hiệu. Hãy kiểm tra thiết bị được đánh dấu "
                    "đỏ/cam trước khi kết luận đó là camera hay có hành vi quay lén."
                ),
                text_color=("#B91C1C", "#F87171"),
            )
            self.lbl_spy_status.configure(
                text=f"⚠️ Có {total_threats} thiết bị cần xác minh thêm."
            )
        else:
            self.spy_status_card.configure(
                fg_color=("#F0FDF4", "#062817"),
                border_color="#10B981",
            )
            self.lbl_spy_badge_icon.configure(text="✅")
            self.lbl_spy_banner_title.configure(
                text="CHƯA PHÁT HIỆN DẤU HIỆU CAMERA MẠNH TRONG LẦN QUÉT NÀY",
                text_color=("#065F46", "#34D399"),
            )
            self.lbl_spy_banner_desc.configure(
                text=(
                    "Kết quả chỉ phản ánh các thiết bị phản hồi trong mạng LAN hiện tại; "
                    "không loại trừ thiết bị ngủ, bị cô lập mạng hoặc nằm ở VLAN khác."
                ),
                text_color=("#047857", "#6EE7B7"),
            )
            self.lbl_spy_status.configure(
                text="✅ Chưa thấy dấu hiệu camera mạnh trên các thiết bị phản hồi."
            )

        for w in self.spy_scroll.winfo_children():
            w.destroy()

        if not results:
            lbl_none = ctk.CTkLabel(
                self.spy_scroll,
                text="Không tìm thấy thiết bị nào trong mạng.",
                font=ctk.CTkFont(size=14),
                pady=50,
            )
            lbl_none.pack()
            return

        # Hiển thị các thiết bị nghi vấn trước, sau đó tới các thiết bị khác
        for r in results:
            self._render_spy_device_card(self.spy_scroll, r)

    def _render_spy_device_card(self, master, res: dict):
        """Vẽ thẻ hiển thị chi tiết 1 thiết bị trong chế độ quét Camera giấu kín."""
        device = res["device"]
        ip = device.get("ip", "")
        mac = device.get("mac", "")
        name = device.get("name", "Thiết bị")
        vendor = device.get("vendor", "Chưa rõ")
        level = res["risk_level"]
        title = res["risk_title"]
        chip = res["matched_chip"]
        open_ports = res["open_cam_ports"]
        reasons = res["reasons"]
        rtsp_url = res["rtsp_url"]
        web_url = res["web_url"]

        if level == "confirmed":
            border_color = "#EF4444"
            bg_color = ("#FEF2F2", "#2B0B0B")
            badge_bg = "#DC2626"
        elif level == "suspicious":
            border_color = "#F97316"
            bg_color = ("#FFF7ED", "#2E1505")
            badge_bg = "#EA580C"
        elif level == "potential":
            border_color = "#F59E0B"
            bg_color = ("#FFFBEB", "#261905")
            badge_bg = "#D97706"
        else:
            border_color = ("#E5E7EB", "#374151")
            bg_color = ("#F9FAFB", "#1E222B")
            badge_bg = "#4B5563"

        card = ctk.CTkFrame(master, fg_color=bg_color, border_width=1, border_color=border_color, corner_radius=8)
        card.pack(fill="x", padx=6, pady=4)
        card.grid_columnconfigure(1, weight=1)

        # Header hàng thiết bị
        hdr_box = ctk.CTkFrame(card, fg_color="transparent")
        hdr_box.pack(padx=12, pady=(10, 4), fill="x")

        lbl_badge = ctk.CTkLabel(
            hdr_box,
            text=title,
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color=badge_bg,
            text_color="white",
            corner_radius=4,
            padx=8,
            pady=3,
        )
        lbl_badge.pack(side="left")

        lbl_ip_mac = ctk.CTkLabel(
            hdr_box,
            text=f"IP: {ip}   •   MAC: {mac}   •   Hãng: {vendor}",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=("#1F2937", "#F3F4F6"),
        )
        lbl_ip_mac.pack(side="left", padx=15)

        # Thông tin chi tiết & Cảnh báo
        if chip:
            ctk.CTkLabel(
                card,
                text=f"🔍 Nền tảng phần cứng phát hiện: {chip}",
                font=ctk.CTkFont(size=11, weight="bold"),
                text_color=("#B45309", "#FCD34D"),
                anchor="w",
            ).pack(padx=14, pady=2, anchor="w")

        for r in reasons:
            ctk.CTkLabel(
                card,
                text=f"• {r}",
                font=ctk.CTkFont(size=11),
                text_color=("#374151", "#E5E7EB"),
                anchor="w",
                wraplength=800,
                justify="left",
            ).pack(padx=14, pady=1, anchor="w")

        # Hàng nút thao tác đối phó
        act_row = ctk.CTkFrame(card, fg_color="transparent")
        act_row.pack(padx=12, pady=(6, 10), fill="x")

        # Nút Chặn MAC
        btn_block = ctk.CTkButton(
            act_row,
            text="🚫 Chặn Camera Này",
            width=135,
            height=28,
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color="#DC2626",
            hover_color="#B91C1C",
            command=lambda: BlockMacGuideWindow(self.winfo_toplevel(), device, gateway_ip=self.scanner.gateway_ip),
        )
        btn_block.pack(side="left", padx=2)

        # Nút Mở Web Camera nếu có
        if web_url:
            btn_web = ctk.CTkButton(
                act_row,
                text=f"🌐 Mở Web Camera ({web_url})",
                width=170,
                height=28,
                font=ctk.CTkFont(size=11, weight="bold"),
                fg_color="#0284C7",
                hover_color="#0369A1",
                command=lambda u=web_url: webbrowser.open(u),
            )
            btn_web.pack(side="left", padx=4)

        # Nút Xem Luồng Video Stream qua VLC nếu phát hiện camera hoặc mở cổng RTSP
        if rtsp_url or level in ("confirmed", "suspicious", "potential") or chip:
            btn_stream = ctk.CTkButton(
                act_row,
                text="📺 Xem Luồng Video (VLC)",
                width=175,
                height=28,
                font=ctk.CTkFont(size=11, weight="bold"),
                fg_color="#7C3AED",
                hover_color="#6D28D9",
                command=lambda d=device: CameraStreamWindow(self.winfo_toplevel(), d, initial_port=554),
            )
            btn_stream.pack(side="left", padx=4)

            btn_auth = ctk.CTkButton(
                act_row,
                text="🛡️ Kiểm Tra Pass (401/200)",
                width=180,
                height=28,
                font=ctk.CTkFont(size=11, weight="bold"),
                fg_color="#059669",
                hover_color="#047857",
                command=lambda d=device: CameraAuthWindow(self.winfo_toplevel(), d),
            )
            btn_auth.pack(side="left", padx=4)

        # Nút Copy RTSP nếu có luồng RTSP
        if rtsp_url:
            def copy_rtsp(u=rtsp_url):
                self.clipboard_clear()
                self.clipboard_append(u)
                messagebox.showinfo("Đã sao chép RTSP", f"Đã sao chép link luồng video RTSP:\n{u}\n\nBạn có thể dán link này vào phần mềm VLC Media Player (Media -> Open Network Stream) để xem trực tiếp camera đang quay gì.")

            btn_rtsp = ctk.CTkButton(
                act_row,
                text="📋 Copy Link RTSP",
                width=135,
                height=28,
                font=ctk.CTkFont(size=11),
                fg_color=("#E5E7EB", "#374151"),
                text_color=("#111827", "#F9FAFB"),
                hover_color=("#D1D5DB", "#4B5563"),
                command=copy_rtsp,
            )
            btn_rtsp.pack(side="left", padx=4)

        # Nút Soi cổng dịch vụ chi tiết
        btn_inspect = ctk.CTkButton(
            act_row,
            text="🔍 Soi Cổng Chi Tiết",
            width=130,
            height=28,
            font=ctk.CTkFont(size=11),
            fg_color=("#E5E7EB", "#374151"),
            text_color=("#111827", "#F9FAFB"),
            hover_color=("#D1D5DB", "#4B5563"),
            command=lambda d=device: DeviceDetailWindow(self.winfo_toplevel(), d),
        )
        btn_inspect.pack(side="left", padx=4)


def main():
    app = WifiScannerApp()
    app.mainloop()


if __name__ == "__main__":
    main()
