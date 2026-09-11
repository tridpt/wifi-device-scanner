"""
wifi_channel_analyzer.py - Trình Phân Tích Phổ Kênh Sóng Wi-Fi (Wi-Fi Channel Analyzer).
Đồ họa phổ sóng hình chuông (Bell Curve Parabolic Spectrum Graph) cho 2.4 GHz & 5 GHz:
- Quét toàn bộ mạng Wi-Fi và BSSID xung quanh qua Windows WLAN Native API (netsh wlan).
- Vẽ đường cong parabol phổ sóng hình chuông trực quan (như app WiFi Analyzer / inSSIDer).
- Nhận diện can nhiễu đồng kênh (Co-Channel) và can nhiễu kênh kề (Adjacent-Channel).
- Tự động đánh giá chất lượng các kênh (1, 6, 11 và 36, 40, 44...) và đề xuất kênh tối ưu nhất cho Router.
- Tương tác rê chuột (Hover) xem chi tiết BSSID, Hãng sản xuất qua OUI và tỉ lệ nghẽn kênh.
"""

import math
import re
import subprocess
import threading
import tkinter as tk
from collections import defaultdict
from typing import Dict, Any, List, Optional, Callable
import customtkinter as ctk

from oui_db import lookup_vendor
from scanner import get_wifi_ssid

# Bảng màu sắc phổ sóng neon
SPECTRUM_PALETTE = [
    "#38BDF8",  # Sky Blue
    "#34D399",  # Emerald
    "#FBBF24",  # Amber Gold
    "#A855F7",  # Purple
    "#F43F5E",  # Rose
    "#FB923C",  # Orange
    "#2DD4BF",  # Teal
    "#E879F9",  # Fuchsia
    "#60A5FA",  # Blue
    "#A3E635",  # Lime
]

# Danh sách kênh chuẩn 5 GHz
CHANNELS_5G = [
    36, 40, 44, 48,
    52, 56, 60, 64,
    100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
    149, 153, 157, 161, 165,
]


class WifiChannelScanner:
    """Bộ xử lý quét và bóc tách dữ liệu phổ sóng Wi-Fi từ Windows netsh wlan."""

    @staticmethod
    def scan_surrounding_networks() -> List[Dict[str, Any]]:
        """
        Quét danh sách toàn bộ mạng Wi-Fi và BSSID xung quanh.
        Trích xuất: SSID, BSSID, Signal %, RSSI dBm, Band, Channel, Radio Type, Channel Utilization.
        """
        networks = []
        try:
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            out = subprocess.check_output(
                "netsh wlan show networks mode=bssid",
                shell=True,
                text=True,
                startupinfo=startupinfo,
                stderr=subprocess.DEVNULL,
                errors="replace",
            )

            current_ssid = ""
            current_auth = ""
            current_bssid_obj = None

            for line in out.splitlines():
                line_s = line.strip()
                if line_s.startswith("SSID "):
                    parts = line_s.split(":", 1)
                    if len(parts) > 1:
                        current_ssid = parts[1].strip() or "Ẩn danh (Hidden)"
                elif line_s.startswith("Authentication"):
                    parts = line_s.split(":", 1)
                    if len(parts) > 1:
                        current_auth = parts[1].strip()
                elif line_s.startswith("BSSID "):
                    parts = line_s.split(":", 1)
                    if len(parts) > 1:
                        mac_addr = parts[1].strip()
                        vendor_info = lookup_vendor(mac_addr)
                        vendor_name = vendor_info[0] if isinstance(vendor_info, tuple) else str(vendor_info)
                        current_bssid_obj = {
                            "ssid": current_ssid,
                            "auth": current_auth,
                            "bssid": mac_addr,
                            "vendor": vendor_name,
                            "signal": 50,
                            "rssi_dbm": -75,
                            "band": "2.4 GHz",
                            "channel": 1,
                            "radio": "802.11n",
                            "utilization": 0,
                        }
                        networks.append(current_bssid_obj)
                elif current_bssid_obj:
                    if line_s.startswith("Signal"):
                        m = re.search(r"(\d+)%", line_s)
                        if m:
                            sig = int(m.group(1))
                            current_bssid_obj["signal"] = sig
                            # Chuyển đổi Signal % sang xấp xỉ dBm (-100 đến -30 dBm)
                            # 100% ~ -30 dBm, 0% ~ -100 dBm
                            current_bssid_obj["rssi_dbm"] = int(-100 + (sig * 0.7))
                    elif line_s.startswith("Band"):
                        parts = line_s.split(":", 1)
                        if len(parts) > 1:
                            current_bssid_obj["band"] = parts[1].strip()
                    elif re.match(r"^Channel\s*:", line_s):
                        m = re.search(r":\s*(\d+)", line_s)
                        if m:
                            current_bssid_obj["channel"] = int(m.group(1))
                    elif line_s.startswith("Radio type"):
                        parts = line_s.split(":", 1)
                        if len(parts) > 1:
                            current_bssid_obj["radio"] = parts[1].strip()
                    elif line_s.startswith("Channel Utilization"):
                        m = re.search(r"\((\d+)\s*%\)", line_s)
                        if m:
                            current_bssid_obj["utilization"] = int(m.group(1))

        except Exception as e:
            print(f"Lỗi quét phổ sóng: {e}")

        return networks

    @staticmethod
    def get_recommendations(networks: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Tính toán mức độ can nhiễu đồng kênh và xếp hạng kênh tối ưu nhất.
        2.4 GHz: Xét 3 kênh không chồng lấn chuẩn (1, 6, 11).
        5 GHz: Xét các kênh UNII-1 (36, 40, 44, 48) và UNII-3 (149, 153, 157, 161).
        """
        # 1. Thống kê 2.4 GHz
        chan_scores_2g = {1: 0.0, 6: 0.0, 11: 0.0}
        chan_counts_2g = {1: 0, 6: 0, 11: 0}

        # 2. Thống kê 5 GHz
        chan_scores_5g = {c: 0.0 for c in [36, 40, 44, 48, 149, 153, 157, 161]}
        chan_counts_5g = {c: 0 for c in chan_scores_5g}

        for n in networks:
            band = n.get("band", "2.4 GHz")
            ch = n.get("channel", 1)
            sig = n.get("signal", 50)
            weight = math.pow(10, (sig - 100) / 20.0)  # Công suất tín hiệu tuyến tính

            if "2.4" in band:
                # Can nhiễu 2.4 GHz ảnh hưởng các kênh lân cận +-2
                for target_ch in (1, 6, 11):
                    dist = abs(ch - target_ch)
                    if dist <= 2:
                        penalty = weight * (1.0 - (dist * 0.35))
                        chan_scores_2g[target_ch] += penalty
                        if dist == 0:
                            chan_counts_2g[target_ch] += 1
            else:
                if ch in chan_scores_5g:
                    chan_scores_5g[ch] += weight
                    chan_counts_5g[ch] += 1

        # Tìm kênh có điểm phạt thấp nhất
        best_2g = min(chan_scores_2g, key=chan_scores_2g.get)
        best_5g = min(chan_scores_5g, key=chan_scores_5g.get)

        return {
            "best_2g_channel": best_2g,
            "best_2g_count": chan_counts_2g[best_2g],
            "scores_2g": chan_scores_2g,
            "counts_2g": chan_counts_2g,
            "best_5g_channel": best_5g,
            "best_5g_count": chan_counts_5g[best_5g],
            "scores_5g": chan_scores_5g,
            "counts_5g": chan_counts_5g,
        }


class WifiSpectrumCanvas(tk.Canvas):
    """
    Widget Canvas vẽ đồ thị phổ sóng hình chuông (Bell Curve Parabolic Graph).
    Tự động co giãn theo kích thước cửa sổ và hỗ trợ chuyển băng tần 2.4 GHz / 5 GHz.
    Hỗ trợ hiển thị chống đè chữ (Anti-Collision Text Layout), huy hiệu cảnh báo đè kênh,
    chế độ cô lập từng kênh (Channel Isolation Focus), và Tooltip so sánh đa mạng trùng kênh.
    """

    def __init__(self, master, **kwargs):
        super().__init__(
            master,
            bg="#0B0F19",
            bd=0,
            highlightthickness=0,
            relief="ridge",
            **kwargs,
        )
        self.current_band = "2.4 GHz"
        self.networks: List[Dict[str, Any]] = []
        self.current_connected_ssid = get_wifi_ssid() or ""
        self.hovered_net: Optional[Dict[str, Any]] = None
        self.selected_channel: Optional[int] = None
        self.badge_hitboxes: List[Dict[str, Any]] = []
        self.on_channel_selected_callback: Optional[Callable[[], None]] = None

        # Tọa độ lề hiển thị
        self.margin_left = 60.0
        self.margin_right = 30.0
        self.margin_top = 45.0
        self.margin_bottom = 45.0

        # Lắng nghe sự kiện co giãn cửa sổ & chuột
        self.bind("<Configure>", lambda e: self.redraw())
        self.bind("<Motion>", self._on_mouse_move)
        self.bind("<Leave>", self._on_mouse_leave)
        self.bind("<Button-1>", self._on_click)

    def set_data(self, networks: List[Dict[str, Any]], band: str = "2.4 GHz", current_ssid: str = ""):
        self.networks = networks
        self.current_band = band
        self.current_connected_ssid = current_ssid or get_wifi_ssid() or ""
        self.selected_channel = None
        self.redraw()

    def _dbm_to_y(self, dbm: float, height: float) -> float:
        """Chuyển đổi cường độ dBm (-100 đến -30) sang tọa độ Y."""
        clamped_dbm = max(-100.0, min(dbm, -30.0))
        y_top = self.margin_top
        y_base = height - self.margin_bottom
        ratio = (clamped_dbm - (-100.0)) / ((-30.0) - (-100.0))
        return y_base - (ratio * (y_base - y_top))

    def _channel_to_x_2g(self, ch: float, width: float) -> float:
        """Chuyển đổi kênh 2.4 GHz (1 đến 14) sang tọa độ X."""
        x_left = self.margin_left
        x_right = width - self.margin_right
        # Kênh từ 0 đến 15 để có khoảng trống lề
        ratio = (ch - 0.0) / (15.0 - 0.0)
        return x_left + ratio * (x_right - x_left)

    def _channel_to_x_5g(self, ch: int, width: float) -> float:
        """Chuyển đổi kênh 5 GHz sang tọa độ X theo danh sách kênh CHANNELS_5G."""
        x_left = self.margin_left
        x_right = width - self.margin_right
        total_chans = len(CHANNELS_5G)
        try:
            idx = CHANNELS_5G.index(ch)
        except ValueError:
            idx = min(range(total_chans), key=lambda i: abs(CHANNELS_5G[i] - ch))

        ratio = (idx + 0.8) / (total_chans + 0.6)
        return x_left + ratio * (x_right - x_left)

    def _on_click(self, event):
        """Xử lý nhấp chuột để chọn / cô lập kênh sóng (Channel Isolation Focus)."""
        mx = event.x
        my = event.y

        # 1. Kiểm tra click vào huy hiệu cảnh báo đè sóng
        for b in getattr(self, "badge_hitboxes", []):
            x1, y1, x2, y2 = b["bbox"]
            if x1 <= mx <= x2 and y1 <= my <= y2:
                ch = b["channel"]
                self.selected_channel = None if self.selected_channel == ch else ch
                self.redraw()
                if callable(self.on_channel_selected_callback):
                    self.on_channel_selected_callback()
                return

        # 2. Kiểm tra click vào đường cong hình chuông
        clicked_ch = None
        min_dist = 9999.0
        for item in getattr(self, "rendered_curves", []):
            xc = item["x_center"]
            yp = item["y_peak"]
            hw = item["half_w"]
            if abs(mx - xc) <= hw and my >= (yp - 25):
                dist = math.hypot(mx - xc, my - yp)
                if dist < min_dist:
                    min_dist = dist
                    clicked_ch = item["net"].get("channel")

        if clicked_ch is not None and min_dist < 60:
            self.selected_channel = None if self.selected_channel == clicked_ch else clicked_ch
        else:
            self.selected_channel = None

        self.redraw()
        if callable(self.on_channel_selected_callback):
            self.on_channel_selected_callback()

    def redraw(self):
        """Vẽ lại toàn bộ lưới tọa độ, đường cong phổ sóng và nhãn chống đè."""
        self.delete("all")
        w = max(self.winfo_width(), 600)
        h = max(self.winfo_height(), 320)

        # 1. Vẽ lưới tọa độ dBm (Trục tung)
        y_base = h - self.margin_bottom
        x_left = self.margin_left
        x_right = w - self.margin_right

        for dbm in range(-100, -20, 10):
            y = self._dbm_to_y(dbm, h)
            self.create_line(x_left, y, x_right, y, fill="#1E293B", dash=(2, 4), width=1)
            self.create_text(
                x_left - 10,
                y,
                text=f"{dbm} dBm",
                fill="#64748B",
                font=("Consolas", 9),
                anchor="e",
            )

        # Đường đáy chuẩn -100 dBm
        self.create_line(x_left, y_base, x_right, y_base, fill="#475569", width=2)

        # 2. Vẽ các vạch chia kênh (Trục hoành)
        if "2.4" in self.current_band:
            for ch in range(1, 15):
                x = self._channel_to_x_2g(ch, w)
                is_std = ch in (1, 6, 11)
                line_color = "#38BDF8" if is_std else "#334155"
                self.create_line(x, y_base, x, y_base + 6, fill=line_color, width=2 if is_std else 1)
                lbl_color = "#38BDF8" if is_std else "#94A3B8"
                self.create_text(
                    x,
                    y_base + 16,
                    text=f"CH {ch}",
                    fill=lbl_color,
                    font=("Segoe UI", 9, "bold" if is_std else "normal"),
                )
                if is_std:
                    self.create_text(
                        x,
                        y_base + 28,
                        text="★",
                        fill="#FACC15",
                        font=("Segoe UI", 8),
                    )
        else:
            for ch in CHANNELS_5G:
                x = self._channel_to_x_5g(ch, w)
                self.create_line(x, y_base, x, y_base + 5, fill="#334155", width=1)
                self.create_text(
                    x,
                    y_base + 15,
                    text=str(ch),
                    fill="#94A3B8",
                    font=("Segoe UI", 8),
                )

        # 3. Lọc danh sách mạng theo băng tần đang chọn
        target_nets = [
            n for n in self.networks
            if ("2.4" in self.current_band and "2.4" in n.get("band", ""))
            or ("5" in self.current_band and "5" in n.get("band", ""))
        ]

        # Nhóm các mạng theo kênh để phân tích đè sóng
        chan_groups = defaultdict(list)
        for net in target_nets:
            ch = net.get("channel", 1)
            chan_groups[ch].append(net)

        self.rendered_curves = []
        self.badge_hitboxes = []

        # Sắp xếp mạng vẽ từ yếu đến mạnh để mạng mạnh hơn vẽ đè lên trên
        target_nets_sorted = sorted(target_nets, key=lambda n: n.get("signal", 0))

        # --- A. VẼ CÁC ĐƯỜNG CONG HÌNH CHUÔNG (CURVES) ---
        for idx, net in enumerate(target_nets_sorted):
            ssid = net.get("ssid", "Unknown")
            ch = net.get("channel", 1)
            rssi = net.get("rssi_dbm", -75)
            is_self = (ssid.lower() == self.current_connected_ssid.lower()) and self.current_connected_ssid != ""

            # Kiểm tra trạng thái cô lập (selected_channel)
            is_in_focus = (self.selected_channel is None) or (self.selected_channel == ch)

            # Bảng màu
            color = SPECTRUM_PALETTE[idx % len(SPECTRUM_PALETTE)]
            if is_self:
                color = "#38BDF8"

            y_peak = self._dbm_to_y(rssi, h)
            height_amp = y_base - y_peak

            if "2.4" in self.current_band:
                x_center = self._channel_to_x_2g(ch, w)
                x_left_edge = self._channel_to_x_2g(ch - 2.0, w)
                x_right_edge = self._channel_to_x_2g(ch + 2.0, w)
                half_w = (x_right_edge - x_left_edge) / 2.0
            else:
                x_center = self._channel_to_x_5g(ch, w)
                ch_spacing = (w - self.margin_left - self.margin_right) / len(CHANNELS_5G)
                half_w = ch_spacing * 1.6

            points = []
            steps = 28
            for step in range(steps + 1):
                t = -1.0 + (2.0 * step / steps)
                px = x_center + (t * half_w)
                py = y_base - height_amp * (1.0 - (t * t))
                points.extend([px, py])

            poly_points = points + [x_center + half_w, y_base, x_center - half_w, y_base]

            is_hovered = (self.hovered_net and self.hovered_net.get("bssid") == net.get("bssid"))

            if is_in_focus:
                line_w = 3 if (is_self or is_hovered) else 2
                border_color = "#FACC15" if (is_self and not is_hovered) else ("#FFFFFF" if is_hovered else color)
                fill_color = "#1E293B" if not is_hovered else "#334155"
            else:
                # Kênh khác bị làm mờ (Dimmed) khi đang cô lập một kênh
                line_w = 1
                border_color = "#1E293B"
                fill_color = "#0B0F19"

            # Vẽ bóng mờ bên trong
            self.create_polygon(poly_points, fill=fill_color, outline="", tags="curve_fill")

            # Vẽ đường cong sáng
            self.create_line(points, fill=border_color, width=line_w, smooth=True, tags="curve_line")

            # Lưu lại thông tin vùng va chạm
            self.rendered_curves.append({
                "net": net,
                "x_center": x_center,
                "y_peak": y_peak,
                "half_w": half_w,
                "color": border_color,
            })

        # --- B. VẼ HUY HIỆU CẢNH BÁO ĐÈ SÓNG (CONGESTION PILL BADGES) ---
        for ch, chan_nets in chan_groups.items():
            if len(chan_nets) < 2:
                continue

            count = len(chan_nets)
            if "2.4" in self.current_band:
                xc = self._channel_to_x_2g(ch, w)
            else:
                xc = self._channel_to_x_5g(ch, w)

            highest_peak_y = min(self._dbm_to_y(n.get("rssi_dbm", -75), h) for n in chan_nets)
            badge_y = max(18.0, highest_peak_y - 36.0)

            is_chan_selected = (self.selected_channel == ch)

            if is_chan_selected:
                bg_col = "#0C4A6E"
                border_col = "#38BDF8"
                txt_col = "#FFFFFF"
                txt = f"🔍 Kênh {ch}: Đang cô lập {count} mạng"
            elif count == 2:
                bg_col = "#78350F"
                border_col = "#F59E0B"
                txt_col = "#FEF3C7"
                txt = f"⚠️ {count} mạng đè sóng"
            else:
                bg_col = "#450A0A"
                border_col = "#EF4444"
                txt_col = "#FEE2E2"
                txt = f"🔥 {count} mạng đè sóng"

            bw = max(len(txt) * 6.8 + 16, 96.0)
            bh = 22.0
            bx1 = xc - (bw / 2.0)
            bx2 = xc + (bw / 2.0)
            by1 = badge_y - (bh / 2.0)
            by2 = badge_y + (bh / 2.0)

            # Vẽ bóng đổ nhẹ cho huy hiệu
            self.create_rectangle(bx1 + 2, by1 + 2, bx2 + 2, by2 + 2, fill="#030712", outline="", tags="badge")
            # Hộp huy hiệu bo viền
            self.create_rectangle(bx1, by1, bx2, by2, fill=bg_col, outline=border_col, width=1.5, tags="badge")
            self.create_text(xc, badge_y, text=txt, fill=txt_col, font=("Segoe UI", 8, "bold"), tags="badge")

            self.badge_hitboxes.append({
                "channel": ch,
                "bbox": (bx1, by1, bx2, by2),
                "nets": chan_nets,
            })

        # --- C. VẼ NHÃN TÊN MẠNG THÔNG MINH CHỐNG ĐÈ CHỮ (ANTI-COLLISION LABELS) ---
        for ch, chan_nets in chan_groups.items():
            if self.selected_channel is not None and ch != self.selected_channel:
                continue  # Ẩn nhãn các kênh bị mờ khi đang cô lập

            if "2.4" in self.current_band:
                xc = self._channel_to_x_2g(ch, w)
            else:
                xc = self._channel_to_x_5g(ch, w)

            # Sắp xếp mạng theo độ mạnh tín hiệu giảm dần (mạnh nhất xếp trước)
            sorted_nets = sorted(chan_nets, key=lambda n: n.get("signal", 0), reverse=True)
            k = len(sorted_nets)

            for i, net in enumerate(sorted_nets):
                ssid = net.get("ssid", "Unknown")
                rssi = net.get("rssi_dbm", -75)
                is_self = (ssid.lower() == self.current_connected_ssid.lower()) and self.current_connected_ssid != ""
                is_hovered = (self.hovered_net and self.hovered_net.get("bssid") == net.get("bssid"))

                y_peak = self._dbm_to_y(rssi, h)

                # Tìm màu mạng tương ứng
                net_color = "#38BDF8" if is_self else ("#FACC15" if is_hovered else "#94A3B8")
                for c_item in self.rendered_curves:
                    if c_item["net"].get("bssid") == net.get("bssid"):
                        net_color = c_item["color"]
                        break

                # Tính toán tọa độ nhãn chống va chạm
                need_leader = False
                if k == 1:
                    lbl_x = xc
                    lbl_y = y_peak - 14.0
                elif k == 2:
                    yp0 = self._dbm_to_y(sorted_nets[0].get("rssi_dbm", -75), h)
                    yp1 = self._dbm_to_y(sorted_nets[1].get("rssi_dbm", -75), h)
                    if abs(yp0 - yp1) < 32:
                        # Hai mạng có đỉnh gần nhau -> Tách lệch trái & phải!
                        if i == 0:
                            lbl_x = xc - 48.0
                            lbl_y = y_peak - 12.0
                        else:
                            lbl_x = xc + 48.0
                            lbl_y = y_peak - 12.0
                        need_leader = True
                    else:
                        # Hai mạng cách xa nhau theo trục dọc -> Giữ ở giữa
                        lbl_x = xc
                        lbl_y = y_peak - 14.0
                else:
                    # 3 mạng trở lên
                    if i == 0:
                        lbl_x = xc
                        lbl_y = y_peak - 16.0
                    elif i == 1:
                        lbl_x = xc - 54.0
                        lbl_y = y_peak - 8.0
                        need_leader = True
                    elif i == 2:
                        lbl_x = xc + 54.0
                        lbl_y = y_peak - 8.0
                        need_leader = True
                    else:
                        offset_dir = 1 if (i % 2 == 1) else -1
                        lbl_x = xc + (offset_dir * 58.0)
                        lbl_y = y_peak + 16.0 * (i - 2)
                        need_leader = True

                # Giới hạn nhãn trong khung hiển thị
                lbl_x = max(self.margin_left + 35, min(lbl_x, w - self.margin_right - 35))
                lbl_y = max(15.0, min(lbl_y, y_base - 10.0))

                # Đường chỉ dẫn (Leader Line) nếu nhãn bị lệch tâm
                if need_leader:
                    anchor_x = lbl_x + 28 if lbl_x < xc else lbl_x - 28
                    self.create_line(
                        anchor_x, lbl_y,
                        xc, y_peak,
                        fill=net_color,
                        dash=(2, 2),
                        width=1,
                        tags="curve_lbl",
                    )

                # Chuẩn bị nội dung nhãn
                label_text = ssid
                if is_self:
                    label_text = f"★ {ssid}"
                if len(label_text) > 13:
                    label_text = label_text[:11] + ".."

                sub_text = f"{rssi} dBm"

                box_w = max(len(label_text) * 7.0, 52.0) + 12.0
                box_h = 24.0
                bx1 = lbl_x - (box_w / 2.0)
                bx2 = lbl_x + (box_w / 2.0)
                by1 = lbl_y - (box_h / 2.0)
                by2 = lbl_y + (box_h / 2.0)

                # Nền Capsule tối đặc che đường kẻ phía sau
                self.create_rectangle(
                    bx1, by1, bx2, by2,
                    fill="#0B0F19",
                    outline=net_color,
                    width=1.5 if (is_self or is_hovered) else 1,
                    tags="curve_lbl",
                )
                self.create_text(
                    lbl_x, lbl_y - 4,
                    text=label_text,
                    fill=net_color,
                    font=("Segoe UI", 8, "bold" if is_self else "normal"),
                    tags="curve_lbl",
                )
                self.create_text(
                    lbl_x, lbl_y + 6,
                    text=sub_text,
                    fill="#94A3B8" if not is_hovered else "#38BDF8",
                    font=("Consolas", 7),
                    tags="curve_lbl",
                )

    def _on_mouse_move(self, event):
        """Bắt vị trí chuột và phát sáng hình chuông tương ứng."""
        mx = event.x
        my = event.y

        closest_net = None
        min_dist = 9999.0

        for item in getattr(self, "rendered_curves", []):
            xc = item["x_center"]
            yp = item["y_peak"]
            hw = item["half_w"]

            if abs(mx - xc) <= hw and my >= (yp - 20):
                dist = math.hypot(mx - xc, my - yp)
                if dist < min_dist:
                    min_dist = dist
                    closest_net = item["net"]

        if closest_net != self.hovered_net:
            self.hovered_net = closest_net
            self.redraw()
            if closest_net:
                self._show_floating_tooltip(closest_net, mx, my)
            else:
                self.delete("tooltip_box")

    def _on_mouse_leave(self, event):
        if self.hovered_net:
            self.hovered_net = None
            self.delete("tooltip_box")
            self.redraw()

    def _show_floating_tooltip(self, net: Dict[str, Any], x: float, y: float):
        """Hiển thị Tooltip chi tiết. Tự động chuyển sang Bảng So Sánh nếu kênh có nhiều mạng đè sóng."""
        self.delete("tooltip_box")

        target_ch = net.get("channel", 1)
        # Lấy tất cả mạng cùng kênh trong băng tần hiện tại
        collocated_nets = [
            n for n in self.networks
            if n.get("channel") == target_ch
            and (("2.4" in self.current_band and "2.4" in n.get("band", "")) or ("5" in self.current_band and "5" in n.get("band", "")))
        ]

        # Khử trùng lặp BSSID
        unique_nets = []
        seen = set()
        for n in collocated_nets:
            b = n.get("bssid")
            if b not in seen:
                seen.add(b)
                unique_nets.append(n)
        unique_nets.sort(key=lambda n: n.get("signal", 0), reverse=True)

        w = max(self.winfo_width(), 600)
        h = max(self.winfo_height(), 320)

        # TRƯỜNG HỢP A: KÊNH CÓ TỪ 2 MẠNG ĐÈ NHAU -> HIỆN BẢNG SO SÁNH ĐA MẠNG
        if len(unique_nets) >= 2:
            count = len(unique_nets)
            box_w = 420.0
            row_height = 28.0
            box_h = 72.0 + (count * row_height) + 36.0

            # Định vị tọa độ thẻ
            tx = x + 18.0
            if tx + box_w > w - 15:
                tx = x - box_w - 18.0
            tx = max(15.0, tx)

            ty = y - (box_h / 2.0)
            ty = max(15.0, min(ty, h - box_h - 15.0))

            # Bóng mờ
            self.create_rectangle(
                tx + 4, ty + 4, tx + box_w + 4, ty + box_h + 4,
                fill="#030712", outline="", tags="tooltip_box"
            )
            # Khung
            self.create_rectangle(
                tx, ty, tx + box_w, ty + box_h,
                fill="#0F172A", outline="#F59E0B" if count == 2 else "#EF4444", width=2, tags="tooltip_box"
            )

            # Tiêu đề
            self.create_text(
                tx + 16, ty + 20,
                text=f"⚠️ KÊNH {target_ch}: {count} MẠNG ĐANG ĐÈ SÓNG NHAU",
                fill="#F59E0B" if count == 2 else "#EF4444",
                font=("Segoe UI", 12, "bold"),
                anchor="w", tags="tooltip_box"
            )
            self.create_text(
                tx + 16, ty + 38,
                text="Hiện tượng can nhiễu đồng kênh (Co-Channel Interference) gây giảm tốc độ",
                fill="#94A3B8",
                font=("Segoe UI", 9),
                anchor="w", tags="tooltip_box"
            )
            # Gạch ngang
            self.create_line(tx + 14, ty + 50, tx + box_w - 14, ty + 50, fill="#334155", width=1, tags="tooltip_box")

            # Danh sách từng mạng
            start_y = ty + 64
            for idx, n in enumerate(unique_nets):
                cur_y = start_y + (idx * row_height)
                n_ssid = n.get("ssid", "Unknown")
                n_sig = n.get("signal", 0)
                n_rssi = n.get("rssi_dbm", -75)
                n_vendor = n.get("vendor", "Chưa rõ")
                n_radio = n.get("radio", "802.11")
                n_is_self = (n_ssid.lower() == self.current_connected_ssid.lower()) and self.current_connected_ssid != ""

                dot_color = "#38BDF8" if n_is_self else ("#34D399" if n_sig >= 70 else ("#FBBF24" if n_sig >= 40 else "#EF4444"))

                # Icon tròn nhỏ
                self.create_text(tx + 16, cur_y, text="●", fill=dot_color, font=("Segoe UI", 10), anchor="w", tags="tooltip_box")

                # Tên mạng
                lbl_name = f"★ {n_ssid}" if n_is_self else n_ssid
                if len(lbl_name) > 16:
                    lbl_name = lbl_name[:14] + ".."
                self.create_text(
                    tx + 30, cur_y,
                    text=lbl_name,
                    fill="#38BDF8" if n_is_self else "#F8FAFC",
                    font=("Segoe UI", 10, "bold" if n_is_self else "normal"),
                    anchor="w", tags="tooltip_box"
                )

                # Thông số tín hiệu & nhà sản xuất
                detail_str = f"{n_sig}% ({n_rssi} dBm)  •  {n_vendor}  •  {n_radio}"
                self.create_text(
                    tx + box_w - 16, cur_y,
                    text=detail_str,
                    fill="#94A3B8",
                    font=("Segoe UI", 9),
                    anchor="e", tags="tooltip_box"
                )

            # Footer gạch ngang & lời khuyên
            foot_y = ty + box_h - 22
            self.create_line(tx + 14, foot_y - 8, tx + box_w - 14, foot_y - 8, fill="#334155", width=1, tags="tooltip_box")
            self.create_text(
                tx + 16, foot_y + 4,
                text="💡 Nhấp chuột vào kênh để cô lập đồ thị | Router nên chuyển sang kênh vắng hơn",
                fill="#38BDF8",
                font=("Segoe UI", 9, "italic"),
                anchor="w", tags="tooltip_box"
            )
            return

        # TRƯỜNG HỢP B: KÊNH ĐỘC LẬP CHỈ CÓ 1 MẠNG -> HIỂN THỊ CHI TIẾT ĐẦY ĐỦ
        ssid = net.get("ssid", "Unknown")
        bssid = net.get("bssid", "—")
        vendor = net.get("vendor", "Chưa rõ hãng")
        ch = net.get("channel", 1)
        band = net.get("band", "2.4 GHz")
        sig = net.get("signal", 0)
        rssi = net.get("rssi_dbm", -75)
        radio = net.get("radio", "802.11")
        util = net.get("utilization", 0)
        is_self = (ssid.lower() == self.current_connected_ssid.lower()) and self.current_connected_ssid != ""

        box_w = 360.0
        box_h = 162.0

        tx = x + 18.0
        if tx + box_w > w - 15:
            tx = x - box_w - 18.0
        tx = max(15.0, tx)

        ty = y - box_h - 15.0
        if ty < 15:
            ty = y + 25.0
        if ty + box_h > h - 15:
            ty = h - box_h - 15.0

        # Đổ bóng
        self.create_rectangle(
            tx + 4, ty + 4, tx + box_w + 4, ty + box_h + 4,
            fill="#030712", outline="", tags="tooltip_box"
        )
        # Khung thẻ
        border_color = "#FACC15" if is_self else "#38BDF8"
        self.create_rectangle(
            tx, ty, tx + box_w, ty + box_h,
            fill="#0F172A", outline=border_color, width=2, tags="tooltip_box"
        )
        # Tiêu đề
        title_text = f"★ {ssid} (ĐANG KẾT NỐI)" if is_self else f"📶 {ssid}"
        self.create_text(
            tx + 16, ty + 20,
            text=title_text,
            fill=border_color,
            font=("Segoe UI", 13, "bold"),
            anchor="w", tags="tooltip_box"
        )
        sig_color = "#34D399" if sig >= 70 else ("#FBBF24" if sig >= 40 else "#EF4444")
        self.create_text(
            tx + box_w - 16, ty + 20,
            text=f"{sig}% ({rssi} dBm)",
            fill=sig_color,
            font=("Segoe UI", 12, "bold"),
            anchor="e", tags="tooltip_box"
        )
        self.create_line(tx + 14, ty + 36, tx + box_w - 14, ty + 36, fill="#334155", width=1, tags="tooltip_box")

        rows = [
            ("📻 Kênh phát:", f"Kênh {ch} ({band})  •  Chuẩn: {radio}"),
            ("🏷️ Nhà sản xuất:", f"{vendor}"),
            ("🔒 Modem BSSID:", f"{bssid}"),
            ("📊 Chiếm dụng kênh:", f"{util}% (Kênh độc lập, sóng thông thoáng)"),
        ]
        for i, (label, val) in enumerate(rows):
            row_y = ty + 54 + (i * 24)
            self.create_text(
                tx + 16, row_y,
                text=label,
                fill="#94A3B8",
                font=("Segoe UI", 10, "bold"),
                anchor="w", tags="tooltip_box"
            )
            self.create_text(
                tx + 140, row_y,
                text=val,
                fill="#F8FAFC",
                font=("Segoe UI", 11),
                anchor="w", tags="tooltip_box"
            )


class WifiChannelAnalyzerView(ctk.CTkFrame):
    """Giao diện chính Trình Phân Tích Kênh Sóng Wi-Fi (Wi-Fi Channel Analyzer View)."""

    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.scanner = WifiChannelScanner()
        self.all_networks: List[Dict[str, Any]] = []

        self._build_ui()

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        # --- 1. THANH TÓM TẮT CHỈ SỐ KPI ---
        kpi_frame = ctk.CTkFrame(self, fg_color=("#E5E7EB", "#1F2937"), corner_radius=10)
        kpi_frame.grid(row=0, column=0, padx=10, pady=(5, 8), sticky="ew")
        kpi_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self.kpi_total_bssids = self._create_kpi_card(kpi_frame, 0, "📶 Tổng Mạng Quét Được", "-- BSSID", "#38BDF8")
        self.kpi_cur_channel = self._create_kpi_card(kpi_frame, 1, "📍 Kênh Đang Kết Nối", "--", "#34D399")
        self.kpi_best_2g = self._create_kpi_card(kpi_frame, 2, "🏆 Kênh Tối Ưu 2.4 GHz", "--", "#FBBF24")
        self.kpi_best_5g = self._create_kpi_card(kpi_frame, 3, "🚀 Kênh Tối Ưu 5 GHz", "--", "#A855F7")

        # --- 2. THANH CÔNG CỤ TOOLBAR ---
        toolbar = ctk.CTkFrame(self, fg_color=("#E5E7EB", "#1F2937"), corner_radius=8, height=46)
        toolbar.grid(row=1, column=0, padx=10, pady=(0, 6), sticky="ew")

        # Nút Quét Lại Phổ Sóng
        self.btn_refresh = ctk.CTkButton(
            toolbar,
            text="🔄 QUÉT LẠI PHỔ SÓNG",
            command=self.refresh_scan,
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#0284C7",
            hover_color="#0369A1",
            height=32,
        )
        self.btn_refresh.pack(side="left", padx=10, pady=7)

        # Nút Chuyển Đổi Băng Tần (Segmented Button)
        self.seg_band = ctk.CTkSegmentedButton(
            toolbar,
            values=["📶 Băng Tần 2.4 GHz", "🚀 Băng Tần 5 GHz"],
            command=self._on_band_changed,
            font=ctk.CTkFont(size=12, weight="bold"),
            height=32,
        )
        self.seg_band.set("📶 Băng Tần 2.4 GHz")
        self.seg_band.pack(side="left", padx=10, pady=7)

        # Nhãn trạng thái
        self.lbl_status = ctk.CTkLabel(
            toolbar,
            text="Đang phân tích phổ sóng xung quanh...",
            font=ctk.CTkFont(size=12),
            text_color=("#4B5563", "#9CA3AF"),
        )
        self.lbl_status.pack(side="left", padx=12, pady=7)

        # --- 3. THANH CẢNH BÁO KÊNH BỊ TRÙNG ĐÈ SÓNG (CONGESTION BAR) ---
        self.frame_conflicts = ctk.CTkFrame(self, fg_color=("#E5E7EB", "#18181B"), corner_radius=8, height=36)
        self.frame_conflicts.grid(row=2, column=0, padx=10, pady=(0, 6), sticky="ew")

        # --- 4. KHUNG ĐỒ THỊ PHỔ SÓNG CANVAS ---
        canvas_box = ctk.CTkFrame(self, fg_color=("#0B0F19", "#0B0F19"), corner_radius=12)
        canvas_box.grid(row=3, column=0, padx=10, pady=0, sticky="nsew")
        canvas_box.grid_columnconfigure(0, weight=1)
        canvas_box.grid_rowconfigure(0, weight=1)

        self.spectrum_canvas = WifiSpectrumCanvas(canvas_box)
        self.spectrum_canvas.grid(row=0, column=0, padx=4, pady=4, sticky="nsew")
        self.spectrum_canvas.on_channel_selected_callback = self._update_conflict_bar

        # --- 5. KHUNG BÁO CÁO ĐÁNH GIÁ NGHẼN KÊNH ---
        footer_report = ctk.CTkFrame(self, fg_color=("#F3F4F6", "#1E293B"), corner_radius=10)
        footer_report.grid(row=4, column=0, padx=10, pady=(6, 5), sticky="ew")
        footer_report.grid_columnconfigure(0, weight=1)

        self.lbl_advice_title = ctk.CTkLabel(
            footer_report,
            text="💡 KHUYẾN NGHỊ TỐI ƯU HÓA KÊNH PHÁT ROUTER WI-FI",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=("#111827", "#F9FAFB"),
            anchor="w",
        )
        self.lbl_advice_title.pack(anchor="w", padx=16, pady=(8, 2))

        self.lbl_advice_body = ctk.CTkLabel(
            footer_report,
            text="Đang tính toán phân bố kênh...",
            font=ctk.CTkFont(size=11),
            text_color=("#4B5563", "#94A3B8"),
            justify="left",
            anchor="w",
        )
        self.lbl_advice_body.pack(anchor="w", padx=16, pady=(0, 8))

    def _create_kpi_card(self, parent, col: int, title: str, value: str, color: str):
        card = ctk.CTkFrame(parent, fg_color=("#F3F4F6", "#111827"), corner_radius=8)
        card.grid(row=0, column=col, padx=6, pady=6, sticky="ew")

        lbl_t = ctk.CTkLabel(card, text=title, font=ctk.CTkFont(size=11), text_color=("#6B7280", "#9CA3AF"))
        lbl_t.pack(anchor="w", padx=10, pady=(6, 0))

        lbl_v = ctk.CTkLabel(card, text=value, font=ctk.CTkFont(size=15, weight="bold"), text_color=color)
        lbl_v.pack(anchor="w", padx=10, pady=(0, 6))
        return lbl_v

    def _update_conflict_bar(self):
        """Cập nhật các nút chip hiển thị kênh đang bị đè sóng cho băng tần hiện tại."""
        for widget in self.frame_conflicts.winfo_children():
            widget.destroy()

        choice = self.seg_band.get()
        band_str = "2.4 GHz" if "2.4" in choice else "5 GHz"
        target_nets = [
            n for n in self.all_networks
            if ("2.4" in band_str and "2.4" in n.get("band", ""))
            or ("5" in band_str and "5" in n.get("band", ""))
        ]

        chan_counts = defaultdict(list)
        for n in target_nets:
            chan_counts[n.get("channel", 1)].append(n)

        conflicted_chans = {ch: nets for ch, nets in chan_counts.items() if len(nets) >= 2}

        if not conflicted_chans:
            lbl = ctk.CTkLabel(
                self.frame_conflicts,
                text=f"✅ Băng tần {band_str} rất thông thoáng: Không có kênh nào bị trùng đè sóng!",
                font=ctk.CTkFont(size=11, weight="bold"),
                text_color="#34D399",
            )
            lbl.pack(side="left", padx=12, pady=4)
            return

        # Tiêu đề cảnh báo
        lbl_title = ctk.CTkLabel(
            self.frame_conflicts,
            text="⚠️ CÁC KÊNH ĐANG BỊ ĐÈ SÓNG:",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="#F59E0B",
        )
        lbl_title.pack(side="left", padx=(10, 6), pady=4)

        # Hiển thị từng nút kênh bị đè sóng
        for ch in sorted(conflicted_chans.keys()):
            count = len(conflicted_chans[ch])
            is_sel = (self.spectrum_canvas.selected_channel == ch)

            if is_sel:
                btn_color = "#0284C7"
                hover_color = "#0369A1"
                btn_txt = f"🔍 Kênh {ch} ({count} mạng)"
            else:
                btn_color = "#B45309" if count == 2 else "#B91C1C"
                hover_color = "#D97706" if count == 2 else "#DC2626"
                btn_txt = f"⚠️ Kênh {ch} ({count} mạng)"

            def _make_cmd(target_ch=ch):
                return lambda: self._toggle_channel_focus(target_ch)

            btn = ctk.CTkButton(
                self.frame_conflicts,
                text=btn_txt,
                command=_make_cmd(ch),
                font=ctk.CTkFont(size=11, weight="bold"),
                fg_color=btn_color,
                hover_color=hover_color,
                height=26,
                corner_radius=6,
            )
            btn.pack(side="left", padx=4, pady=4)

        # Nút hủy cô lập nếu đang chọn kênh
        if self.spectrum_canvas.selected_channel is not None:
            btn_clear = ctk.CTkButton(
                self.frame_conflicts,
                text="✕ Xem Tất Cả",
                command=self._clear_channel_focus,
                font=ctk.CTkFont(size=11),
                fg_color="#374151",
                hover_color="#4B5563",
                height=26,
                corner_radius=6,
            )
            btn_clear.pack(side="left", padx=8, pady=4)

    def _toggle_channel_focus(self, ch: int):
        """Bật/tắt chế độ cô lập kênh từ nút chip."""
        if self.spectrum_canvas.selected_channel == ch:
            self.spectrum_canvas.selected_channel = None
        else:
            self.spectrum_canvas.selected_channel = ch
        self.spectrum_canvas.redraw()
        self._update_conflict_bar()

    def _clear_channel_focus(self):
        """Hủy bỏ cô lập kênh."""
        self.spectrum_canvas.selected_channel = None
        self.spectrum_canvas.redraw()
        self._update_conflict_bar()

    def _on_band_changed(self, choice: str):
        band_str = "2.4 GHz" if "2.4" in choice else "5 GHz"
        cur_ssid = get_wifi_ssid() or ""
        self.spectrum_canvas.set_data(self.all_networks, band=band_str, current_ssid=cur_ssid)
        self._update_conflict_bar()

    def refresh_scan(self):
        """Quét lại danh sách mạng Wi-Fi và cập nhật đồ thị."""
        self.btn_refresh.configure(state="disabled", text="⏳ ĐANG QUÉT PHỔ SÓNG...")
        self.lbl_status.configure(text="Đang nhận diện toàn bộ sóng Wi-Fi từ các nhà hàng xóm...", text_color="#38BDF8")
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self):
        networks = self.scanner.scan_surrounding_networks()
        recs = self.scanner.get_recommendations(networks)
        cur_ssid = get_wifi_ssid() or ""

        self.all_networks = networks
        self.after(0, lambda: self._apply_scan_results(networks, recs, cur_ssid))

    def _apply_scan_results(self, networks: List[Dict[str, Any]], recs: Dict[str, Any], cur_ssid: str):
        self.btn_refresh.configure(state="normal", text="🔄 QUÉT LẠI PHỔ SÓNG")
        total_bssid = len(networks)
        self.lbl_status.configure(
            text=f"Quét xong: Tìm thấy {total_bssid} BSSID sóng Wi-Fi xung quanh.",
            text_color="#34D399",
        )

        # 1. Cập nhật thẻ KPI
        self.kpi_total_bssids.configure(text=f"{total_bssid} BSSID")

        # Tìm kênh mạng hiện tại
        cur_chan = "--"
        for n in networks:
            if n.get("ssid", "").lower() == cur_ssid.lower():
                cur_chan = f"CH {n.get('channel', '--')} ({n.get('band', '')})"
                break
        self.kpi_cur_channel.configure(text=cur_chan)

        best_2g = recs.get("best_2g_channel", 1)
        best_5g = recs.get("best_5g_channel", 36)
        self.kpi_best_2g.configure(text=f"Kênh {best_2g} (Tối ưu)")
        self.kpi_best_5g.configure(text=f"Kênh {best_5g} (Tối ưu)")

        # 2. Cập nhật đồ thị Canvas
        choice = self.seg_band.get()
        band_str = "2.4 GHz" if "2.4" in choice else "5 GHz"
        self.spectrum_canvas.set_data(networks, band=band_str, current_ssid=cur_ssid)
        self._update_conflict_bar()

        # 3. Tạo thông điệp khuyến nghị
        counts_2g = recs.get("counts_2g", {})
        c1 = counts_2g.get(1, 0)
        c6 = counts_2g.get(6, 0)
        c11 = counts_2g.get(11, 0)

        advice_text = (
            f"• Băng tần 2.4 GHz: Kênh 1 có {c1} mạng, Kênh 6 có {c6} mạng, Kênh 11 có {c11} mạng.\n"
            f"👉 ĐỀ XUẤT: Router nhà bạn nên đặt ở [Kênh {best_2g}] để tránh can nhiễu đồng kênh với hàng xóm.\n"
            f"• Băng tần 5 GHz: Đang thông thoáng nhất ở [Kênh {best_5g}] (chuẩn sóng Wi-Fi 5/6 tốc độ Gigabit)."
        )
        self.lbl_advice_body.configure(text=advice_text)
