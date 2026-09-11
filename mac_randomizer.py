"""
mac_randomizer.py - Công cụ quản lý MAC riêng tư trên thiết bị của người dùng.

Áp dụng chuẩn IEEE 802.11 Locally Administered Addresses (LAA) và cơ chế
Windows Native Hardware MAC Randomization. Chỉ sử dụng trên adapter bạn sở hữu
hoặc được quản trị; không dùng để né chính sách truy cập hay giới hạn dịch vụ.
"""

import os
import re
import sys
import json
import time
import random
import subprocess
import threading
from typing import Dict, Any, Iterable, List, Optional, Tuple
import tkinter as tk
from tkinter import messagebox
import customtkinter as ctk

from oui_db import lookup_vendor, is_randomized_mac

# Prefix MAC mô phỏng các hãng thiết bị phổ biến (Bit LAA bật hoặc OUI nổi tiếng)
SIMULATED_PRESETS = {
    "laa": {
        "name": "Chuẩn Quốc Tế LAA (Ngẫu nhiên an toàn tuyệt đối)",
        "desc": "Theo chuẩn IEEE 802, chữ số thứ hai là 2, 6, A hoặc E. Mọi Router đều hỗ trợ.",
        "prefixes": ["02", "06", "0A", "0E", "12", "16", "1A", "1E", "22", "26", "2A", "2E", "62", "72", "A2", "E2"],
    },
    "apple": {
        "name": "Giả lập Apple iPhone / iPad (iOS Private MAC)",
        "desc": "Tạo địa chỉ MAC bảo mật tương tự iPhone sử dụng tính năng Private Wi-Fi Address.",
        "prefixes": ["02:F0", "06:CD", "12:EA", "62:23", "92:D0", "AE:22"],
    },
    "samsung": {
        "name": "Giả lập Samsung Galaxy (OneUI MAC)",
        "desc": "Mô phỏng điện thoại Samsung Galaxy chuyển vùng Wi-Fi.",
        "prefixes": ["26:DC", "42:5B", "8A:2C", "AA:11", "DA:39"],
    },
    "google": {
        "name": "Giả lập Google Pixel (Android Private MAC)",
        "desc": "Mô phỏng thiết bị Google Android sử dụng Randomized MAC.",
        "prefixes": ["32:8A", "6A:B2", "86:14", "CA:55"],
    },
}


def _hidden_process_kwargs() -> Dict[str, Any]:
    """Return Windows subprocess options that prevent a console window flashing."""
    if os.name != "nt":
        return {}

    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = subprocess.SW_HIDE
    return {
        "startupinfo": startupinfo,
        "creationflags": subprocess.CREATE_NO_WINDOW,
    }


def _run_hidden(command: List[str], **kwargs: Any) -> Any:
    """Run a system command without creating a visible Windows console."""
    options = _hidden_process_kwargs()
    options.update(kwargs)
    return subprocess.run(command, **options)


def clean_mac(mac_str: str) -> str:
    """Chuẩn hóa MAC thành 12 ký tự Hex viết hoa."""
    clean = (mac_str or "").strip().replace(":", "").replace("-", "").replace(".", "").upper()
    return clean


def format_mac_colon(clean_mac_str: str) -> str:
    """Định dạng chuỗi Hex thành AA:BB:CC:DD:EE:FF."""
    clean = clean_mac(clean_mac_str)
    if len(clean) == 12:
        return ":".join(clean[i : i + 2] for i in range(0, 12, 2))
    return clean_mac_str


def is_laa_mac(mac_str: str) -> bool:
    """
    Kiểm tra xem MAC có phải là Locally Administered Address (LAA / MAC Ảo) không.
    Theo chuẩn IEEE 802, nếu Bit 1 của Byte đầu tiên = 1 thì đó là LAA (Private/Random).
    """
    clean = clean_mac(mac_str)
    if len(clean) >= 2:
        try:
            first_byte = int(clean[:2], 16)
            return (first_byte & 0x02) != 0
        except ValueError:
            pass
    return False


def generate_random_mac(preset_key: str = "laa") -> str:
    """
    Sinh địa chỉ MAC ngẫu nhiên hợp lệ theo chuẩn IEEE 802.
    Bit 0 = 0 (Unicast) và Bit 1 = 1 (Locally Administered Address - LAA).
    Chữ số hex thứ hai luôn thuộc tập [2, 6, A, E].
    """
    preset = SIMULATED_PRESETS.get(preset_key, SIMULATED_PRESETS["laa"])
    prefix_choice = random.choice(preset["prefixes"])

    # Xử lý prefix
    clean_p = clean_mac(prefix_choice)
    needed_nibbles = 12 - len(clean_p)

    remaining = "".join(f"{random.randint(0, 15):X}" for _ in range(needed_nibbles))
    full_hex = clean_p + remaining

    # Đảm bảo bit LAA được bật nếu preset là LAA thông thường
    first_byte = int(full_hex[:2], 16)
    first_byte = (first_byte | 0x02) & 0xFE  # Bật bit 1, tắt bit 0
    full_hex = f"{first_byte:02X}" + full_hex[2:]

    return format_mac_colon(full_hex)


def get_wifi_adapter_info() -> Dict[str, Any]:
    """
    Lấy thông tin chi tiết về card mạng Wi-Fi và danh tính hiện tại:
    - Tên card, mô tả
    - MAC thực tế đang hoạt động (Active LinkLayer)
    - MAC phần cứng gốc của nhà sản xuất (Permanent / Burned-in)
    - Trạng thái LAA / MAC Ảo ngẫu nhiên
    - SSID, BSSID, Kênh, Băng tần, Cường độ tín hiệu
    - Chế độ MAC Randomization của profile hiện tại
    """
    info: Dict[str, Any] = {
        "adapter_name": "Wi-Fi",
        "adapter_desc": "Không xác định",
        "active_mac": "Chưa rõ",
        "permanent_mac": "Chưa rõ",
        "permanent_vendor": "Chưa rõ",
        "is_randomized": False,
        "ssid": "Chưa kết nối",
        "bssid": "",
        "band": "",
        "channel": "",
        "signal": "",
        "state": "disconnected",
        "profile_randomization": "Chưa rõ",
    }

    # 1. Truy vấn thông tin Wi-Fi chi tiết từ netsh wlan show interfaces
    try:
        res = _run_hidden(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
        )
        if res.returncode == 0:
            for line in res.stdout.splitlines():
                if ":" in line:
                    parts = line.split(":", 1)
                    k = parts[0].strip()
                    v = parts[1].strip()
                    if k == "Name":
                        info["adapter_name"] = v
                    elif k == "Description":
                        info["adapter_desc"] = v
                    elif k == "Physical address":
                        info["active_mac"] = format_mac_colon(v)
                    elif k == "State":
                        info["state"] = v
                    elif k == "SSID":
                        info["ssid"] = v
                    elif k == "AP BSSID":
                        info["bssid"] = v
                    elif k == "Band":
                        info["band"] = v
                    elif k == "Channel":
                        info["channel"] = v
                    elif k == "Signal":
                        info["signal"] = v
    except Exception as e:
        info["error_wlan"] = str(e)

    # 2. Truy vấn địa chỉ phần cứng vĩnh viễn (PermanentAddress) qua PowerShell Get-NetAdapter
    try:
        ps_cmd = (
            "Get-NetAdapter | Where-Object { $_.PhysicalMediaType -match '802.11' -or $_.MediaType -match '802.11' } "
            "| Select-Object -First 1 Name, InterfaceDescription, MacAddress, PermanentAddress, Status | ConvertTo-Json"
        )
        res_ps = _run_hidden(
            ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=8,
        )
        if res_ps.returncode == 0 and res_ps.stdout.strip():
            try:
                data = json.loads(res_ps.stdout)
                if isinstance(data, dict):
                    if data.get("PermanentAddress"):
                        info["permanent_mac"] = format_mac_colon(data["PermanentAddress"])
                    if data.get("MacAddress") and info["active_mac"] == "Chưa rõ":
                        info["active_mac"] = format_mac_colon(data["MacAddress"])
                    if data.get("InterfaceDescription") and info["adapter_desc"] == "Không xác định":
                        info["adapter_desc"] = data["InterfaceDescription"]
            except json.JSONDecodeError:
                pass
    except Exception as e:
        info["error_ps"] = str(e)

    # 3. Phân tích Vendor cho Permanent MAC
    if info["permanent_mac"] and info["permanent_mac"] != "Chưa rõ":
        v_name, _, _ = lookup_vendor(info["permanent_mac"])
        info["permanent_vendor"] = v_name
    elif info["active_mac"] and info["active_mac"] != "Chưa rõ":
        v_name, _, _ = lookup_vendor(info["active_mac"])
        info["permanent_vendor"] = v_name

    if info["permanent_vendor"] in ("Chưa rõ hãng", "unknown", "", "Thiết bị bảo mật (MAC riêng tư)"):
        desc_lower = info.get("adapter_desc", "").lower()
        if "intel" in desc_lower:
            info["permanent_vendor"] = "Intel Corporation"
        elif "realtek" in desc_lower:
            info["permanent_vendor"] = "Realtek Semiconductor"
        elif "broadcom" in desc_lower:
            info["permanent_vendor"] = "Broadcom"
        elif "qualcomm" in desc_lower or "atheros" in desc_lower:
            info["permanent_vendor"] = "Qualcomm Atheros"
        elif "mediatek" in desc_lower or "ralink" in desc_lower:
            info["permanent_vendor"] = "MediaTek"

    # 4. Kiểm tra xem Active MAC có phải là MAC ngẫu nhiên không
    if info["active_mac"] and info["active_mac"] != "Chưa rõ":
        is_laa = is_laa_mac(info["active_mac"])
        differs_from_perm = (
            info["permanent_mac"] != "Chưa rõ"
            and clean_mac(info["active_mac"]) != clean_mac(info["permanent_mac"])
        )
        info["is_randomized"] = is_laa or differs_from_perm or is_randomized_mac(info["active_mac"])

    # 5. Kiểm tra chế độ MAC Randomization của profile đang kết nối
    if info["ssid"] and info["ssid"] != "Chưa kết nối":
        try:
            p_res = _run_hidden(
                ["netsh", "wlan", "show", "profile", f"name={info['ssid']}"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=5,
            )
            for line in p_res.stdout.splitlines():
                if "MAC Randomization" in line and ":" in line:
                    info["profile_randomization"] = line.split(":", 1)[1].strip()
                    break
        except Exception:
            pass

    return info


def get_saved_wifi_profiles() -> List[str]:
    """Lấy danh sách tên tất cả các mạng Wi-Fi đã lưu trên hệ thống."""
    profiles: List[str] = []
    try:
        res = _run_hidden(
            ["netsh", "wlan", "show", "profiles"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
        )
        if res.returncode == 0:
            for line in res.stdout.splitlines():
                if ":" not in line:
                    continue
                label, ssid = line.split(":", 1)
                label = label.strip().lower()
                ssid = ssid.strip()
                # "show profiles" labels are localized by Windows, while the
                # actual SSID stays after the colon. Keep the heuristic narrow
                # enough to exclude interface headings such as "Wi-Fi:".
                if ssid and ("profile" in label or "hồ sơ" in label):
                    if ssid not in profiles:
                        profiles.append(ssid)
    except Exception:
        pass
    return profiles


def normalize_mac_randomization_mode(value: Any) -> Optional[str]:
    """Map Windows/localized profile status text to the app's three modes."""
    text = str(value or "").strip().lower()
    if not text:
        return None
    if "daily" in text or "hàng ngày" in text or "mỗi ngày" in text:
        return "daily"
    if text in {"no", "off", "false"} or "disabled" in text or "disable" in text or "tắt" in text:
        return "no"
    if text in {"yes", "on", "true"} or "enabled" in text or "enable" in text or "bật" in text:
        return "yes"
    return None


def get_mac_profile_settings(profiles: Optional[List[str]] = None) -> List[Dict[str, str]]:
    """Read privacy modes for saved Wi-Fi profiles without exposing credentials."""
    profile_names = list(profiles) if profiles is not None else get_saved_wifi_profiles()
    settings: List[Dict[str, str]] = []
    for ssid in profile_names:
        if not ssid:
            continue
        try:
            result = _run_hidden(
                ["netsh", "wlan", "show", "profile", f"name={ssid}"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=5,
            )
        except Exception:
            continue
        if result.returncode != 0:
            continue
        mode = None
        for line in result.stdout.splitlines():
            if ":" not in line:
                continue
            label = line.split(":", 1)[0].strip().lower()
            if "randomization" not in label and "ngẫu nhiên" not in label:
                continue
            mode = normalize_mac_randomization_mode(line.split(":", 1)[1])
            if mode:
                break
        if mode:
            settings.append({"ssid": ssid, "mode": mode})
    return settings


def apply_mac_profile_settings(settings: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Apply only validated privacy modes; never imports Wi-Fi passwords."""
    results: List[Dict[str, Any]] = []
    for item in settings or []:
        if not isinstance(item, dict):
            continue
        ssid = str(item.get("ssid") or "").strip()
        mode = normalize_mac_randomization_mode(item.get("mode"))
        if not ssid or mode is None:
            continue
        ok, message = set_mac_randomization_for_profile(ssid, mode=mode)
        results.append({"ssid": ssid, "mode": mode, "ok": ok, "message": message})
    return results


def set_mac_randomization_for_profile(ssid: str, mode: str = "yes") -> Tuple[bool, str]:
    """
    Đặt chế độ Randomization cho profile Wi-Fi.
    mode: 'yes' (Bật ngẫu nhiên), 'daily' (Đổi mỗi ngày), 'no' (Tắt - dùng MAC gốc).
    """
    if not ssid:
        return False, "Chưa chọn mạng Wi-Fi."

    valid_modes = {"yes", "daily", "no"}
    if mode.lower() not in valid_modes:
        mode = "yes"

    try:
        cmd = ["netsh", "wlan", "set", "profileparameter", f"name={ssid}", f"Randomization={mode.lower()}"]
        res = _run_hidden(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=6)
        if res.returncode == 0:
            mode_desc = {
                "yes": "Đã BẬT địa chỉ ngẫu nhiên",
                "daily": "Đã BẬT tự động đổi MAC MỖI NGÀY",
                "no": "Đã TẮT địa chỉ ngẫu nhiên (dùng MAC phần cứng gốc)",
            }
            return True, f"{mode_desc.get(mode.lower(), 'Thành công')} cho mạng '{ssid}'."
        else:
            return False, res.stderr.strip() or res.stdout.strip()
    except Exception as e:
        return False, f"Lỗi hệ thống: {str(e)}"


def force_generate_new_random_mac(ssid: str, reconnect: bool = True) -> Tuple[bool, str, Optional[int]]:
    """
    Tạo một địa chỉ MAC LAA mới cho profile Wi-Fi do người dùng quản lý:
    1. Xuất profile sang file XML tạm thời.
    2. Tạo một randomizationSeed ngẫu nhiên 32-bit mới.
    3. Cập nhật thẻ <MacRandomization> và <randomizationSeed>.
    4. Nạp lại profile vào hệ thống bằng 'netsh wlan add profile'.
    5. Nếu reconnect=True và máy đang kết nối mạng này, ngắt và kết nối lại ngay.
    """
    if not ssid:
        return False, "Chưa chọn mạng Wi-Fi.", None

    import tempfile

    temp_dir = tempfile.gettempdir()
    clean_name = re.sub(r'[\\/*?:"<>|]', "_", ssid)
    xml_filename = f"Wi-Fi-{clean_name}.xml"
    xml_path = os.path.join(temp_dir, xml_filename)

    try:
        # 1. Export profile
        export_cmd = ["netsh", "wlan", "export", "profile", f"name={ssid}", f"folder={temp_dir}"]
        exp_res = _run_hidden(export_cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=6)

        # Tìm file XML được sinh ra
        if not os.path.exists(xml_path):
            # Thử tìm file có đuôi .xml trong temp_dir vừa được sửa đổi
            found = False
            for f in os.listdir(temp_dir):
                if f.startswith("Wi-Fi-") and f.endswith(".xml") and clean_name in f:
                    xml_path = os.path.join(temp_dir, f)
                    found = True
                    break
            if not found:
                return False, f"Không thể xuất cấu hình profile cho mạng '{ssid}': {exp_res.stderr or exp_res.stdout}", None

        # 2. Đọc và chỉnh sửa XML
        with open(xml_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

        new_seed = random.randint(100000000, 4000000000)
        v3_block = (
            f"\t<MacRandomization xmlns=\"http://www.microsoft.com/networking/WLAN/profile/v3\">\n"
            f"\t\t<enableRandomization>true</enableRandomization>\n"
            f"\t\t<randomizationSeed>{new_seed}</randomizationSeed>\n"
            f"\t</MacRandomization>"
        )

        if "<MacRandomization" in content:
            new_content = re.sub(
                r"<MacRandomization[\s\S]*?</MacRandomization>",
                v3_block.strip(),
                content,
            )
        else:
            new_content = content.replace("</WLANProfile>", f"{v3_block}\n</WLANProfile>")

        with open(xml_path, "w", encoding="utf-8") as f:
            f.write(new_content)

        # 3. Nạp lại profile vào hệ thống
        add_cmd = ["netsh", "wlan", "add", "profile", f"filename={xml_path}", "user=all"]
        add_res = _run_hidden(add_cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=6)

        # Xóa file tạm
        try:
            if os.path.exists(xml_path):
                os.remove(xml_path)
        except Exception:
            pass

        if add_res.returncode != 0:
            return False, f"Không thể cập nhật cấu hình: {add_res.stderr or add_res.stdout}", None

        # 4. Tái kết nối nếu được yêu cầu
        if reconnect:
            # Kiểm tra xem có đang kết nối mạng này không
            current_info = get_wifi_adapter_info()
            if current_info.get("ssid") == ssid:
                reconn_ok, reconn_msg = reconnect_wifi(ssid)
                if reconn_ok:
                    return True, f"Đã cấp danh tính MAC ngẫu nhiên mới (Seed: {new_seed}) và kết nối lại thành công!", new_seed
                else:
                    return True, f"Đã cập nhật danh tính mới (Seed: {new_seed}). Lưu ý kết nối lại: {reconn_msg}", new_seed

        return True, f"Đã tạo danh tính ngẫu nhiên mới cho mạng '{ssid}' (Seed: {new_seed}). Khi kết nối, card Wi-Fi sẽ mang địa chỉ MAC hoàn toàn mới!", new_seed

    except Exception as e:
        return False, f"Lỗi trong quá trình đổi MAC: {str(e)}", None


def reconnect_wifi(ssid: str) -> Tuple[bool, str]:
    """Ngắt và kết nối lại mạng Wi-Fi để cập nhật địa chỉ MAC và yêu cầu IP mới từ Router."""
    try:
        # Ngắt kết nối
        _run_hidden(["netsh", "wlan", "disconnect"], capture_output=True, timeout=5)
        time.sleep(1.5)
        # Kết nối lại
        conn_res = _run_hidden(
            ["netsh", "wlan", "connect", f"name={ssid}"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=8,
        )
        if conn_res.returncode == 0:
            return True, f"Đã kết nối lại thành công vào Wi-Fi '{ssid}'."
        else:
            return False, f"Không thể tự động kết nối lại: {conn_res.stderr or conn_res.stdout}"
    except Exception as e:
        return False, f"Lỗi tái kết nối: {str(e)}"


def open_windows_wifi_settings() -> bool:
    """Mở trang cài đặt phần cứng ngẫu nhiên Wi-Fi của Windows Settings."""
    if os.name != "nt":
        return False
    try:
        os.startfile("ms-settings:network-wifi")
        return True
    except Exception:
        return False


def get_mac_privacy_tips() -> List[Dict[str, str]]:
    """Return lawful privacy and connection-troubleshooting guidance."""
    return [
        {
            "step": "1. Bảo vệ quyền riêng tư",
            "desc": "Dùng địa chỉ LAA để giảm việc các mạng bạn quản lý liên kết hoạt động của thiết bị qua MAC phần cứng.",
        },
        {
            "step": "2. Chỉ áp dụng trên adapter của bạn",
            "desc": "Đổi MAC có thể làm mất kết nối hoặc cần đăng nhập lại mạng; hãy lưu cấu hình hiện tại trước khi thử.",
        },
        {
            "step": "3. Tôn trọng chính sách mạng",
            "desc": "Không dùng MAC randomization để né captive portal, khóa truy cập, thanh toán hoặc cơ chế kiểm soát của quản trị viên.",
        },
        {
            "step": "4. Khắc phục kết nối",
            "desc": "Nếu mạng yêu cầu đăng nhập lại, mở trang cổng thông báo theo hướng dẫn của nhà cung cấp hoặc liên hệ quản trị viên.",
        },
        {
            "step": "5. Khôi phục khi cần",
            "desc": "Tắt tính năng hoặc khôi phục MAC phần cứng nếu gặp lỗi DHCP, lọc MAC, cấp phép thiết bị hoặc chẩn đoán sự cố.",
        },
    ]


# =====================================================================
# GIAO DIỆN CỬA SỔ QUẢN LÝ MAC RIÊNG TƯ (MacRandomizerWindow)
# =====================================================================


class MacRandomizerWindow(ctk.CTkToplevel):
    """Cửa sổ quản lý MAC riêng tư cho adapter do người dùng quản lý."""

    def __init__(self, master):
        super().__init__(master)

        self.title("🎭 Quản lý MAC riêng tư — MAC Randomizer")
        self.geometry("820x760")
        self.minsize(720, 640)

        self.transient(master)
        self.after(50, self.lift)

        self.adapter_info: Dict[str, Any] = {}
        self.saved_profiles: List[str] = []
        self.is_busy = False

        self._build_ui()
        self._refresh_data_async()

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # ---------------- 1. HEADER BANNER ----------------
        header = ctk.CTkFrame(self, corner_radius=0, height=75, fg_color=("#F3F4F6", "#0F172A"))
        header.grid(row=0, column=0, sticky="ew")
        header.grid_columnconfigure(1, weight=1)

        lbl_icon = ctk.CTkLabel(header, text="🎭", font=ctk.CTkFont(size=36))
        lbl_icon.grid(row=0, column=0, rowspan=2, padx=(20, 15), pady=12)

        lbl_title = ctk.CTkLabel(
            header,
            text="TRÌNH ĐỔI DANH TÍNH CARD MẠNG (MAC RANDOMIZER)",
            font=ctk.CTkFont(size=17, weight="bold"),
            text_color=("#1E293B", "#F8FAFC"),
            anchor="w",
        )
        lbl_title.grid(row=0, column=1, sticky="w", pady=(10, 2))

        lbl_sub = ctk.CTkLabel(
            header,
            text="Đổi địa chỉ MAC để tăng quyền riêng tư trên adapter bạn quản lý",
            font=ctk.CTkFont(size=12),
            text_color=("#64748B", "#94A3B8"),
            anchor="w",
        )
        lbl_sub.grid(row=1, column=1, sticky="w", pady=(0, 10))

        # Nút làm mới dữ liệu góc phải
        self.btn_refresh = ctk.CTkButton(
            header,
            text="🔄 Làm mới",
            font=ctk.CTkFont(size=12, weight="bold"),
            width=95,
            height=32,
            fg_color="#3B82F6",
            hover_color="#2563EB",
            command=self._refresh_data_async,
        )
        self.btn_refresh.grid(row=0, column=2, rowspan=2, padx=20, pady=12, sticky="e")

        # ---------------- 2. MAIN SCROLLABLE CONTAINER ----------------
        self.scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self.scroll.grid(row=1, column=0, sticky="nsew", padx=15, pady=(5, 5))
        self.scroll.grid_columnconfigure(0, weight=1)

        # A. THẺ DANH TÍNH HIỆN TẠI (Current Identity Card)
        self._build_identity_card(self.scroll)

        # B. THẺ BẢNG ĐIỀU KHIỂN 1-CLICK (Control Card)
        self._build_control_card(self.scroll)

        # C. THẺ TRÌNH TẠO MAC & GIẢ LẬP HÃNG (Generator Card)
        self._build_generator_card(self.scroll)

        # D. THẺ HƯỚNG DẪN RIÊNG TƯ HỢP PHÁP (Guide Card)
        self._build_guide_card(self.scroll)

        # ---------------- 3. FOOTER STATUS BAR ----------------
        footer = ctk.CTkFrame(self, height=32, corner_radius=0, fg_color=("#E2E8F0", "#1E293B"))
        footer.grid(row=2, column=0, sticky="ew")
        footer.grid_columnconfigure(0, weight=1)

        self.lbl_status = ctk.CTkLabel(
            footer,
            text="Đang phân tích cấu hình card mạng Wi-Fi...",
            font=ctk.CTkFont(size=12),
            text_color=("#334155", "#CBD5E1"),
            anchor="w",
            padx=20,
        )
        self.lbl_status.grid(row=0, column=0, sticky="w")

        btn_settings = ctk.CTkButton(
            footer,
            text="⚙️ Cài đặt Wi-Fi Windows",
            font=ctk.CTkFont(size=11),
            width=160,
            height=24,
            fg_color="transparent",
            text_color=("#2563EB", "#60A5FA"),
            hover_color=("#DBEAFE", "#334155"),
            command=open_windows_wifi_settings,
        )
        btn_settings.grid(row=0, column=1, sticky="e", padx=15)

    def _build_identity_card(self, parent):
        """Thẻ hiển thị thông tin danh tính card Wi-Fi hiện tại."""
        card = ctk.CTkFrame(parent, corner_radius=10, fg_color=("#FFFFFF", "#1E293B"), border_width=1, border_color=("#E2E8F0", "#334155"))
        card.grid(row=0, column=0, sticky="ew", padx=5, pady=8)
        card.grid_columnconfigure((0, 1), weight=1)

        # Tiêu đề Card
        title_box = ctk.CTkFrame(card, fg_color="transparent")
        title_box.grid(row=0, column=0, columnspan=2, sticky="ew", padx=16, pady=(14, 10))
        title_box.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            title_box,
            text="📌 DANH TÍNH MẠNG HIỆN TẠI (CURRENT NETWORK IDENTITY)",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=("#0284C7", "#38BDF8"),
            anchor="w",
        ).grid(row=0, column=0, sticky="w")

        self.lbl_privacy_badge = ctk.CTkLabel(
            title_box,
            text="🛡️ ĐANG KIỂM TRA...",
            font=ctk.CTkFont(size=11, weight="bold"),
            corner_radius=6,
            fg_color="#475569",
            text_color="#F8FAFC",
            padx=10,
            pady=3,
        )
        self.lbl_privacy_badge.grid(row=0, column=1, sticky="e")

        # Khung thông tin MAC Đang Hoạt Động (To & Nổi bật)
        active_mac_box = ctk.CTkFrame(card, corner_radius=8, fg_color=("#F8FAFC", "#0F172A"), border_width=1, border_color=("#CBD5E1", "#334155"))
        active_mac_box.grid(row=1, column=0, columnspan=2, sticky="ew", padx=16, pady=(0, 12))
        active_mac_box.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(active_mac_box, text="🎭 ĐỊA CHỈ MAC ĐANG DÙNG:", font=ctk.CTkFont(size=11, weight="bold"), text_color=("#64748B", "#94A3B8")).grid(row=0, column=0, padx=14, pady=(10, 2), sticky="w")

        self.lbl_active_mac = ctk.CTkLabel(
            active_mac_box,
            text="--:--:--:--:--:--",
            font=ctk.CTkFont(family="Consolas", size=22, weight="bold"),
            text_color=("#2563EB", "#60A5FA"),
        )
        self.lbl_active_mac.grid(row=1, column=0, padx=14, pady=(0, 10), sticky="w")

        self.lbl_mac_desc = ctk.CTkLabel(
            active_mac_box,
            text="Đang nhận diện trạng thái MAC...",
            font=ctk.CTkFont(size=12),
            text_color=("#475569", "#94A3B8"),
            anchor="e",
        )
        self.lbl_mac_desc.grid(row=1, column=1, padx=14, pady=(0, 10), sticky="e")

        # Chi tiết phần cứng và kết nối
        details_box = ctk.CTkFrame(card, fg_color="transparent")
        details_box.grid(row=2, column=0, columnspan=2, sticky="ew", padx=16, pady=(0, 14))
        details_box.grid_columnconfigure((0, 1), weight=1)

        # Cột trái
        self.lbl_adapter_info = ctk.CTkLabel(details_box, text="📟 Card Wi-Fi: Đang đọc...", font=ctk.CTkFont(size=12), anchor="w", text_color=("#334155", "#E2E8F0"))
        self.lbl_adapter_info.grid(row=0, column=0, sticky="w", pady=2)

        self.lbl_permanent_mac = ctk.CTkLabel(details_box, text="🏷️ MAC Gốc Phần Cứng: Đang đọc...", font=ctk.CTkFont(size=12), anchor="w", text_color=("#334155", "#E2E8F0"))
        self.lbl_permanent_mac.grid(row=1, column=0, sticky="w", pady=2)

        # Cột phải
        self.lbl_wifi_conn = ctk.CTkLabel(details_box, text="📶 Wi-Fi: Chưa kết nối", font=ctk.CTkFont(size=12), anchor="w", text_color=("#334155", "#E2E8F0"))
        self.lbl_wifi_conn.grid(row=0, column=1, sticky="w", pady=2)

        self.lbl_random_mode = ctk.CTkLabel(details_box, text="🔄 Chế độ Đổi MAC: Chưa rõ", font=ctk.CTkFont(size=12), anchor="w", text_color=("#334155", "#E2E8F0"))
        self.lbl_random_mode.grid(row=1, column=1, sticky="w", pady=2)

    def _build_control_card(self, parent):
        """Thẻ điều khiển đổi MAC 1-click."""
        card = ctk.CTkFrame(parent, corner_radius=10, fg_color=("#FFFFFF", "#1E293B"), border_width=1, border_color=("#E2E8F0", "#334155"))
        card.grid(row=1, column=0, sticky="ew", padx=5, pady=8)
        card.grid_columnconfigure(0, weight=1)

        # Tiêu đề Card
        ctk.CTkLabel(
            card,
            text="⚡ QUẢN LÝ ĐỊA CHỈ MAC RIÊNG TƯ",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=("#10B981", "#34D399"),
            anchor="w",
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(14, 8))

        # Khung chọn profile mạng
        sel_frame = ctk.CTkFrame(card, fg_color="transparent")
        sel_frame.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 10))
        sel_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(sel_frame, text="Chọn mạng Wi-Fi cần áp dụng:", font=ctk.CTkFont(size=12, weight="bold")).grid(row=0, column=0, padx=(0, 10), sticky="w")

        self.profile_combo = ctk.CTkOptionMenu(
            sel_frame,
            values=["Đang quét danh sách Wi-Fi..."],
            width=260,
            height=32,
            font=ctk.CTkFont(size=12),
        )
        self.profile_combo.grid(row=0, column=1, sticky="w")

        self.chk_reconnect = ctk.CTkCheckBox(
            sel_frame,
            text="Tự động kết nối lại Wi-Fi sau khi áp dụng cấu hình",
            font=ctk.CTkFont(size=12),
        )
        self.chk_reconnect.grid(row=0, column=2, padx=(15, 0), sticky="e")
        self.chk_reconnect.select()

        # NÚT HÀNH ĐỘNG CHÍNH (3 NÚT NỔI BẬT)
        btn_grid = ctk.CTkFrame(card, fg_color="transparent")
        btn_grid.grid(row=2, column=0, sticky="ew", padx=16, pady=(5, 16))
        btn_grid.grid_columnconfigure((0, 1, 2), weight=1)

        # 1. Áp dụng địa chỉ MAC riêng tư mới (Lớn nhất, màu Xanh Ngọc)
        self.btn_force_random = ctk.CTkButton(
            btn_grid,
            text="🎲 ÁP DỤNG MAC RIÊNG TƯ\n(Địa chỉ LAA mới)",
            font=ctk.CTkFont(size=13, weight="bold"),
            height=52,
            fg_color="#10B981",
            hover_color="#059669",
            command=self._on_click_force_new_mac,
        )
        self.btn_force_random.grid(row=0, column=0, padx=(0, 6), sticky="ew")

        # 2. Nút Tự Động Đổi Hằng Ngày
        self.btn_daily_mode = ctk.CTkButton(
            btn_grid,
            text="📅 ĐỔI MAC MỖI NGÀY\n(Daily Randomization)",
            font=ctk.CTkFont(size=12, weight="bold"),
            height=52,
            fg_color="#8B5CF6",
            hover_color="#7C3AED",
            command=lambda: self._on_set_mode("daily"),
        )
        self.btn_daily_mode.grid(row=0, column=1, padx=6, sticky="ew")

        # 3. Nút Khôi Phục MAC Thật Của Máy
        self.btn_restore_mac = ctk.CTkButton(
            btn_grid,
            text="🔄 DÙNG MAC GỐC\n(Khôi Phục Phần Cứng)",
            font=ctk.CTkFont(size=12, weight="bold"),
            height=52,
            fg_color="#64748B",
            hover_color="#475569",
            command=lambda: self._on_set_mode("no"),
        )
        self.btn_restore_mac.grid(row=0, column=2, padx=(6, 0), sticky="ew")

    def _build_generator_card(self, parent):
        """Thẻ sinh địa chỉ MAC ngẫu nhiên theo chuẩn và mô phỏng hãng."""
        card = ctk.CTkFrame(parent, corner_radius=10, fg_color=("#FFFFFF", "#1E293B"), border_width=1, border_color=("#E2E8F0", "#334155"))
        card.grid(row=2, column=0, sticky="ew", padx=5, pady=8)
        card.grid_columnconfigure(0, weight=1)

        # Tiêu đề Card
        ctk.CTkLabel(
            card,
            text="🛠️ TRÌNH TẠO & MÔ PHỎNG ĐỊA CHỈ MAC (MAC GENERATOR & EMULATOR)",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=("#F59E0B", "#FBBF24"),
            anchor="w",
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(14, 8))

        gen_frame = ctk.CTkFrame(card, fg_color="transparent")
        gen_frame.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 14))
        gen_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(gen_frame, text="Kiểu mô phỏng:", font=ctk.CTkFont(size=12, weight="bold")).grid(row=0, column=0, padx=(0, 10), sticky="w")

        preset_options = [
            "Chuẩn Quốc Tế LAA (An toàn mọi Router)",
            "Apple iPhone (iOS Private MAC)",
            "Samsung Galaxy (OneUI Private MAC)",
            "Google Pixel (Android Private MAC)",
        ]
        self.preset_combo = ctk.CTkOptionMenu(
            gen_frame,
            values=preset_options,
            width=280,
            height=32,
            font=ctk.CTkFont(size=12),
            command=lambda v: self._generate_sample_mac(),
        )
        self.preset_combo.grid(row=0, column=1, sticky="w")

        # Hàng hiển thị MAC sinh ra
        mac_display_frame = ctk.CTkFrame(card, fg_color=("#F8FAFC", "#0F172A"), corner_radius=8, border_width=1, border_color=("#CBD5E1", "#334155"))
        mac_display_frame.grid(row=2, column=0, sticky="ew", padx=16, pady=(0, 14))
        mac_display_frame.grid_columnconfigure(0, weight=1)

        self.entry_generated_mac = ctk.CTkEntry(
            mac_display_frame,
            font=ctk.CTkFont(family="Consolas", size=15, weight="bold"),
            height=36,
            fg_color="transparent",
            border_width=0,
        )
        self.entry_generated_mac.grid(row=0, column=0, padx=10, pady=6, sticky="ew")

        btn_box = ctk.CTkFrame(mac_display_frame, fg_color="transparent")
        btn_box.grid(row=0, column=1, padx=6, pady=6, sticky="e")

        ctk.CTkButton(
            btn_box,
            text="🎲 Tạo Mã Khác",
            font=ctk.CTkFont(size=12),
            width=105,
            height=32,
            fg_color="#D97706",
            hover_color="#B45309",
            command=self._generate_sample_mac,
        ).pack(side="left", padx=4)

        ctk.CTkButton(
            btn_box,
            text="📋 Sao Chép",
            font=ctk.CTkFont(size=12),
            width=85,
            height=32,
            fg_color="#3B82F6",
            hover_color="#2563EB",
            command=self._copy_generated_mac,
        ).pack(side="left", padx=4)

        self._generate_sample_mac()

    def _build_guide_card(self, parent):
        """Thẻ hướng dẫn sử dụng MAC randomization an toàn và hợp pháp."""
        card = ctk.CTkFrame(parent, corner_radius=10, fg_color=("#FFFFFF", "#1E293B"), border_width=1, border_color=("#E2E8F0", "#334155"))
        card.grid(row=3, column=0, sticky="ew", padx=5, pady=8)
        card.grid_columnconfigure(0, weight=1)

        # Tiêu đề Card
        ctk.CTkLabel(
            card,
            text="📖 HƯỚNG DẪN RIÊNG TƯ & KHẮC PHỤC KẾT NỐI",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=("#6366F1", "#818CF8"),
            anchor="w",
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(14, 10))

        tips = get_mac_privacy_tips()
        for idx, tip in enumerate(tips):
            tip_box = ctk.CTkFrame(card, fg_color=("#F8FAFC", "#0F172A"), corner_radius=6)
            tip_box.grid(row=idx + 1, column=0, sticky="ew", padx=16, pady=3)
            tip_box.grid_columnconfigure(1, weight=1)

            ctk.CTkLabel(
                tip_box,
                text=tip["step"],
                font=ctk.CTkFont(size=12, weight="bold"),
                text_color=("#2563EB", "#60A5FA"),
                width=170,
                anchor="w",
                padx=10,
            ).grid(row=0, column=0, sticky="w", pady=6)

            ctk.CTkLabel(
                tip_box,
                text=tip["desc"],
                font=ctk.CTkFont(size=12),
                text_color=("#475569", "#CBD5E1"),
                anchor="w",
                wraplength=520,
                justify="left",
            ).grid(row=0, column=1, sticky="w", padx=10, pady=6)

        # Chú thích an toàn dưới cùng
        note_box = ctk.CTkLabel(
            card,
            text="💡 Cơ chế đổi MAC qua Profile Seed tương thích 100% với Windows 10/11, không sửa registry driver gây lỗi màn hình xanh.",
            font=ctk.CTkFont(size=11, slant="italic"),
            text_color=("#64748B", "#94A3B8"),
            anchor="w",
            padx=16,
            pady=10,
        )
        note_box.grid(row=len(tips) + 1, column=0, sticky="w")

    # =====================================================================
    # LOGIC XỬ LÝ SỰ KIỆN & THREADING
    # =====================================================================

    def _refresh_data_async(self):
        """Làm mới dữ liệu không đồng bộ để tránh đơ giao diện."""
        if self.is_busy:
            return

        self.btn_refresh.configure(state="disabled", text="⏳ Đang đọc...")
        self.lbl_status.configure(text="Đang phân tích cấu hình card mạng Wi-Fi và danh tính hiện tại...")

        def worker():
            info = get_wifi_adapter_info()
            profiles = get_saved_wifi_profiles()
            self.after(0, lambda: self._apply_data(info, profiles))

        threading.Thread(target=worker, daemon=True).start()

    def _apply_data(self, info: Dict[str, Any], profiles: List[str]):
        """Cập nhật dữ liệu lên giao diện."""
        self.adapter_info = info
        self.saved_profiles = profiles

        # 1. MAC đang dùng
        active_mac = info.get("active_mac", "Chưa rõ")
        self.lbl_active_mac.configure(text=active_mac)

        # Trạng thái bảo mật / LAA
        if info.get("is_randomized"):
            self.lbl_privacy_badge.configure(
                text="🛡️ DANH TÍNH ẢO ĐÃ BẬT (Private / Randomized MAC)",
                fg_color="#10B981",
                text_color="#FFFFFF",
            )
            self.lbl_mac_desc.configure(
                text="✓ Đang ẩn danh tính thật. Router chỉ thấy địa chỉ ảo ngẫu nhiên này.",
                text_color=("#059669", "#34D399"),
            )
        else:
            self.lbl_privacy_badge.configure(
                text="⚠️ ĐANG DÙNG MAC GỐC PHẦN CỨNG",
                fg_color="#EF4444",
                text_color="#FFFFFF",
            )
            self.lbl_mac_desc.configure(
                text="⚠️ Lộ danh tính thiết bị gốc! Bấm nút bên dưới để đổi sang MAC ngẫu nhiên.",
                text_color=("#DC2626", "#F87171"),
            )

        # 2. Chi tiết card
        desc = info.get("adapter_desc", "Không xác định")
        name = info.get("adapter_name", "Wi-Fi")
        self.lbl_adapter_info.configure(text=f"📟 Card: {name} ({desc})")

        # MAC gốc
        perm_mac = info.get("permanent_mac", "Chưa rõ")
        vendor = info.get("permanent_vendor", "Chưa rõ")
        self.lbl_permanent_mac.configure(text=f"🏷️ MAC Gốc: {perm_mac} [{vendor}]")

        # Kết nối Wi-Fi
        ssid = info.get("ssid", "Chưa kết nối")
        band = info.get("band", "")
        sig = info.get("signal", "")
        conn_str = f"📶 Wi-Fi: {ssid}"
        if band:
            conn_str += f" ({band})"
        if sig:
            conn_str += f" — Sóng: {sig}"
        self.lbl_wifi_conn.configure(text=conn_str)

        # Chế độ đổi MAC
        mode_val = info.get("profile_randomization", "Chưa rõ")
        mode_trans = {
            "Enabled": "Bật (Ngẫu nhiên)",
            "Daily": "Tự động đổi Mỗi Ngày",
            "Disabled": "Tắt (Dùng MAC gốc)",
        }
        self.lbl_random_mode.configure(text=f"🔄 Trạng thái Profile: {mode_trans.get(mode_val, mode_val)}")

        # 3. Cập nhật Combobox chọn mạng
        if profiles:
            self.profile_combo.configure(values=profiles)
            if ssid in profiles:
                self.profile_combo.set(ssid)
            else:
                self.profile_combo.set(profiles[0])
        else:
            self.profile_combo.configure(values=[ssid] if ssid != "Chưa kết nối" else ["Không tìm thấy profile"])

        self.btn_refresh.configure(state="normal", text="🔄 Làm mới")
        self.lbl_status.configure(text=f"Sẵn sàng. Danh tính hiện tại: {active_mac} ({'Đã ẩn danh' if info.get('is_randomized') else 'MAC Thật'}).")

    def _generate_sample_mac(self):
        """Sinh địa chỉ MAC mẫu theo preset đã chọn."""
        val = self.preset_combo.get()
        preset_key = "laa"
        if "Apple" in val:
            preset_key = "apple"
        elif "Samsung" in val:
            preset_key = "samsung"
        elif "Pixel" in val or "Google" in val:
            preset_key = "google"

        mac = generate_random_mac(preset_key)
        self.entry_generated_mac.delete(0, "end")
        self.entry_generated_mac.insert(0, mac)

    def _copy_generated_mac(self):
        """Sao chép địa chỉ MAC vào Clipboard."""
        mac = self.entry_generated_mac.get().strip()
        if mac:
            self.clipboard_clear()
            self.clipboard_append(mac)
            self.lbl_status.configure(text=f"Đã sao chép địa chỉ MAC '{mac}' vào Clipboard!")

    def _on_click_force_new_mac(self):
        """Người dùng bấm nút 1-Click Đổi MAC Mới."""
        target_ssid = self.profile_combo.get()
        if not target_ssid or target_ssid.startswith("Đang") or target_ssid.startswith("Không"):
            messagebox.showwarning("Chưa chọn mạng", "Vui lòng chọn mạng Wi-Fi bạn muốn đổi danh tính!", parent=self)
            return

        reconnect = bool(self.chk_reconnect.get())
        msg = (
            f"Bạn có muốn áp dụng một địa chỉ MAC LAA ngẫu nhiên mới cho mạng '{target_ssid}'?\n\n"
            f"- Địa chỉ LAA mới chỉ phục vụ mục đích riêng tư trên adapter bạn quản lý.\n"
            f"- Một số mạng có thể yêu cầu đăng nhập lại hoặc từ chối thiết bị; hãy tuân thủ chính sách của quản trị viên.\n"
        )
        if reconnect and target_ssid == self.adapter_info.get("ssid"):
            msg += "- Kết nối Wi-Fi sẽ ngắt và tự động kết nối lại sau 1-2 giây."

        if not messagebox.askyesno("Xác nhận đổi danh tính", msg, parent=self):
            return

        self._set_busy_state(True, "Đang tạo danh tính MAC mới và cập nhật cấu hình...")

        def worker():
            ok, text, seed = force_generate_new_random_mac(target_ssid, reconnect=reconnect)
            time.sleep(1)
            new_info = get_wifi_adapter_info()

            def finish():
                self._set_busy_state(False)
                self._apply_data(new_info, self.saved_profiles)
                if ok:
                    messagebox.showinfo(
                        "Đổi Danh Tính Thành Công",
                        f"🎉 THÀNH CÔNG!\n\n{text}\n\nĐịa chỉ MAC hiện tại: {new_info.get('active_mac')}\n\n"
                        "💡 Nếu kết nối bị ngắt, hãy kết nối lại theo chính sách của mạng hoặc liên hệ quản trị viên.",
                        parent=self,
                    )
                else:
                    messagebox.showerror("Không thể đổi MAC", f"Lỗi: {text}", parent=self)

            self.after(0, finish)

        threading.Thread(target=worker, daemon=True).start()

    def _on_set_mode(self, mode: str):
        """Đặt chế độ Daily hoặc Khôi phục MAC gốc."""
        target_ssid = self.profile_combo.get()
        if not target_ssid or target_ssid.startswith("Đang") or target_ssid.startswith("Không"):
            messagebox.showwarning("Chưa chọn mạng", "Vui lòng chọn mạng Wi-Fi cần áp dụng!", parent=self)
            return

        mode_names = {
            "daily": "Tự Động Đổi MAC Mỗi Ngày (Daily)",
            "no": "Khôi Phục Dùng MAC Gốc Phần Cứng",
        }
        action_name = mode_names.get(mode, mode)

        if not messagebox.askyesno(
            "Xác nhận thay đổi",
            f"Bạn có muốn thiết lập chế độ '{action_name}' cho mạng '{target_ssid}'?",
            parent=self,
        ):
            return

        self._set_busy_state(True, f"Đang áp dụng chế độ {action_name}...")

        def worker():
            ok, text = set_mac_randomization_for_profile(target_ssid, mode=mode)
            # Nếu đang kết nối mạng này và người dùng muốn khôi phục MAC gốc, kết nối lại
            if ok and self.chk_reconnect.get() and target_ssid == self.adapter_info.get("ssid"):
                reconnect_wifi(target_ssid)

            time.sleep(1)
            new_info = get_wifi_adapter_info()

            def finish():
                self._set_busy_state(False)
                self._apply_data(new_info, self.saved_profiles)
                if ok:
                    messagebox.showinfo("Cập nhật thành công", f"✓ {text}", parent=self)
                else:
                    messagebox.showerror("Lỗi thiết lập", f"Không thể đổi chế độ: {text}", parent=self)

            self.after(0, finish)

        threading.Thread(target=worker, daemon=True).start()

    def _set_busy_state(self, busy: bool, status_msg: str = ""):
        """Khóa các nút khi đang thao tác với mạng."""
        self.is_busy = busy
        st = "disabled" if busy else "normal"
        self.btn_force_random.configure(state=st)
        self.btn_daily_mode.configure(state=st)
        self.btn_restore_mac.configure(state=st)
        self.btn_refresh.configure(state=st)
        if status_msg:
            self.lbl_status.configure(text=status_msg)
