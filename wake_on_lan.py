"""
wake_on_lan.py - Module đánh thức máy tính từ xa qua mạng LAN (Wake-on-LAN - WoL).
Sử dụng giao thức tiêu chuẩn quốc tế AMD Magic Packet qua UDP Broadcast.
Cung cấp quản lý danh bạ máy tính đã lưu (Saved PCs) và hướng dẫn bật WoL trong BIOS/Windows.
"""

import os
import sys
import json
import socket
import time
from typing import Dict, Any, List, Optional

if getattr(sys, "frozen", False):
    CURRENT_DIR = os.path.dirname(sys.executable)
else:
    CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

SAVED_WOL_FILE = os.path.join(CURRENT_DIR, "saved_wol_devices.json")


def clean_mac(mac_str: str) -> str:
    """Chuẩn hóa địa chỉ MAC thành 12 ký tự Hex viết hoa."""
    clean = (mac_str or "").strip().replace(":", "").replace("-", "").replace(".", "").upper()
    if len(clean) != 12:
        raise ValueError("Địa chỉ MAC không hợp lệ (cần đúng 12 ký tự Hex, ví dụ: AA:BB:CC:DD:EE:FF)")
    # Kiểm tra xem có phải ký tự Hex hợp lệ
    int(clean, 16)
    return clean


def format_mac_colon(clean_mac_str: str) -> str:
    """Định dạng chuỗi 12 ký tự thành AA:BB:CC:DD:EE:FF."""
    return ":".join(clean_mac_str[i : i + 2] for i in range(0, 12, 2))


def send_magic_packet(
    mac_address: str,
    broadcast_ip: str = "255.255.255.255",
    subnet_ip: Optional[str] = None,
    port: int = 9,
    repetitions: int = 3,
) -> Dict[str, Any]:
    """
    Gửi gói tin Magic Packet tới card mạng của máy tính đích để đánh thức máy.
    - Cấu trúc: 6 byte 0xFF + lặp lại 16 lần chuỗi 6 byte MAC = 102 bytes.
    - Gửi qua UDP broadcast tới cả 255.255.255.255 và cổng 9 lẫn cổng 7.
    """
    try:
        raw_mac = clean_mac(mac_address)
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "mac": mac_address,
        }

    mac_bytes = bytes.fromhex(raw_mac)
    magic_packet = b"\xff" * 6 + (mac_bytes * 16)

    targets = [
        (broadcast_ip, port),
        (broadcast_ip, 7),  # Thêm cổng 7 dự phòng
    ]
    if subnet_ip:
        # Nếu có địa chỉ subnet broadcast (ví dụ 192.168.1.255)
        targets.append((subnet_ip, port))

    sent_count = 0
    errors = []

    for _ in range(repetitions):
        for host, p in targets:
            s = None
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                s.sendto(magic_packet, (host, p))
                sent_count += 1
            except Exception as ex:
                errors.append(str(ex))
            finally:
                if s:
                    try:
                        s.close()
                    except Exception:
                        pass
        time.sleep(0.04)  # Giãn cách nhẹ 40ms giữa các lần bắn gói tin

    if sent_count > 0:
        return {
            "success": True,
            "mac": format_mac_colon(raw_mac),
            "sent_packets": sent_count,
            "targets": targets,
            "message": f"Đã bắn thành công {sent_count} gói tin Magic Packet tới {format_mac_colon(raw_mac)} qua UDP port 9 & 7!",
        }
    else:
        return {
            "success": False,
            "mac": mac_address,
            "error": "; ".join(errors) if errors else "Không thể gửi gói tin broadcast",
        }


def load_saved_wol_devices() -> List[Dict[str, Any]]:
    """Đọc danh bạ máy tính đã lưu để bật từ xa."""
    if not os.path.exists(SAVED_WOL_FILE):
        return []
    try:
        with open(SAVED_WOL_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
    except Exception:
        pass
    return []


def save_wol_device(name: str, mac: str, ip: str = "", note: str = "") -> List[Dict[str, Any]]:
    """Lưu hoặc cập nhật một máy tính vào danh bạ WoL."""
    try:
        clean = clean_mac(mac)
        formatted_mac = format_mac_colon(clean)
    except Exception:
        formatted_mac = mac.strip().upper()

    devices = load_saved_wol_devices()
    # Tìm xem đã có MAC này chưa
    found = False
    for d in devices:
        if d.get("mac", "").upper() == formatted_mac:
            d["name"] = name.strip() or d.get("name", "Máy tính")
            if ip:
                d["ip"] = ip.strip()
            if note:
                d["note"] = note.strip()
            found = True
            break

    if not found:
        devices.append({
            "name": name.strip() or f"PC ({formatted_mac[-5:]})",
            "mac": formatted_mac,
            "ip": ip.strip(),
            "note": note.strip(),
        })

    try:
        with open(SAVED_WOL_FILE, "w", encoding="utf-8") as f:
            json.dump(devices, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

    return devices


def delete_saved_wol_device(mac: str) -> List[Dict[str, Any]]:
    """Xóa một máy tính khỏi danh bạ WoL."""
    clean = mac.strip().upper()
    devices = load_saved_wol_devices()
    devices = [d for d in devices if d.get("mac", "").upper() != clean]
    try:
        with open(SAVED_WOL_FILE, "w", encoding="utf-8") as f:
            json.dump(devices, f, ensure_ascii=False, indent=2)
    except Exception:
        pass
    return devices


def get_wol_setup_guide() -> Dict[str, Any]:
    """Tài liệu hướng dẫn thiết lập Wake-on-LAN trên máy đích (Target PC)."""
    return {
        "title": "Hướng dẫn bật tính năng Wake-on-LAN trên máy tính đích",
        "bios_steps": [
            "Khởi động lại máy tính cần bật, nhấn phím Delete hoặc F2 (tuỳ mainboard) để vào BIOS / UEFI.",
            "Tìm mục 'Power Management' hoặc 'Advanced' / 'APM Configuration'.",
            "BẬT (Enabled) các mục: 'Power On By PCI-E/PCI', 'Wake on LAN', hoặc 'Resume by Onboard LAN'.",
            "TẮT (Disabled) chế độ tiết kiệm điện sâu: 'ErP Ready' hoặc 'Deep Sleep' (nếu bật ErP thì card mạng sẽ bị cắt điện hoàn toàn khi tắt máy).",
            "Nhấn F10 để Lưu và Khởi động lại vào Windows.",
        ],
        "windows_steps": [
            "Trên máy tính đích, bấm chuột phải vào nút Start ➔ chọn 'Device Manager' (Quản lý thiết bị).",
            "Mở rộng mục 'Network adapters' (Card mạng) ➔ Nhấp đúp vào card mạng Ethernet (Intel/Realtek).",
            "Chuyển sang tab 'Power Management' (Quản lý nguồn): Tích chọn cả 3 ô 'Allow this device to wake the computer' và 'Only allow a magic packet to wake the computer'.",
            "Chuyển sang tab 'Advanced' (Nâng cao): Đảm bảo các mục 'Wake on Magic Packet' hoặc 'Shutdown Wake Up' được chọn là 'Enabled'.",
            "Lưu ý Windows 10/11: Nếu bấm Shutdown mà máy không bật được, hãy vào 'Control Panel' ➔ 'Power Options' ➔ 'Choose what the power buttons do' ➔ Bấm 'Change settings that are currently unavailable' ➔ TẮT tính năng 'Turn on fast startup' (Khởi động nhanh).",
        ],
    }
