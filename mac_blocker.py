"""
mac_blocker.py - Trợ lý hỗ trợ chặn thiết bị lạ qua bộ lọc địa chỉ MAC (MAC Filtering).
Cung cấp hướng dẫn cấu hình chi tiết theo từng dòng Modem mạng phổ biến tại Việt Nam
(ZTE Viettel/VNPT, Huawei Viettel, TP-Link, Tenda, DrayTek, ASUS...).
"""

from typing import Dict, Any, List

ROUTER_GUIDES: Dict[str, Dict[str, Any]] = {
    "zte": {
        "name": "Modem ZTE (Viettel / VNPT)",
        "menu_path": "Bảo mật (Security) ➔ MAC Filter  (hoặc Network ➔ WLAN ➔ Access Control List)",
        "mode_setting": "Chọn chế độ: Blacklist (hoặc Block / Deny - Chặn thiết bị trong danh sách)",
        "default_ip": "192.168.1.1",
        "default_user": "admin (hoặc user in ở mặt dưới đáy modem)",
        "steps": [
            "Đăng nhập vào trang quản trị modem với tài khoản/mật khẩu in dưới đáy cục modem.",
            "Vào mục 'Security' (Bảo mật) ➔ 'MAC Filter' (hoặc 'Network' ➔ 'WLAN' ➔ 'Access Control List').",
            "BẬT tính năng 'Enable MAC Filter' và chọn Rule là 'Blacklist' (Chặn danh sách này).",
            "Dán địa chỉ MAC thiết bị lạ vào ô MAC Address rồi bấm 'Add' hoặc 'Apply' để hoàn tất.",
        ],
        "warning": "TUYỆT ĐỐI KHÔNG chọn chế độ 'Whitelist' (Cho phép)! Vì nếu chọn Whitelist thì toàn bộ điện thoại, tivi khác trong nhà sẽ bị mất Wi-Fi ngay lập tức!",
    },
    "huawei": {
        "name": "Modem Huawei (Viettel HG8145 / HG8045)",
        "menu_path": "Security ➔ MAC Filter Configuration (hoặc WLAN ➔ WLAN Filtering)",
        "mode_setting": "Filter Mode: Blacklist (Chặn thiết bị)",
        "default_ip": "192.168.1.1",
        "default_user": "admin / mật khẩu dưới tem modem",
        "steps": [
            "Đăng nhập vào modem qua trình duyệt web.",
            "Chọn mục 'Security' trên thanh menu trên cùng ➔ chọn 'MAC Filter Configuration' ở menu bên trái.",
            "Tích chọn 'Enable MAC Filter' ➔ Chọn Filter Mode là 'Blacklist'.",
            "Bấm nút 'New' ➔ Nhập địa chỉ MAC thiết bị lạ ➔ Bấm 'Apply' để chặn.",
        ],
        "warning": "Hãy chắc chắn chọn đúng 'Blacklist' để chỉ chặn riêng thiết bị này.",
    },
    "tp-link": {
        "name": "Router Wi-Fi TP-Link",
        "menu_path": "Advanced (Nâng cao) ➔ Wireless (Không dây) ➔ MAC Filtering (Lọc địa chỉ MAC)",
        "mode_setting": "Filtering Rules: Deny the stations specified by any enabled entries (Từ chối / Chặn)",
        "default_ip": "192.168.0.1 hoặc 192.168.1.1",
        "default_user": "admin / admin",
        "steps": [
            "Đăng nhập trang quản trị TP-Link (tplinkwifi.net hoặc 192.168.1.1).",
            "Vào mục 'Advanced' ➔ 'Wireless' ➔ 'Wireless MAC Filtering' (hoặc 'Security' ➔ 'Access Control').",
            "Bấm 'Enable' ➔ Chọn Filtering Rule là 'Deny the stations specified...' (Chặn).",
            "Bấm 'Add New...' ➔ Dán địa chỉ MAC và bấm 'Save'.",
        ],
        "warning": "Không chọn 'Allow' (Cho phép) vì sẽ làm ngắt Wi-Fi tất cả các thiết bị khác.",
    },
    "general": {
        "name": "Modem / Router Wi-Fi thông thường",
        "menu_path": "Wireless / Wi-Fi ➔ MAC Filter / Access Control (hoặc Security ➔ Firewall)",
        "mode_setting": "Mode: Blacklist / Deny (Chặn)",
        "default_ip": "192.168.1.1",
        "default_user": "admin / in dưới tem modem",
        "steps": [
            "Đăng nhập vào trang quản trị modem bằng tài khoản in dưới đáy thiết bị.",
            "Tìm mục 'Cài đặt Wi-Fi' hoặc 'Bảo mật (Security)' ➔ 'Lọc địa chỉ MAC' (MAC Filter / Access Control).",
            "Bật chức năng lọc và chọn chế độ 'Blacklist' (Danh sách chặn / Từ chối).",
            "Dán địa chỉ MAC cần chặn và bấm 'Lưu' (Apply/Save).",
        ],
        "warning": "Chỉ chọn 'Blacklist' hoặc 'Deny', không chọn 'Whitelist'/'Allow' kẻo chặn nhầm các máy khác trong nhà.",
    },
}


def get_guide_for_router(vendor_name: str) -> Dict[str, Any]:
    """Lấy bài hướng dẫn chặn MAC phù hợp với hãng Router đang dùng."""
    v_lower = (vendor_name or "").lower()
    if "zte" in v_lower:
        return ROUTER_GUIDES["zte"]
    elif "huawei" in v_lower:
        return ROUTER_GUIDES["huawei"]
    elif "tp-link" in v_lower or "tplink" in v_lower:
        return ROUTER_GUIDES["tp-link"]
    return ROUTER_GUIDES["general"]


def format_mac_variants(mac_str: str) -> Dict[str, str]:
    """
    Chuẩn hóa địa chỉ MAC thành các định dạng phổ biến của các dòng modem khác nhau.
    """
    clean = mac_str.strip().replace(":", "").replace("-", "").replace(".", "").upper()
    if len(clean) != 12:
        return {"colon": mac_str, "dash": mac_str, "plain": mac_str}

    # Định dạng AA:BB:CC:DD:EE:FF
    colon = ":".join(clean[i : i + 2] for i in range(0, 12, 2))
    # Định dạng AA-BB-CC-DD-EE-FF
    dash = "-".join(clean[i : i + 2] for i in range(0, 12, 2))
    # Định dạng aabb.ccdd.eeff
    cisco = f"{clean[:4].lower()}.{clean[4:8].lower()}.{clean[8:].lower()}"

    return {
        "colon": colon,
        "dash": dash,
        "lower_colon": colon.lower(),
        "plain": clean,
        "cisco": cisco,
    }
