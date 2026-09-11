"""
export_utils.py - Xuất danh sách thiết bị ra file CSV (chuẩn UTF-8 có BOM mở Excel không lỗi font) và JSON.
"""

import csv
import json
from datetime import datetime
from typing import List, Dict, Any


def export_to_csv(devices: List[Dict[str, Any]], filepath: str) -> bool:
    """
    Xuất danh sách thiết bị ra file CSV với mã hoá UTF-8-SIG (tương thích 100% Microsoft Excel).
    """
    try:
        with open(filepath, mode="w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)
            # Dòng tiêu đề
            writer.writerow([
                "STT",
                "Địa chỉ IP",
                "Địa chỉ MAC",
                "Tên thiết bị (Hostname)",
                "Nhà sản xuất (Hãng)",
                "Mô tả / Loại thiết bị",
                "Phản hồi (ms)",
                "Loại thiết bị đặc biệt",
                "Thời gian quét",
            ])
            scan_time = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

            for idx, d in enumerate(devices, start=1):
                special_tag = []
                if d.get("is_gateway"):
                    special_tag.append("Router Wi-Fi / Gateway")
                if d.get("is_self"):
                    special_tag.append("Máy đang dùng")
                if d.get("is_random_mac"):
                    special_tag.append("MAC ngẫu nhiên (iOS/Android)")

                writer.writerow([
                    idx,
                    d.get("ip", ""),
                    d.get("mac", ""),
                    d.get("name", "—"),
                    d.get("vendor", "Chưa rõ"),
                    d.get("hint", ""),
                    f"{d.get('rtt_ms', 0)} ms",
                    ", ".join(special_tag) if special_tag else "Bình thường",
                    scan_time,
                ])
        return True
    except Exception as e:
        print(f"Lỗi khi xuất CSV: {e}")
        return False


def export_to_json(devices: List[Dict[str, Any]], filepath: str) -> bool:
    """
    Xuất danh sách thiết bị ra file JSON.
    """
    try:
        data = {
            "exported_at": datetime.now().isoformat(),
            "device_count": len(devices),
            "devices": devices,
        }
        with open(filepath, mode="w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        print(f"Lỗi khi xuất JSON: {e}")
        return False
