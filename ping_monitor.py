"""
ping_monitor.py - Bộ giám sát độ trễ và độ ổn định mạng thời gian thực (Real-time Ping Monitor).
Sử dụng Windows Native ICMP API 64-bit (IcmpSendEcho trong icmp.dll).
Đo đồng thời Router nội bộ và Internet để chẩn đoán nguyên nhân gây giật lag.
"""

import ctypes
import math
import socket
import struct
import threading
import time
from collections import deque
from ctypes import wintypes
from typing import Optional, Dict, Any, List, Tuple

# Khởi tạo thư viện ICMP của Windows
_icmp = ctypes.windll.icmp

IcmpCreateFile = _icmp.IcmpCreateFile
IcmpCreateFile.restype = wintypes.HANDLE

IcmpCloseHandle = _icmp.IcmpCloseHandle
IcmpCloseHandle.argtypes = [wintypes.HANDLE]
IcmpCloseHandle.restype = wintypes.BOOL

IcmpSendEcho = _icmp.IcmpSendEcho
IcmpSendEcho.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.WORD,
    wintypes.LPVOID,
    wintypes.LPVOID,
    wintypes.DWORD,
    wintypes.DWORD,
]
IcmpSendEcho.restype = wintypes.DWORD


class IP_OPTION_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("Ttl", ctypes.c_ubyte),
        ("Tos", ctypes.c_ubyte),
        ("Flags", ctypes.c_ubyte),
        ("OptionsSize", ctypes.c_ubyte),
        ("OptionsData", ctypes.c_void_p),
    ]


class ICMP_ECHO_REPLY(ctypes.Structure):
    _fields_ = [
        ("Address", wintypes.DWORD),
        ("Status", wintypes.DWORD),
        ("RoundTripTime", wintypes.DWORD),
        ("DataSize", wintypes.WORD),
        ("Reserved", wintypes.WORD),
        ("Data", ctypes.c_void_p),
        ("Options", IP_OPTION_INFORMATION),
    ]


def native_ping(ip_str: str, timeout_ms: int = 1000) -> Optional[int]:
    """
    Gửi gói ICMP Echo Request trực tiếp bằng Windows Native API.
    Trả về RoundTripTime (ms) nếu thành công, None nếu timeout hoặc rớt gói.
    """
    handle = IcmpCreateFile()
    if not handle or handle == wintypes.HANDLE(-1).value:
        return None
    try:
        dest_addr = struct.unpack("<I", socket.inet_aton(ip_str))[0]
        data = b"wifi_ping_probe"
        reply_size = ctypes.sizeof(ICMP_ECHO_REPLY) + len(data) + 16
        reply_buf = ctypes.create_string_buffer(reply_size)
        res = IcmpSendEcho(
            handle, dest_addr, data, len(data), None, reply_buf, reply_size, timeout_ms
        )
        if res != 0:
            reply = ICMP_ECHO_REPLY.from_buffer_copy(
                reply_buf[: ctypes.sizeof(ICMP_ECHO_REPLY)]
            )
            if reply.Status == 0:
                return reply.RoundTripTime
        return None
    except Exception:
        return None
    finally:
        IcmpCloseHandle(handle)


def tcp_ping(host: str, port: int = 53, timeout_ms: int = 800) -> Optional[int]:
    """
    Đo độ trễ bằng phương pháp bắt tay TCP (TCP SYN/ACK Handshake).
    Vượt qua 100% tường lửa chặn gói tin ICMP của Modem mạng và Nhà mạng.
    """
    t0 = time.perf_counter()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout_ms / 1000.0)
    try:
        s.connect((host, port))
        latency = int(round((time.perf_counter() - t0) * 1000))
        return max(latency, 1)
    except Exception:
        return None
    finally:
        try:
            s.close()
        except Exception:
            pass


def smart_ping(host: str, timeout_ms: int = 800) -> Tuple[Optional[int], str]:
    """
    Đo ping thông minh (Hybrid Smart Ping):
    1. Ưu tiên thử ICMP ping chuẩn.
    2. Nếu ICMP bị timeout (do modem hoặc nhà mạng Viettel/VNPT bật tường lửa chặn ping),
       tự động chuyển sang TCP Handshake Ping (cổng 53 DNS hoặc 80/443 Web).
    Trả về: (latency_ms, method_used)
    """
    # 1. Thử ICMP trước (nhanh 300ms)
    try:
        t_icmp = native_ping(host, timeout_ms=min(timeout_ms, 350))
        if t_icmp is not None:
            return t_icmp, "ICMP"
    except Exception:
        pass

    # 2. Nếu ICMP thất bại, thử TCP Ping qua các cổng tiêu chuẩn (timeout nhanh 300ms)
    candidate_ports = [53, 80, 443]
    for port in candidate_ports:
        t_tcp = tcp_ping(host, port=port, timeout_ms=min(timeout_ms, 300))
        if t_tcp is not None:
            return t_tcp, f"TCP:{port}"

    return None, "Timeout"


class PingMonitor:
    """Bộ điều khiển giám sát độ trễ kép (Router và Internet) với bộ đệm lịch sử."""

    MAX_POINTS = 50  # Số điểm vẽ biểu đồ sóng

    def __init__(self, router_ip: str = "192.168.1.1", internet_ip: str = "8.8.8.8"):
        self.router_ip = router_ip
        self.internet_ip = internet_ip
        self.is_running = False
        self.is_paused = False
        self.worker_thread: Optional[threading.Thread] = None

        # Bộ đệm lưu trữ lịch sử các giá trị ping gần nhất (ms)
        self.history_router: deque = deque(maxlen=self.MAX_POINTS)
        self.history_internet: deque = deque(maxlen=self.MAX_POINTS)

        # Bộ đệm tính toán thống kê (100 mẫu gần nhất)
        self.stat_samples_router: deque = deque(maxlen=100)
        self.stat_samples_internet: deque = deque(maxlen=100)

        # Callbacks cập nhật UI
        self.on_update_callback = None

    def start(self, on_update=None):
        """Khởi động luồng đo ping định kỳ."""
        if self.is_running:
            return
        self.is_running = True
        self.is_paused = False
        self.on_update_callback = on_update
        self.worker_thread = threading.Thread(target=self._run_loop, daemon=True)
        self.worker_thread.start()

    def pause(self):
        """Tạm dừng đo."""
        self.is_paused = True

    def resume(self):
        """Tiếp tục đo."""
        self.is_paused = False

    def stop(self):
        """Dừng hẳn tiến trình đo."""
        self.is_running = False

    def reset_data(self):
        """Xóa trắng dữ liệu lịch sử để đo lại từ đầu."""
        self.history_router.clear()
        self.history_internet.clear()
        self.stat_samples_router.clear()
        self.stat_samples_internet.clear()

    def set_targets(self, router_ip: Optional[str] = None, internet_ip: Optional[str] = None):
        """Cập nhật địa chỉ IP mục tiêu."""
        if router_ip:
            self.router_ip = router_ip
        if internet_ip:
            self.internet_ip = internet_ip

    def _run_loop(self):
        while self.is_running:
            if not self.is_paused:
                t_router, r_meth = smart_ping(self.router_ip, timeout_ms=800)
                t_inet, i_meth = smart_ping(self.internet_ip, timeout_ms=800)
                self.last_router_method = r_meth
                self.last_internet_method = i_meth

                self.history_router.append(t_router)
                self.history_internet.append(t_inet)

                self.stat_samples_router.append(t_router)
                self.stat_samples_internet.append(t_inet)

                stats = self.get_current_stats()
                diagnosis = self.diagnose(stats)

                if self.on_update_callback:
                    try:
                        self.on_update_callback(stats, diagnosis)
                    except Exception:
                        pass

            time.sleep(1.0)

    def get_current_stats(self) -> Dict[str, Any]:
        """Tính toán các chỉ số thống kê mạng."""
        def compute(samples_deque, method_name: str = "ICMP"):
            if not samples_deque:
                return {"cur": 0, "min": 0, "max": 0, "avg": 0, "loss_rate": 0, "jitter": 0, "method": method_name}

            valid = [s for s in samples_deque if s is not None]
            total = len(samples_deque)
            lost = total - len(valid)
            loss_rate = round((lost / total) * 100, 1)

            if not valid:
                return {"cur": None, "min": 0, "max": 0, "avg": 0, "loss_rate": loss_rate, "jitter": 0, "method": method_name}

            cur = samples_deque[-1]
            min_val = min(valid)
            max_val = max(valid)
            avg_val = round(sum(valid) / len(valid), 1)

            # Tính Jitter (độ lệch biến thiên trung bình giữa các lần ping liên tiếp)
            jitter = 0
            if len(valid) > 1:
                diffs = [abs(valid[i] - valid[i - 1]) for i in range(1, len(valid))]
                jitter = round(sum(diffs) / len(diffs), 1)

            return {
                "cur": cur,
                "min": min_val,
                "max": max_val,
                "avg": avg_val,
                "loss_rate": loss_rate,
                "jitter": jitter,
                "method": method_name,
            }

        r_meth = getattr(self, "last_router_method", "ICMP")
        i_meth = getattr(self, "last_internet_method", "ICMP")

        return {
            "router_ip": self.router_ip,
            "internet_ip": self.internet_ip,
            "router": compute(self.stat_samples_router, r_meth),
            "internet": compute(self.stat_samples_internet, i_meth),
            "history_router": list(self.history_router),
            "history_internet": list(self.history_internet),
        }

    def diagnose(self, stats: Dict[str, Any]) -> Dict[str, Any]:
        """
        Thuật toán chẩn đoán thông minh:
        Phân biệt mạng chậm do sóng Wi-Fi hay do nhà mạng cáp quang.
        """
        r_stats = stats["router"]
        i_stats = stats["internet"]

        r_cur = r_stats["cur"]
        i_cur = i_stats["cur"]
        r_loss = r_stats["loss_rate"]
        i_loss = i_stats["loss_rate"]

        # Trường hợp 1: Mất mạng hoàn toàn
        if r_cur is None and i_cur is None:
            return {
                "level": "danger",
                "title": "MẤT KẾT NỐI MẠNG HOÀN TOÀN",
                "badge": "⚫ Mất Mạng",
                "color": "#EF4444",
                "desc": "Không thể kết nối tới cả Router Wi-Fi lẫn Internet. Vui lòng kiểm tra lại cáp mạng hoặc kết nối Wi-Fi trên máy tính của bạn.",
            }

        # Trường hợp 2: Wi-Fi yếu / Nhiễu sóng / Quá tải
        if r_loss > 10 or (r_cur is not None and r_cur > 45):
            return {
                "level": "warning",
                "title": "NGUYÊN NHÂN: SÓNG WI-FI YẾU HOẶC NHIỄU SÓNG",
                "badge": "🟡 Sóng Wi-Fi Kém",
                "color": "#F59E0B",
                "desc": f"Độ trễ tới Router nội bộ quá cao ({r_cur or 'Timeout'} ms, rớt {r_loss}% gói). Do máy ở xa cục phát, có vật cản tường dày hoặc cục Wi-Fi đang quá tải.",
            }

        # Trường hợp 3: Kết nối Wi-Fi tốt nhưng cáp quang nhà mạng có vấn đề
        if (r_cur is not None and r_cur <= 10) and (i_cur is None or i_loss > 15 or i_cur > 120):
            return {
                "level": "warning_isp",
                "title": "NGUYÊN NHÂN: ĐƯỜNG TRUYỀN NHÀ MẠNG CÁP QUANG BỊ NGHẼN",
                "badge": "🔴 Sự Cố Nhà Mạng",
                "color": "#EC4899",
                "desc": f"Sóng Wi-Fi tới Router rất tốt ({r_cur} ms) nhưng ping Internet bị lag ({i_cur or 'Timeout'} ms, rớt {i_loss}% gói). Sự cố do nhà cung cấp mạng (Viettel/FPT/VNPT) hoặc nghẽn cáp biển.",
            }

        # Trường hợp 4: Mạng hoạt động tuyệt vời
        if (r_cur is not None and r_cur <= 12) and (i_cur is not None and i_cur <= 90 and i_loss == 0):
            return {
                "level": "success",
                "title": "MẠNG HOẠT ĐỘNG HOÀN HẢO",
                "badge": "🟢 Cực Kỳ Ổn Định",
                "color": "#10B981",
                "desc": f"Sóng Wi-Fi mạnh ({r_cur} ms) và đường truyền Internet thông suốt ({i_cur} ms, 0% rớt gói). Đạt chuẩn xem video 4K và chơi game mượt mà.",
            }

        # Trường hợp 5: Mạng bình thường
        return {
            "level": "normal",
            "title": "KẾT NỐI MẠNG ỔN ĐỊNH",
            "badge": "🔵 Bình Thường",
            "color": "#3B82F6",
            "desc": f"Độ trễ Router: {r_cur} ms | Internet: {i_cur} ms. Mạng đáp ứng tốt các nhu cầu học tập, làm việc và giải trí hàng ngày.",
        }
