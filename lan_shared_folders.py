"""
lan_shared_folders.py - Trình Dò Ổ Đĩa Chia Sẻ Mạng LAN & Thư Mục SMB (SMB Shared Folders & NAS Explorer).
Sử dụng Windows C-API Native (NetShareEnum trong netapi32.dll) và đa luồng hiệu năng cao:
- Dò tìm các máy tính Windows, máy chủ, ổ đĩa mạng NAS, router mở cổng SMB (445 / 139).
- Trích xuất danh sách thư mục chia sẻ công khai (Public, Users, Data, Movies...).
- Phân loại rủi ro an ninh: Mở công khai không cần mật khẩu vs Có bảo vệ mật khẩu.
- 1-Click mở thẳng thư mục trong Windows File Explorer (explorer.exe \\\\IP\\Share).
- Tự kiểm tra máy tính cá nhân (My PC) để phát hiện và cảnh báo thư mục bị share lộ dữ liệu.
- Mở nhanh trình quản lý chia sẻ file của Windows (fsmgmt.msc).
"""

import ctypes
from ctypes import wintypes
import socket
import subprocess
import threading
import time
from typing import Dict, Any, List, Optional, Callable
import customtkinter as ctk

# Nạp Win32 NetAPI32 DLL
try:
    _netapi32 = ctypes.windll.netapi32
except Exception:
    _netapi32 = None

# Định nghĩa struct SHARE_INFO_1 (Level 1) cho NetShareEnum
class SHARE_INFO_1(ctypes.Structure):
    _fields_ = [
        ("shi1_netname", wintypes.LPWSTR),
        ("shi1_type", wintypes.DWORD),
        ("shi1_remark", wintypes.LPWSTR),
    ]

# Định nghĩa struct SHARE_INFO_2 (Level 2) cho máy cục bộ
class SHARE_INFO_2(ctypes.Structure):
    _fields_ = [
        ("shi2_netname", wintypes.LPWSTR),
        ("shi2_type", wintypes.DWORD),
        ("shi2_remark", wintypes.LPWSTR),
        ("shi2_permissions", wintypes.DWORD),
        ("shi2_max_uses", wintypes.DWORD),
        ("shi2_current_uses", wintypes.DWORD),
        ("shi2_path", wintypes.LPWSTR),
        ("shi2_passwd", wintypes.LPWSTR),
    ]

# Các hằng số loại Share theo Microsoft Win32
STYPE_DISKTREE = 0x00000000    # Ổ đĩa / Thư mục chia sẻ thường
STYPE_PRINTQ   = 0x00000001    # Hàng đợi máy in
STYPE_DEVICE   = 0x00000002    # Thiết bị giao tiếp
STYPE_IPC      = 0x00000003    # IPC Interprocess
STYPE_SPECIAL  = 0x80000000    # Share ẩn hệ thống quản trị (C$, ADMIN$...)
STYPE_TEMPORARY= 0x40000000


class SMBShareScanner:
    """Bộ xử lý dò tìm và trích xuất thư mục chia sẻ SMB trong mạng LAN."""

    def __init__(self):
        self.should_stop = False
        self.is_scanning = False

    def stop(self):
        self.should_stop = True

    @staticmethod
    def check_smb_port(ip: str, timeout: float = 0.35) -> bool:
        """Kiểm tra nhanh cổng TCP 445 (SMB) hoặc 139 (NetBIOS Session)."""
        for port in (445, 139):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            try:
                s.connect((ip, port))
                s.close()
                return True
            except Exception:
                try:
                    s.close()
                except Exception:
                    pass
        return False

    @staticmethod
    def get_local_shares() -> List[Dict[str, Any]]:
        """
        Lấy toàn bộ danh sách thư mục chia sẻ trên máy tính hiện tại (This PC).
        Sử dụng Win32 NetShareEnum Level 2 trích xuất được cả đường dẫn vật lý ổ đĩa.
        """
        shares = []
        if not _netapi32:
            return shares

        try:
            bufptr = ctypes.c_void_p()
            entriesread = wintypes.DWORD()
            totalentries = wintypes.DWORD()
            resume_handle = wintypes.DWORD(0)

            res = _netapi32.NetShareEnum(
                None,
                2,
                ctypes.byref(bufptr),
                -1,
                ctypes.byref(entriesread),
                ctypes.byref(totalentries),
                ctypes.byref(resume_handle),
            )

            if res == 0 and bufptr.value:
                items = ctypes.cast(bufptr, ctypes.POINTER(SHARE_INFO_2))
                for i in range(entriesread.value):
                    item = items[i]
                    netname = item.shi2_netname or ""
                    path = item.shi2_path or ""
                    remark = item.shi2_remark or ""
                    stype = item.shi2_type

                    is_special = bool(stype & STYPE_SPECIAL) or netname.endswith("$")
                    is_disk = (stype & 0x0000FFFF) == STYPE_DISKTREE

                    shares.append({
                        "name": netname,
                        "path": path,
                        "remark": remark,
                        "type_code": stype,
                        "is_disk": is_disk,
                        "is_special": is_special,
                        "unc_path": rf"\\127.0.0.1\{netname}",
                        "is_public_risk": is_disk and not is_special,
                    })
                _netapi32.NetApiBufferFree(bufptr)
        except Exception:
            pass

        return shares

    @staticmethod
    def enumerate_remote_shares(ip: str, hostname: str = "") -> Dict[str, Any]:
        """
        Dò tìm danh sách thư mục chia sẻ trên một thiết bị từ xa qua IP.
        Phân biệt rõ ràng:
        - Result 0: Thành công (Tìm thấy danh sách thư mục chia sẻ công khai).
        - Result 5: Cần mật khẩu (Access Denied - Thiết bị bật SMB nhưng yêu cầu xác thực bảo mật).
        - Result khác: Không hỗ trợ hoặc tường lửa chặn.
        """
        result = {
            "ip": ip,
            "hostname": hostname or ip,
            "smb_open": True,
            "has_shares": False,
            "requires_auth": False,
            "shares": [],
            "error_msg": "",
        }

        if not _netapi32:
            result["error_msg"] = "NetAPI32 không khả dụng"
            return result

        try:
            bufptr = ctypes.c_void_p()
            entriesread = wintypes.DWORD()
            totalentries = wintypes.DWORD()
            resume_handle = wintypes.DWORD(0)

            server_target = rf"\\{ip}"
            res = _netapi32.NetShareEnum(
                server_target,
                1,
                ctypes.byref(bufptr),
                -1,
                ctypes.byref(entriesread),
                ctypes.byref(totalentries),
                ctypes.byref(resume_handle),
            )

            if res == 0 and bufptr.value:
                items = ctypes.cast(bufptr, ctypes.POINTER(SHARE_INFO_1))
                for i in range(entriesread.value):
                    item = items[i]
                    netname = item.shi1_netname or ""
                    remark = item.shi1_remark or ""
                    stype = item.shi1_type

                    is_special = bool(stype & STYPE_SPECIAL) or netname.endswith("$")
                    is_disk = (stype & 0x0000FFFF) == STYPE_DISKTREE

                    # Bỏ qua các share quản trị ẩn của Windows trừ khi có thư mục share thường
                    result["shares"].append({
                        "name": netname,
                        "remark": remark,
                        "is_disk": is_disk,
                        "is_special": is_special,
                        "unc_path": rf"\\{ip}\{netname}",
                        "is_public_risk": is_disk and not is_special,
                    })

                _netapi32.NetApiBufferFree(bufptr)
                result["has_shares"] = len(result["shares"]) > 0

            elif res == 5:
                # 5 = ERROR_ACCESS_DENIED: Máy này bật SMB nhưng yêu cầu mật khẩu
                result["requires_auth"] = True
                result["error_msg"] = "Cần tài khoản & mật khẩu (Được bảo vệ)"
            elif res == 53:
                result["error_msg"] = "Không tìm thấy đường dẫn mạng (Host từ chối RPC)"
            else:
                result["error_msg"] = f"Mã lỗi Windows RPC: {res}"

        except Exception as e:
            result["error_msg"] = str(e)

        # Thử nghiệm dự phòng bằng `net view` nếu NetShareEnum gặp mã lạ
        if not result["shares"] and not result["requires_auth"]:
            try:
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                out = subprocess.check_output(
                    f"net view \\\\{ip}",
                    shell=True,
                    text=True,
                    stderr=subprocess.STDOUT,
                    timeout=1.8,
                    startupinfo=startupinfo,
                    errors="replace",
                )
                if "Access is denied" in out or "System error 5" in out:
                    result["requires_auth"] = True
                else:
                    lines = out.splitlines()
                    table_start = False
                    for line in lines:
                        line_s = line.strip()
                        if "---" in line_s:
                            table_start = True
                            continue
                        if table_start and line_s:
                            if "The command completed successfully" in line_s:
                                break
                            parts = line_s.split()
                            if parts:
                                s_name = parts[0]
                                s_type = parts[1] if len(parts) > 1 else "Disk"
                                is_disk = "disk" in s_type.lower()
                                is_spec = s_name.endswith("$")
                                result["shares"].append({
                                    "name": s_name,
                                    "remark": " ".join(parts[2:]) if len(parts) > 2 else "",
                                    "is_disk": is_disk,
                                    "is_special": is_spec,
                                    "unc_path": rf"\\{ip}\{s_name}",
                                    "is_public_risk": is_disk and not is_spec,
                                })
                    if result["shares"]:
                        result["has_shares"] = True
            except Exception:
                pass

        return result


def open_in_explorer(unc_path: str):
    """Mở đường dẫn UNC trong Windows File Explorer."""
    try:
        subprocess.Popen(["explorer.exe", unc_path])
    except Exception as e:
        print(f"Lỗi mở Explorer: {e}")


def copy_text_to_clipboard(text: str, root_widget=None):
    """Sao chép chuỗi vào Clipboard Windows."""
    try:
        if root_widget:
            root_widget.clipboard_clear()
            root_widget.clipboard_append(text)
            root_widget.update()
        else:
            subprocess.run(["clip"], input=text.encode("utf-8"), check=True, creationflags=subprocess.CREATE_NO_WINDOW)
    except Exception:
        pass


def open_windows_fsmgmt():
    """Khởi chạy trình quản lý chia sẻ file chuẩn của Windows (fsmgmt.msc)."""
    try:
        subprocess.Popen("fsmgmt.msc", shell=True)
    except Exception as e:
        print(f"Lỗi mở fsmgmt.msc: {e}")


class LanSharedFoldersView(ctk.CTkFrame):
    """Giao diện Khám phá & Dò tìm Ổ Đĩa Chia Sẻ Mạng LAN (SMB Explorer View)."""

    def __init__(
        self,
        master,
        get_active_devices_fn: Optional[Callable[[], List[Dict[str, Any]]]] = None,
        on_open_port_scan: Optional[Callable[[Dict[str, Any]], None]] = None,
        **kwargs,
    ):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.get_active_devices_fn = get_active_devices_fn
        self.on_open_port_scan = on_open_port_scan
        self.scanner = SMBShareScanner()

        # Dữ liệu kết quả quét
        self.discovered_hosts: List[Dict[str, Any]] = []
        self.local_pc_shares: List[Dict[str, Any]] = []

        self._build_ui()

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        # --- 1. THANH TÓM TẮT CHỈ SỐ KPI ---
        kpi_frame = ctk.CTkFrame(self, fg_color=("#E5E7EB", "#1F2937"), corner_radius=10)
        kpi_frame.grid(row=0, column=0, padx=5, pady=(5, 8), sticky="ew")
        kpi_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self.kpi_smb_hosts = self._create_kpi_card(kpi_frame, 0, "💻 Máy Mở SMB", "0 máy", "#38BDF8")
        self.kpi_total_shares = self._create_kpi_card(kpi_frame, 1, "📁 Thư Mục Phát Hiện", "0 folder", "#60A5FA")
        self.kpi_public_risk = self._create_kpi_card(kpi_frame, 2, "🚨 Mở Không Cần Pass", "0 folder", "#F87171")
        self.kpi_protected = self._create_kpi_card(kpi_frame, 3, "🔒 Cần Mật Khẩu", "0 máy", "#34D399")

        # --- 2. THANH CÔNG CỤ TOOLBAR ---
        toolbar = ctk.CTkFrame(self, fg_color=("#E5E7EB", "#1F2937"), corner_radius=8, height=48)
        toolbar.grid(row=1, column=0, padx=5, pady=(0, 8), sticky="ew")

        # Nút Quét Dò Tìm Toàn Mạng
        self.btn_scan = ctk.CTkButton(
            toolbar,
            text="🔍 DÒ TÌM Ổ CHIA SẺ TRONG MẠNG",
            command=self.start_scan,
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#0284C7",
            hover_color="#0369A1",
            height=34,
        )
        self.btn_scan.pack(side="left", padx=10, pady=7)

        # Nút Soi Máy Này (My PC Shares)
        btn_my_pc = ctk.CTkButton(
            toolbar,
            text="💻 Soi Thư Mục Máy Này (This PC)",
            command=self.inspect_local_pc,
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#059669",
            hover_color="#047857",
            height=34,
        )
        btn_my_pc.pack(side="left", padx=6, pady=7)

        # Nút Mở fsmgmt.msc (Windows Shared Folders Console)
        btn_fsmgmt = ctk.CTkButton(
            toolbar,
            text="📁 Quản Lý File Share (fsmgmt.msc)",
            command=open_windows_fsmgmt,
            font=ctk.CTkFont(size=12),
            fg_color="#4B5563",
            hover_color="#374151",
            height=34,
        )
        btn_fsmgmt.pack(side="left", padx=6, pady=7)

        # Nhãn trạng thái & Thanh tiến trình
        self.lbl_status = ctk.CTkLabel(
            toolbar,
            text="Sẵn sàng dò tìm các thư mục chia sẻ công khai trong mạng LAN...",
            font=ctk.CTkFont(size=12),
            text_color=("#4B5563", "#9CA3AF"),
        )
        self.lbl_status.pack(side="left", padx=12, pady=7)

        self.progress_bar = ctk.CTkProgressBar(toolbar, width=140, height=8)
        self.progress_bar.set(0.0)
        self.progress_bar.pack(side="right", padx=12, pady=7)

        # --- 3. KHU VỰC DANH SÁCH THẺ (SCROLLABLE FRAME) ---
        self.cards_container = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self.cards_container.grid(row=2, column=0, padx=5, pady=0, sticky="nsew")
        self.cards_container.grid_columnconfigure(0, weight=1)

        # Hiển thị màn hình chờ ban đầu
        self._show_empty_placeholder()

        # --- 4. BIỂU NGỮ CẢNH BÁO AN NINH (BOTTOM BANNER) ---
        footer_banner = ctk.CTkFrame(self, fg_color=("#FEF3C7", "#1E293B"), corner_radius=8, height=36)
        footer_banner.grid(row=3, column=0, padx=5, pady=(8, 4), sticky="ew")

        lbl_tip = ctk.CTkLabel(
            footer_banner,
            text="💡 CẢNH BÁO AN NINH: Các thư mục hiển thị [🚨 MỞ CÔNG KHAI] cho phép bất kỳ ai cùng bắt Wi-Fi xem & tải tài liệu. Nếu là máy của bạn, hãy tắt chia sẻ hoặc đặt mật khẩu!",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=("#92400E", "#FBBF24"),
        )
        lbl_tip.pack(side="left", padx=12, pady=6)

    def _create_kpi_card(self, parent, col: int, title: str, value: str, color: str):
        card = ctk.CTkFrame(parent, fg_color=("#F3F4F6", "#111827"), corner_radius=8)
        card.grid(row=0, column=col, padx=6, pady=6, sticky="ew")

        lbl_t = ctk.CTkLabel(card, text=title, font=ctk.CTkFont(size=11), text_color=("#6B7280", "#9CA3AF"))
        lbl_t.pack(anchor="w", padx=10, pady=(6, 0))

        lbl_v = ctk.CTkLabel(card, text=value, font=ctk.CTkFont(size=15, weight="bold"), text_color=color)
        lbl_v.pack(anchor="w", padx=10, pady=(0, 6))
        return lbl_v

    def _show_empty_placeholder(self):
        """Hiển thị giao diện hướng dẫn ban đầu."""
        for w in self.cards_container.winfo_children():
            w.destroy()

        box = ctk.CTkFrame(self.cards_container, fg_color=("#E5E7EB", "#1E293B"), corner_radius=12)
        box.pack(padx=20, pady=30, fill="x")

        lbl_ico = ctk.CTkLabel(box, text="📂", font=ctk.CTkFont(size=42))
        lbl_ico.pack(pady=(20, 5))

        lbl_h = ctk.CTkLabel(
            box,
            text="Khám Phá Thư Mục Chia Sẻ Mạng LAN & Ổ Đĩa SMB",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=("#111827", "#F9FAFB"),
        )
        lbl_h.pack(pady=(0, 6))

        lbl_d = ctk.CTkLabel(
            box,
            text="Dò tìm các máy tính Windows, NAS, máy chủ và Router đang chia sẻ dữ liệu qua giao thức SMB (Cổng 445/139).\n"
                 "• Phát hiện các thư mục bỏ quên không đặt mật khẩu (Users, Public, Media...).\n"
                 "• 1-Click mở thẳng bằng Windows File Explorer hoặc sao chép đường dẫn UNC.\n"
                 "• Soi xem máy tính cá nhân của bạn có đang bị rò rỉ tài liệu ra mạng Wi-Fi công cộng hay không.",
            font=ctk.CTkFont(size=12),
            text_color=("#4B5563", "#9CA3AF"),
            justify="center",
        )
        lbl_d.pack(pady=(0, 20))

    def inspect_local_pc(self):
        """Soi nhanh các thư mục chia sẻ trên chính máy tính của bạn (This PC)."""
        self.lbl_status.configure(text="Đang phân tích các thư mục chia sẻ trên máy tính của bạn...", text_color="#38BDF8")
        shares = self.scanner.get_local_shares()
        self.local_pc_shares = shares

        # Tạo đối tượng giả lập cho máy tính cá nhân
        hostname = socket.gethostname()
        local_host = {
            "ip": "127.0.0.1 (Máy Này)",
            "hostname": f"Máy tính của bạn ({hostname})",
            "vendor": "Thiết bị hiện tại",
            "smb_open": True,
            "has_shares": len(shares) > 0,
            "requires_auth": False,
            "shares": shares,
            "is_self": True,
        }

        # Cập nhật hiển thị lên đầu
        filtered = [h for h in self.discovered_hosts if not h.get("is_self")]
        self.discovered_hosts = [local_host] + filtered
        self._refresh_ui_cards()

        public_count = sum(1 for s in shares if s.get("is_public_risk"))
        if public_count > 0:
            self.lbl_status.configure(
                text=f"⚠️ CẢNH BÁO: Máy bạn đang chia sẻ {public_count} thư mục công khai ra ngoài mạng LAN!",
                text_color="#F87171",
            )
        else:
            self.lbl_status.configure(
                text="✅ An toàn: Máy bạn chỉ có các share quản trị ẩn của Windows (C$, ADMIN$), không chia sẻ thư mục công khai.",
                text_color="#34D399",
            )

    def start_scan(self):
        """Khởi động quét dò tìm toàn mạng LAN trong luồng nền."""
        if self.scanner.is_scanning:
            return

        devices = []
        if self.get_active_devices_fn:
            devices = self.get_active_devices_fn()

        if not devices:
            self.lbl_status.configure(
                text="Chưa có danh sách thiết bị! Hãy bấm 'Quét mạng' ở Tab 1 trước hoặc đợi vài giây.",
                text_color="#F87171",
            )
            return

        self.btn_scan.configure(state="disabled", text="⏳ ĐANG DÒ TÌM SMB...")
        self.progress_bar.set(0.0)
        self.lbl_status.configure(text=f"Đang kiểm tra cổng SMB 445 trên {len(devices)} thiết bị...", text_color="#38BDF8")

        for w in self.cards_container.winfo_children():
            w.destroy()

        self.discovered_hosts.clear()
        threading.Thread(target=self._scan_worker, args=(devices,), daemon=True).start()

    def _scan_worker(self, devices: List[Dict[str, Any]]):
        self.scanner.is_scanning = True
        self.scanner.should_stop = False

        total = len(devices)
        processed = 0

        # Bước 1: Dò tìm máy mở cổng 445/139
        smb_candidates = []
        for dev in devices:
            if self.scanner.should_stop:
                break
            ip = dev.get("ip")
            if not ip:
                continue

            if self.scanner.check_smb_port(ip):
                smb_candidates.append(dev)

            processed += 1
            progress_val = (processed / total) * 0.5
            self.after(0, lambda p=progress_val, c=processed, t=total: self._update_scan_progress(p, f"Đang dò cổng SMB: {c}/{t} thiết bị..."))

        # Bước 2: Khám phá thư mục chia sẻ trên các máy có cổng SMB
        cand_total = len(smb_candidates)
        for idx, dev in enumerate(smb_candidates):
            if self.scanner.should_stop:
                break
            ip = dev.get("ip")
            hostname = dev.get("name", "")
            vendor = dev.get("vendor", "")
            is_self = dev.get("is_self", False)

            if is_self:
                local_shares = self.scanner.get_local_shares()
                host_info = {
                    "ip": ip,
                    "hostname": f"Máy Này ({hostname})",
                    "vendor": vendor,
                    "smb_open": True,
                    "has_shares": len(local_shares) > 0,
                    "requires_auth": False,
                    "shares": local_shares,
                    "is_self": True,
                }
            else:
                host_info = self.scanner.enumerate_remote_shares(ip, hostname)
                host_info["vendor"] = vendor
                host_info["is_self"] = False

            self.discovered_hosts.append(host_info)

            progress_val = 0.5 + ((idx + 1) / max(cand_total, 1)) * 0.5
            self.after(0, lambda p=progress_val, cur=idx + 1, tot=cand_total: self._update_scan_progress(p, f"Đang trích xuất thư mục share: {cur}/{tot} máy..."))
            self.after(0, self._refresh_ui_cards)

        self.scanner.is_scanning = False
        self.after(0, self._on_scan_finished)

    def _update_scan_progress(self, progress: float, msg: str):
        self.progress_bar.set(progress)
        self.lbl_status.configure(text=msg, text_color="#38BDF8")

    def _on_scan_finished(self):
        self.btn_scan.configure(state="normal", text="🔍 DÒ TÌM Ổ CHIA SẺ TRONG MẠNG")
        self.progress_bar.set(1.0)

        total_hosts = len(self.discovered_hosts)
        public_shares = sum(
            sum(1 for s in h.get("shares", []) if s.get("is_public_risk"))
            for h in self.discovered_hosts
        )

        if total_hosts == 0:
            self.lbl_status.configure(
                text="Quét xong: Không phát hiện máy tính nào đang mở dịch vụ chia sẻ SMB.",
                text_color=("#4B5563", "#9CA3AF"),
            )
            self._show_empty_placeholder()
        else:
            msg = f"Hoàn tất: Tìm thấy {total_hosts} máy mở SMB."
            if public_shares > 0:
                msg += f" ⚠️ Cảnh báo có {public_shares} thư mục chia sẻ công khai không có mật khẩu!"
                self.lbl_status.configure(text=msg, text_color="#F87171")
            else:
                msg += " Tất cả đều được bảo vệ bằng mật khẩu an toàn."
                self.lbl_status.configure(text=msg, text_color="#34D399")

        self._refresh_ui_cards()

    def _refresh_ui_cards(self):
        """Vẽ lại toàn bộ danh sách thẻ thiết bị và cập nhật số liệu KPI."""
        # 1. Tính toán KPI
        total_smb_hosts = len(self.discovered_hosts)
        total_shares_count = 0
        total_public_risk = 0
        total_protected_hosts = 0

        for h in self.discovered_hosts:
            if h.get("requires_auth"):
                total_protected_hosts += 1
            shares = h.get("shares", [])
            for s in shares:
                if s.get("is_disk") and not s.get("is_special"):
                    total_shares_count += 1
                    if s.get("is_public_risk"):
                        total_public_risk += 1

        self.kpi_smb_hosts.configure(text=f"{total_smb_hosts} máy")
        self.kpi_total_shares.configure(text=f"{total_shares_count} folder")
        self.kpi_public_risk.configure(text=f"{total_public_risk} folder")
        self.kpi_protected.configure(text=f"{total_protected_hosts} máy")

        # 2. Xóa widget cũ và vẽ lại
        for w in self.cards_container.winfo_children():
            w.destroy()

        if not self.discovered_hosts:
            self._show_empty_placeholder()
            return

        for host in self.discovered_hosts:
            self._render_host_card(host)

    def _render_host_card(self, host: Dict[str, Any]):
        """Vẽ thẻ hiển thị cho 1 máy tính/thiết bị có mở SMB."""
        ip = host.get("ip", "")
        hostname = host.get("hostname", ip)
        vendor = host.get("vendor", "Chưa rõ")
        is_self = host.get("is_self", False)
        requires_auth = host.get("requires_auth", False)
        shares = host.get("shares", [])

        # Phân loại màu sắc thẻ
        has_public_share = any(s.get("is_public_risk") for s in shares)
        if has_public_share:
            border_color = "#EF4444"
            badge_text = "🚨 CÓ THƯ MỤC MỞ CÔNG KHAI (KHÔNG MẬT KHẨU)"
            badge_color = ("#FEE2E2", "#7F1D1D")
            badge_text_color = ("#991B1B", "#FCA5A5")
        elif requires_auth:
            border_color = "#10B981"
            badge_text = "🔒 BẢO VỆ MẬT KHẨU (CẦN ĐĂNG NHẬP)"
            badge_color = ("#D1FAE5", "#064E3B")
            badge_text_color = ("#065F46", "#6EE7B7")
        else:
            border_color = "#3B82F6"
            badge_text = "📁 MỞ DỊCH VỤ SMB"
            badge_color = ("#DBEAFE", "#1E3A8A")
            badge_text_color = ("#1E40AF", "#93C5FD")

        card = ctk.CTkFrame(
            self.cards_container,
            fg_color=("#FFFFFF", "#1E293B"),
            border_color=border_color,
            border_width=1,
            corner_radius=10,
        )
        card.pack(fill="x", padx=4, pady=6)

        # Header của Card
        header = ctk.CTkFrame(card, fg_color="transparent")
        header.pack(fill="x", padx=12, pady=(10, 6))

        # Icon máy tính / server
        icon_str = "💻" if not is_self else "🖥️"
        lbl_icon = ctk.CTkLabel(header, text=icon_str, font=ctk.CTkFont(size=24))
        lbl_icon.pack(side="left", padx=(0, 10))

        # Thông tin Tên máy & IP
        info_box = ctk.CTkFrame(header, fg_color="transparent")
        info_box.pack(side="left", fill="both", expand=True)

        title_row = ctk.CTkFrame(info_box, fg_color="transparent")
        title_row.pack(anchor="w")

        lbl_name = ctk.CTkLabel(
            title_row,
            text=hostname,
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=("#111827", "#F9FAFB"),
        )
        lbl_name.pack(side="left", padx=(0, 8))

        lbl_ip = ctk.CTkLabel(
            title_row,
            text=f"[{ip}]",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#38BDF8",
        )
        lbl_ip.pack(side="left", padx=(0, 8))

        if is_self:
            badge_self = ctk.CTkLabel(
                title_row,
                text="MÁY TÍNH CỦA BẠN",
                font=ctk.CTkFont(size=10, weight="bold"),
                fg_color="#15803D",
                text_color="#FFFFFF",
                corner_radius=4,
                padx=6,
                pady=1,
            )
            badge_self.pack(side="left")

        lbl_vendor = ctk.CTkLabel(
            info_box,
            text=f"Hãng: {vendor} • Giao thức chia sẻ: Microsoft SMB / CIFS (Cổng 445)",
            font=ctk.CTkFont(size=11),
            text_color=("#6B7280", "#9CA3AF"),
        )
        lbl_vendor.pack(anchor="w", pady=(2, 0))

        # Huy hiệu trạng thái bên phải
        badge_status = ctk.CTkLabel(
            header,
            text=badge_text,
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color=badge_color,
            text_color=badge_text_color,
            corner_radius=6,
            padx=10,
            pady=4,
        )
        badge_status.pack(side="right", padx=(8, 0))

        # Nút thao tác nhanh trên Header
        btn_box = ctk.CTkFrame(header, fg_color="transparent")
        btn_box.pack(side="right")

        # Nút mở thư mục gốc của máy trong Explorer
        clean_ip = ip.split()[0]
        unc_root = rf"\\{clean_ip}"
        btn_open_root = ctk.CTkButton(
            btn_box,
            text="📂 Mở Thư Mục Gốc",
            command=lambda p=unc_root: open_in_explorer(p),
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color="#0284C7",
            hover_color="#0369A1",
            width=120,
            height=28,
        )
        btn_open_root.pack(side="left", padx=4)

        # Nút Soi cổng
        if self.on_open_port_scan and not is_self:
            btn_ports = ctk.CTkButton(
                btn_box,
                text="🔍 Soi Cổng",
                command=lambda d={"ip": clean_ip, "name": hostname, "vendor": vendor}: self.on_open_port_scan(d),
                font=ctk.CTkFont(size=11),
                fg_color="#4B5563",
                hover_color="#374151",
                width=80,
                height=28,
            )
            btn_ports.pack(side="left", padx=4)

        # Phân cách
        sep = ctk.CTkFrame(card, height=1, fg_color=("#E5E7EB", "#334155"))
        sep.pack(fill="x", padx=12, pady=4)

        # Danh sách thư mục chia sẻ bên trong
        shares_body = ctk.CTkFrame(card, fg_color="transparent")
        shares_body.pack(fill="x", padx=16, pady=(4, 10))

        regular_shares = [s for s in shares if not s.get("is_special")]
        special_shares = [s for s in shares if s.get("is_special")]

        if requires_auth and not regular_shares:
            lbl_auth_note = ctk.CTkLabel(
                shares_body,
                text="🔒 Máy này đã bật tường lửa chia sẻ: Chỉ người có tài khoản Windows và mật khẩu hợp lệ mới có thể duyệt file.\n"
                     "👉 Bạn có thể bấm 'Mở Thư Mục Gốc' để nhập tên đăng nhập và mật khẩu (nếu bạn có quyền truy cập).",
                font=ctk.CTkFont(size=11),
                text_color=("#4B5563", "#9CA3AF"),
                justify="left",
            )
            lbl_auth_note.pack(anchor="w", pady=4)
        elif not shares:
            lbl_none = ctk.CTkLabel(
                shares_body,
                text="Không phát hiện thư mục chia sẻ công khai nào khả dụng.",
                font=ctk.CTkFont(size=11),
                text_color=("#6B7280", "#9CA3AF"),
            )
            lbl_none.pack(anchor="w", pady=4)
        else:
            if regular_shares:
                lbl_sec_reg = ctk.CTkLabel(
                    shares_body,
                    text=f"📁 CÁC THƯ MỤC CHIA SẺ CÔNG KHAI ({len(regular_shares)}):",
                    font=ctk.CTkFont(size=11, weight="bold"),
                    text_color=("#111827", "#E2E8F0"),
                )
                lbl_sec_reg.pack(anchor="w", pady=(2, 4))

                for s in regular_shares:
                    self._render_share_row(shares_body, s, clean_ip)

            if special_shares:
                lbl_spec_note = ctk.CTkLabel(
                    shares_body,
                    text=f"⚙️ Share hệ thống quản trị ẩn Windows: {', '.join(s.get('name', '') for s in special_shares)} (Chỉ Admin máy đó mới mở được)",
                    font=ctk.CTkFont(size=10),
                    text_color=("#6B7280", "#64748B"),
                )
                lbl_spec_note.pack(anchor="w", pady=(4, 0))

    def _render_share_row(self, parent, share: Dict[str, Any], host_ip: str):
        """Vẽ 1 dòng hiển thị thư mục chia sẻ công khai."""
        name = share.get("name", "")
        unc_path = share.get("unc_path") or rf"\\{host_ip}\{name}"
        remark = share.get("remark", "")
        path_on_disk = share.get("path", "")
        is_public = share.get("is_public_risk", True)

        row = ctk.CTkFrame(parent, fg_color=("#F3F4F6", "#0F172A"), corner_radius=6)
        row.pack(fill="x", pady=2)

        icon_str = "📂" if is_public else "📁"
        lbl_ic = ctk.CTkLabel(row, text=icon_str, font=ctk.CTkFont(size=16))
        lbl_ic.pack(side="left", padx=(8, 6), pady=4)

        info_col = ctk.CTkFrame(row, fg_color="transparent")
        info_col.pack(side="left", fill="both", expand=True, pady=4)

        sub_row = ctk.CTkFrame(info_col, fg_color="transparent")
        sub_row.pack(anchor="w")

        lbl_sname = ctk.CTkLabel(
            sub_row,
            text=name,
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#38BDF8",
        )
        lbl_sname.pack(side="left", padx=(0, 6))

        if is_public:
            lbl_tag = ctk.CTkLabel(
                sub_row,
                text="CÔNG KHAI (MỞ TOANG)",
                font=ctk.CTkFont(size=9, weight="bold"),
                fg_color="#DC2626",
                text_color="#FFFFFF",
                corner_radius=3,
                padx=4,
                pady=0,
            )
            lbl_tag.pack(side="left")

        desc_parts = [unc_path]
        if path_on_disk:
            desc_parts.append(f"Ổ đĩa: {path_on_disk}")
        if remark:
            desc_parts.append(f"Ghi chú: {remark}")

        lbl_sdesc = ctk.CTkLabel(
            info_col,
            text=" • ".join(desc_parts),
            font=ctk.CTkFont(size=10),
            text_color=("#6B7280", "#94A3B8"),
        )
        lbl_sdesc.pack(anchor="w")

        act_box = ctk.CTkFrame(row, fg_color="transparent")
        act_box.pack(side="right", padx=6, pady=4)

        btn_open = ctk.CTkButton(
            act_box,
            text="📂 Mở Folder",
            command=lambda p=unc_path: open_in_explorer(p),
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color="#10B981",
            hover_color="#059669",
            width=84,
            height=26,
        )
        btn_open.pack(side="left", padx=3)

        btn_copy = ctk.CTkButton(
            act_box,
            text="📋 Copy UNC",
            command=lambda p=unc_path: copy_text_to_clipboard(p, self),
            font=ctk.CTkFont(size=11),
            fg_color="#4B5563",
            hover_color="#374151",
            width=76,
            height=26,
        )
        btn_copy.pack(side="left", padx=3)
