"""CustomTkinter UI for a real, bounded LAN throughput test."""

from __future__ import annotations

from tkinter import filedialog, messagebox
from typing import Any, Dict, Optional

import customtkinter as ctk

from throughput_test import (
    THROUGHPUT_DEFAULT_DURATION_S,
    THROUGHPUT_DEFAULT_PING_INTERVAL_S,
    THROUGHPUT_DEFAULT_PORT,
    THROUGHPUT_DEFAULT_RATE_MBPS,
    THROUGHPUT_DEFAULT_UDP_PAYLOAD_BYTES,
    THROUGHPUT_MAX_DURATION_S,
    THROUGHPUT_MAX_RATE_MBPS,
    THROUGHPUT_MAX_UDP_PAYLOAD_BYTES,
    THROUGHPUT_MIN_DURATION_S,
    THROUGHPUT_MIN_RATE_MBPS,
    THROUGHPUT_MIN_UDP_PAYLOAD_BYTES,
    THROUGHPUT_PROTOCOL_TCP,
    THROUGHPUT_PROTOCOL_UDP,
    THROUGHPUT_ROLE_CLIENT,
    THROUGHPUT_ROLE_SERVER,
    ThroughputTestSession,
    find_iperf3,
    validate_throughput_config,
)


ROLE_LABELS = {
    THROUGHPUT_ROLE_CLIENT: "Máy này là Client (gửi)",
    THROUGHPUT_ROLE_SERVER: "Máy này là Server (nhận)",
}
ROLE_BY_LABEL = {label: value for value, label in ROLE_LABELS.items()}

PROTOCOL_LABELS = {
    THROUGHPUT_PROTOCOL_TCP: "TCP - truyền tin cậy",
    THROUGHPUT_PROTOCOL_UDP: "UDP - đo jitter/mất gói",
}
PROTOCOL_BY_LABEL = {label: value for value, label in PROTOCOL_LABELS.items()}


def _format_data_size(byte_count: Optional[int]) -> str:
    if byte_count is None:
        return "--"
    size = float(byte_count)
    if size >= 1024 * 1024 * 1024:
        return f"{size / (1024 * 1024 * 1024):.2f} GB"
    return f"{size / (1024 * 1024):.1f} MB"


def _format_ping_stats(stats: Dict[str, Any]) -> str:
    if not stats or stats.get("avg_ms") is None:
        return "không có phản hồi"
    return (
        f"Avg {stats['avg_ms']:.1f} ms | p95 {stats['p95_ms']:.1f} ms | "
        f"Jitter {stats['jitter_ms']:.1f} ms | Mất {stats['loss_rate']:.1f}%"
    )


class ThroughputTestWindow(ctk.CTkToplevel):
    """Guide a user through an iperf3 test without exposing a LAN server broadly."""

    def __init__(
        self,
        master,
        *,
        default_local_ip: str = "",
        default_gateway: str = "",
        default_target: str = "",
    ) -> None:
        super().__init__(master)
        self.title("Throughput LAN - iperf3")
        self.geometry("940x790")
        self.minsize(790, 670)
        self.transient(master)

        self._closing = False
        self._session: Optional[ThroughputTestSession] = None
        self._run_token = 0
        self._inputs_enabled = True
        self._input_widgets = []
        self._last_client_target = str(default_target or "").strip()
        self._server_bind_ip = str(default_local_ip or "").strip()
        self._active_role = THROUGHPUT_ROLE_CLIENT

        self.role_var = ctk.StringVar(value=ROLE_LABELS[THROUGHPUT_ROLE_CLIENT])
        self.endpoint_var = ctk.StringVar(value=self._last_client_target)
        self.port_var = ctk.StringVar(value=str(THROUGHPUT_DEFAULT_PORT))
        self.protocol_var = ctk.StringVar(value=PROTOCOL_LABELS[THROUGHPUT_PROTOCOL_TCP])
        self.rate_var = ctk.StringVar(value=f"{THROUGHPUT_DEFAULT_RATE_MBPS:g}")
        self.duration_var = ctk.StringVar(value=f"{THROUGHPUT_DEFAULT_DURATION_S:g}")
        self.payload_var = ctk.StringVar(value=str(THROUGHPUT_DEFAULT_UDP_PAYLOAD_BYTES))
        self.router_var = ctk.StringVar(value=str(default_gateway or "").strip())
        self.ping_interval_var = ctk.StringVar(value=f"{THROUGHPUT_DEFAULT_PING_INTERVAL_S:g}")
        self.iperf_path_var = ctk.StringVar(value=find_iperf3() or "")

        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self._close)
        self.after(80, self._focus_window)

    def set_target(self, target: str) -> bool:
        """Pre-fill a discovered device while the window is idle."""
        target = str(target or "").strip()
        if not target or (self._session and self._session.is_running):
            return False
        self._last_client_target = target
        if self._active_role == THROUGHPUT_ROLE_CLIENT:
            self.endpoint_var.set(target)
        return True

    def _focus_window(self) -> None:
        try:
            self.lift()
            self.focus_force()
        except Exception:
            pass

    def _build_ui(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        hero = ctk.CTkFrame(
            self,
            fg_color=("#E0F2FE", "#082F49"),
            border_width=1,
            border_color="#0284C7",
            corner_radius=12,
        )
        hero.grid(row=0, column=0, padx=16, pady=(16, 10), sticky="ew")
        ctk.CTkLabel(
            hero,
            text="🚀 Throughput LAN thật - TCP/UDP + Ping router",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color=("#075985", "#BAE6FD"),
            anchor="w",
        ).pack(fill="x", padx=18, pady=(13, 2))
        ctk.CTkLabel(
            hero,
            text=(
                "Truyền luồng dữ liệu có kiểm soát giữa PC và điện thoại/NAS bằng iperf3. "
                "Chỉ nhận IP LAN riêng, giới hạn 1-100 Mbps và lấy mốc ping router trước/trong khi test."
            ),
            font=ctk.CTkFont(size=12),
            text_color=("#0C4A6E", "#BAE6FD"),
            anchor="w",
            justify="left",
            wraplength=875,
        ).pack(fill="x", padx=18, pady=(0, 13))

        form = ctk.CTkFrame(self, fg_color=("#F8FAFC", "#111827"), corner_radius=10)
        form.grid(row=1, column=0, padx=16, pady=(0, 10), sticky="ew")
        for column in (1, 3, 5):
            form.grid_columnconfigure(column, weight=1)

        self._add_option(form, 0, 0, "Vai trò", self.role_var, list(ROLE_BY_LABEL), self._on_role_changed)
        self.lbl_endpoint = ctk.CTkLabel(
            form,
            text="IP máy server (điện thoại/NAS)",
            font=ctk.CTkFont(size=11, weight="bold"),
            anchor="w",
        )
        self.lbl_endpoint.grid(row=0, column=2, padx=(14, 6), pady=(14, 6), sticky="w")
        self.entry_endpoint = ctk.CTkEntry(
            form,
            textvariable=self.endpoint_var,
            placeholder_text="Ví dụ: 192.168.1.25",
            height=30,
        )
        self.entry_endpoint.grid(row=0, column=3, padx=(0, 10), pady=(14, 6), sticky="ew")
        self._input_widgets.append(self.entry_endpoint)
        self._add_entry(form, 0, 4, "Cổng iperf3", self.port_var)

        self._add_option(
            form,
            1,
            0,
            "Giao thức",
            self.protocol_var,
            list(PROTOCOL_BY_LABEL),
            self._on_protocol_changed,
        )
        self._add_entry(form, 1, 2, "Tốc độ mục tiêu (Mbps)", self.rate_var)
        self._add_entry(form, 1, 4, "Thời gian (giây)", self.duration_var)

        self.lbl_payload = ctk.CTkLabel(
            form,
            text="Payload UDP (byte)",
            font=ctk.CTkFont(size=11, weight="bold"),
            anchor="w",
        )
        self.lbl_payload.grid(row=2, column=0, padx=(14, 6), pady=6, sticky="w")
        self.entry_payload = ctk.CTkEntry(form, textvariable=self.payload_var, height=30)
        self.entry_payload.grid(row=2, column=1, padx=(0, 10), pady=6, sticky="ew")
        self._input_widgets.append(self.entry_payload)
        self._add_entry(form, 2, 2, "IP router để ping (tùy chọn)", self.router_var)
        self._add_entry(form, 2, 4, "Lấy mẫu ping (giây)", self.ping_interval_var)

        ctk.CTkLabel(
            form,
            text="Đường dẫn iperf3.exe",
            font=ctk.CTkFont(size=11, weight="bold"),
            anchor="w",
        ).grid(row=3, column=0, padx=(14, 6), pady=6, sticky="w")
        self.entry_iperf_path = ctk.CTkEntry(
            form,
            textvariable=self.iperf_path_var,
            placeholder_text="Tự tìm bản đi kèm hoặc chọn iperf3.exe",
            height=30,
        )
        self.entry_iperf_path.grid(row=3, column=1, columnspan=3, padx=(0, 10), pady=6, sticky="ew")
        self._input_widgets.append(self.entry_iperf_path)
        self.btn_browse_iperf = ctk.CTkButton(
            form,
            text="Chọn file...",
            width=105,
            height=30,
            fg_color=("#E5E7EB", "#374151"),
            text_color=("#111827", "#F9FAFB"),
            hover_color=("#D1D5DB", "#4B5563"),
            command=self._choose_iperf3,
        )
        self.btn_browse_iperf.grid(row=3, column=4, padx=(0, 10), pady=6, sticky="ew")
        self._input_widgets.append(self.btn_browse_iperf)
        self.lbl_iperf_status = ctk.CTkLabel(
            form,
            text="",
            font=ctk.CTkFont(size=11),
            text_color=("#64748B", "#94A3B8"),
            anchor="w",
            justify="left",
            wraplength=800,
        )
        self.lbl_iperf_status.grid(row=4, column=0, columnspan=6, padx=14, pady=(2, 12), sticky="w")

        actions = ctk.CTkFrame(self, fg_color="transparent")
        actions.grid(row=2, column=0, padx=16, pady=(0, 8), sticky="ew")
        actions.grid_columnconfigure(4, weight=1)
        self.btn_start = ctk.CTkButton(
            actions,
            text="▶ Bắt đầu throughput test",
            width=185,
            height=34,
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#0284C7",
            hover_color="#0369A1",
            command=self._start_test,
        )
        self.btn_start.grid(row=0, column=0, padx=(0, 8), sticky="w")
        self.btn_stop = ctk.CTkButton(
            actions,
            text="■ Dừng",
            width=95,
            height=34,
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#DC2626",
            hover_color="#B91C1C",
            state="disabled",
            command=self._stop_test,
        )
        self.btn_stop.grid(row=0, column=1, padx=(0, 8), sticky="w")
        self.btn_copy = ctk.CTkButton(
            actions,
            text="📋 Hướng dẫn máy kia",
            width=155,
            height=34,
            fg_color=("#E5E7EB", "#374151"),
            text_color=("#111827", "#F9FAFB"),
            hover_color=("#D1D5DB", "#4B5563"),
            command=self._copy_peer_instructions,
        )
        self.btn_copy.grid(row=0, column=2, padx=(0, 14), sticky="w")
        self.progress = ctk.CTkProgressBar(actions, height=8)
        self.progress.grid(row=0, column=4, padx=(0, 10), sticky="ew")
        self.progress.set(0)
        self.lbl_progress = ctk.CTkLabel(
            actions,
            text="Sẵn sàng",
            width=150,
            anchor="e",
            text_color=("#475569", "#CBD5E1"),
        )
        self.lbl_progress.grid(row=0, column=5, sticky="e")

        result_box = ctk.CTkFrame(self, fg_color=("#FFFFFF", "#0F172A"), corner_radius=10)
        result_box.grid(row=3, column=0, padx=16, pady=(0, 8), sticky="nsew")
        result_box.grid_columnconfigure(0, weight=1)
        result_box.grid_rowconfigure(2, weight=1)
        self.lbl_status = ctk.CTkLabel(
            result_box,
            text="Trạng thái: Sẵn sàng",
            font=ctk.CTkFont(size=13, weight="bold"),
            anchor="w",
        )
        self.lbl_status.grid(row=0, column=0, padx=14, pady=(12, 3), sticky="w")
        self.lbl_summary = ctk.CTkLabel(
            result_box,
            text="Chưa có kết quả. Cài app iperf3 trên điện thoại, mở Server rồi nhập IP của điện thoại vào đây.",
            font=ctk.CTkFont(size=12),
            text_color=("#475569", "#CBD5E1"),
            anchor="w",
            justify="left",
            wraplength=860,
        )
        self.lbl_summary.grid(row=1, column=0, padx=14, pady=(0, 6), sticky="ew")
        self.details = ctk.CTkTextbox(
            result_box,
            font=("Consolas", 11),
            wrap="word",
            activate_scrollbars=True,
        )
        self.details.grid(row=2, column=0, padx=10, pady=(0, 10), sticky="nsew")
        self._set_details(self._peer_help_text())

        self._refresh_iperf_status()
        self._on_protocol_changed()
        self._on_role_changed(self.role_var.get())

    def _add_entry(self, parent, row: int, column: int, label: str, variable) -> None:
        ctk.CTkLabel(
            parent,
            text=label,
            font=ctk.CTkFont(size=11, weight="bold"),
            anchor="w",
        ).grid(row=row, column=column, padx=(14, 6), pady=6, sticky="w")
        entry = ctk.CTkEntry(parent, textvariable=variable, height=30)
        entry.grid(row=row, column=column + 1, padx=(0, 10), pady=6, sticky="ew")
        self._input_widgets.append(entry)

    def _add_option(self, parent, row: int, column: int, label: str, variable, values, command) -> None:
        ctk.CTkLabel(
            parent,
            text=label,
            font=ctk.CTkFont(size=11, weight="bold"),
            anchor="w",
        ).grid(row=row, column=column, padx=(14, 6), pady=(14, 6) if row == 0 else 6, sticky="w")
        option = ctk.CTkOptionMenu(
            parent,
            variable=variable,
            values=values,
            command=command,
            height=30,
            font=ctk.CTkFont(size=11),
        )
        option.grid(row=row, column=column + 1, padx=(0, 10), pady=(14, 6) if row == 0 else 6, sticky="ew")
        self._input_widgets.append(option)

    def _set_details(self, text: str) -> None:
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("end", text)
        self.details.configure(state="disabled")

    def _append_details(self, text: str) -> None:
        self.details.configure(state="normal")
        self.details.insert("end", text.rstrip() + "\n")
        self.details.see("end")
        self.details.configure(state="disabled")

    def _current_role(self) -> str:
        return ROLE_BY_LABEL.get(self.role_var.get(), THROUGHPUT_ROLE_CLIENT)

    def _current_protocol(self) -> str:
        return PROTOCOL_BY_LABEL.get(self.protocol_var.get(), THROUGHPUT_PROTOCOL_TCP)

    def _on_role_changed(self, _value=None) -> None:
        role = self._current_role()
        if role == self._active_role:
            self._update_role_copy()
            return
        if self._active_role == THROUGHPUT_ROLE_CLIENT:
            self._last_client_target = self.endpoint_var.get().strip()
        else:
            self._server_bind_ip = self.endpoint_var.get().strip()
        self._active_role = role
        if role == THROUGHPUT_ROLE_CLIENT:
            self.lbl_endpoint.configure(text="IP máy server (điện thoại/NAS)")
            self.entry_endpoint.configure(placeholder_text="Ví dụ: 192.168.1.25")
            self.endpoint_var.set(self._last_client_target)
        else:
            self.lbl_endpoint.configure(text="IP nội bộ máy này để lắng nghe")
            self.entry_endpoint.configure(placeholder_text="Ví dụ: 192.168.1.10")
            self.endpoint_var.set(self._server_bind_ip)
        self._update_role_copy()

    def _on_protocol_changed(self, _value=None) -> None:
        enabled = self._current_protocol() == THROUGHPUT_PROTOCOL_UDP and self._inputs_enabled
        self.entry_payload.configure(state="normal" if enabled else "disabled")
        self.lbl_payload.configure(text_color=("#111827", "#F9FAFB") if enabled else ("#94A3B8", "#64748B"))
        self._update_role_copy()

    def _update_role_copy(self) -> None:
        if not hasattr(self, "details") or (self._session and self._session.is_running):
            return
        self._set_details(self._peer_help_text())

    def _peer_help_text(self) -> str:
        role = self._current_role()
        protocol = self._current_protocol().upper()
        endpoint = self.endpoint_var.get().strip() or "<IP LAN>"
        port = self.port_var.get().strip() or str(THROUGHPUT_DEFAULT_PORT)
        rate = self.rate_var.get().strip() or f"{THROUGHPUT_DEFAULT_RATE_MBPS:g}"
        duration = self.duration_var.get().strip() or f"{THROUGHPUT_DEFAULT_DURATION_S:g}"
        if role == THROUGHPUT_ROLE_CLIENT:
            return (
                "Cách dùng với điện thoại/NAS:\n"
                "1. Kết nối cùng Wi-Fi với máy tính.\n"
                "2. Mở app hỗ trợ iperf3 trên điện thoại, chọn Server, cổng "
                f"{port}, bấm Start.\n"
                "3. Giữ app ở foreground, tắt tiết kiệm pin trong lúc test.\n"
                "4. Nhập IP Wi-Fi của điện thoại vào ô IP máy server, rồi bấm Bắt đầu.\n\n"
                f"Bài test hiện tại: {protocol}, mục tiêu {rate} Mbps trong {duration} giây.\n"
                "Nếu báo connection refused/timeout: kiểm tra IP, Server đã Start và Wi-Fi không bật client isolation.\n\n"
                "Lưu ý: chỉ dùng với thiết bị và mạng LAN của bạn."
            )
        return (
            "Máy này sẽ mở iperf3 Server cho đúng một client LAN, sau đó tự động dừng.\n"
            "Chỉ cho phép Windows Firewall nếu Windows hỏi và chỉ trên mạng Private.\n"
            f"Trên điện thoại/máy khác: chọn Client, nhập {endpoint}:{port}, "
            f"chọn {protocol}, {rate} Mbps, {duration} giây, rồi Start.\n\n"
            "Server iperf3 tự nhận TCP hoặc UDP do Client chọn; mục Giao thức ở đây chỉ dùng để soạn hướng dẫn cho máy kia.\n\n"
            "Không mở cổng ra Internet và bấm Dừng ngay khi xong."
        )

    def _refresh_iperf_status(self) -> None:
        path = find_iperf3(self.iperf_path_var.get())
        if path:
            self.lbl_iperf_status.configure(
                text=(
                    f"iperf3 sẵn sàng: {path} | Giới hạn: "
                    f"{THROUGHPUT_MIN_RATE_MBPS:g}-{THROUGHPUT_MAX_RATE_MBPS:g} Mbps, "
                    f"{THROUGHPUT_MIN_DURATION_S:g}-{THROUGHPUT_MAX_DURATION_S:g} giây, "
                    f"UDP {THROUGHPUT_MIN_UDP_PAYLOAD_BYTES}-{THROUGHPUT_MAX_UDP_PAYLOAD_BYTES} byte"
                ),
                text_color="#10B981",
            )
        else:
            self.lbl_iperf_status.configure(
                text=(
                    "Chưa tìm thấy iperf3.exe. Chọn file iperf3.exe portable; "
                    "bản đi kèm của app sẽ được tự động dùng nếu có."
                ),
                text_color="#F59E0B",
            )

    def _choose_iperf3(self) -> None:
        path = filedialog.askopenfilename(
            parent=self,
            title="Chọn iperf3.exe",
            filetypes=[("iperf3.exe", "iperf3.exe"), ("Executable", "*.exe")],
        )
        if path:
            self.iperf_path_var.set(path)
        self._refresh_iperf_status()

    def _read_config(self) -> Dict[str, Any]:
        role = self._current_role()
        endpoint = self.endpoint_var.get().strip()
        protocol = self._current_protocol()
        return validate_throughput_config(
            role=role,
            target=endpoint if role == THROUGHPUT_ROLE_CLIENT else "",
            bind_ip=endpoint if role == THROUGHPUT_ROLE_SERVER else "",
            rate_mbps=float(self.rate_var.get().strip()),
            duration_s=float(self.duration_var.get().strip()),
            protocol=protocol,
            port=int(self.port_var.get().strip()),
            udp_payload_size=(
                int(self.payload_var.get().strip())
                if protocol == THROUGHPUT_PROTOCOL_UDP
                else THROUGHPUT_DEFAULT_UDP_PAYLOAD_BYTES
            ),
            ping_target=self.router_var.get().strip(),
            ping_interval_s=float(self.ping_interval_var.get().strip()),
        )

    def _set_inputs_enabled(self, enabled: bool) -> None:
        self._inputs_enabled = enabled
        state = "normal" if enabled else "disabled"
        for widget in self._input_widgets:
            widget.configure(state=state)
        self.btn_start.configure(state=state)
        self.btn_copy.configure(state=state)
        self._on_protocol_changed()

    def _start_test(self) -> None:
        if self._session and self._session.is_running:
            return
        try:
            config = self._read_config()
        except (TypeError, ValueError) as exc:
            messagebox.showerror("Thông số chưa hợp lệ", str(exc), parent=self)
            return

        executable = find_iperf3(self.iperf_path_var.get())
        if not executable:
            messagebox.showerror(
                "Thiếu iperf3",
                "Không tìm thấy iperf3.exe. Bấm 'Chọn file...' để chọn bản portable iperf3.",
                parent=self,
            )
            self._refresh_iperf_status()
            return

        role = config["role"]
        endpoint = config["target"] if role == THROUGHPUT_ROLE_CLIENT else config["bind_ip"]
        estimated = _format_data_size(config["estimated_bytes"])
        if role == THROUGHPUT_ROLE_CLIENT:
            confirm_text = (
                f"Truyền tới {endpoint}:{config['port']}\n"
                f"{config['protocol'].upper()} - {config['rate_mbps']:g} Mbps trong "
                f"{config['duration_s']:g} giây\n"
                f"Dữ liệu tối đa dự kiến: {estimated}\n\n"
                "Chỉ tiếp tục nếu đây là thiết bị trong LAN của bạn và iperf3 Server đã được bật."
            )
        else:
            confirm_text = (
                f"Mở Server trên {endpoint}:{config['port']} cho đúng một client LAN.\n"
                f"Cửa sổ sẽ tự dừng sau khoảng {config['duration_s'] + 2:g} giây nếu không có client.\n\n"
                "Chỉ cho phép Windows Firewall trên mạng Private, không mở cổng ra Internet."
            )
        if not messagebox.askyesno("Xác nhận throughput test", confirm_text, parent=self):
            return

        self._run_token += 1
        run_token = self._run_token
        self._set_details("Đang chuẩn bị bài test...\n")
        self.progress.set(0)
        self.lbl_progress.configure(text="Đang lấy baseline")
        self.lbl_status.configure(text="Trạng thái: Đang khởi tạo...", text_color="#F59E0B")
        self.lbl_summary.configure(text="Đang lấy mốc ping router trước khi truyền dữ liệu.")
        self._set_inputs_enabled(False)
        self.btn_stop.configure(state="normal")
        self._session = ThroughputTestSession(
            config,
            executable=executable,
            on_update=lambda event, token=run_token: self._queue_update(token, event),
            on_complete=lambda summary, token=run_token: self._queue_complete(token, summary),
        )
        if not self._session.start():
            self._set_inputs_enabled(True)
            self.btn_stop.configure(state="disabled")

    def _stop_test(self) -> None:
        if self._session and self._session.is_running:
            self.btn_stop.configure(state="disabled")
            self.lbl_status.configure(text="Trạng thái: Đang dừng an toàn...", text_color="#F59E0B")
            self._session.stop()

    def _queue_update(self, token: int, event: Dict[str, Any]) -> None:
        if self._closing or token != self._run_token:
            return
        try:
            self.after(0, lambda: self._handle_update(token, event))
        except Exception:
            pass

    def _handle_update(self, token: int, event: Dict[str, Any]) -> None:
        if self._closing or token != self._run_token:
            return
        kind = event.get("kind")
        if kind == "status":
            self.lbl_status.configure(text=f"Trạng thái: {event.get('message', '')}", text_color="#F59E0B")
            self._append_details(event.get("message", ""))
        elif kind == "progress":
            elapsed = float(event.get("elapsed_s", 0.0))
            duration = max(0.001, float(event.get("duration_s", 1.0)))
            self.progress.set(min(0.99, elapsed / duration))
            self.lbl_progress.configure(text=f"{elapsed:.0f}/{duration:.0f} giây")
        elif kind == "ping":
            phase = event.get("phase", "during")
            value = event.get("latency_ms")
            value_text = f"{value:.0f} ms" if value is not None else "Timeout"
            if phase == "baseline":
                self.lbl_summary.configure(text=f"Ping router trước test: {value_text}")
            else:
                self.lbl_summary.configure(text=f"Đang truyền dữ liệu - ping router: {value_text}")

    def _queue_complete(self, token: int, summary: Dict[str, Any]) -> None:
        if self._closing or token != self._run_token:
            return
        try:
            self.after(0, lambda: self._handle_complete(token, summary))
        except Exception:
            pass

    def _handle_complete(self, token: int, summary: Dict[str, Any]) -> None:
        if self._closing or token != self._run_token:
            return
        result = summary.get("result")
        error = summary.get("error")
        cancelled = summary.get("cancelled")
        timed_out = summary.get("timed_out")
        if error:
            status = f"Trạng thái: Lỗi - {error}"
            color = "#EF4444"
        elif cancelled:
            status = "Trạng thái: Đã dừng theo yêu cầu"
            color = "#F59E0B"
        elif timed_out:
            status = "Trạng thái: Quá thời gian cho phép"
            color = "#F59E0B"
        else:
            status = "Trạng thái: Hoàn tất"
            color = "#10B981"
        self.lbl_status.configure(text=status, text_color=color)
        self.progress.set(1 if not cancelled else self.progress.get())
        self.lbl_progress.configure(text=f"{summary.get('elapsed_s', 0):.1f} giây")

        baseline = summary.get("baseline_ping", {})
        during = summary.get("during_ping", {})
        lines = []
        if result:
            summary_text = (
                f"Thông lượng thực: {result['mbps']:.2f} Mbps | "
                f"Đã truyền: {_format_data_size(result['bytes'])} | "
                f"Thời gian: {result['seconds']:.2f} giây"
            )
            lines.append(summary_text)
            if result.get("jitter_ms") is not None:
                lines.append(
                    f"UDP: Jitter {result['jitter_ms']:.2f} ms | "
                    f"Mất {result.get('lost_percent', 0):.2f}% | "
                    f"{result.get('lost_packets', 0)}/{result.get('packets', 0)} gói"
                )
        else:
            summary_text = "Không có kết quả throughput hoàn chỉnh. Xem chi tiết bên dưới."
        lines.extend(
            (
                f"Ping router trước test: {_format_ping_stats(baseline)}",
                f"Ping router khi test: {_format_ping_stats(during)}",
            )
        )
        if summary.get("avg_ping_delta_ms") is not None:
            lines.append(
                f"Chênh lệch latency: Avg {summary['avg_ping_delta_ms']:+.1f} ms | "
                f"p95 {summary['p95_ping_delta_ms']:+.1f} ms"
            )
        self.lbl_summary.configure(text=summary_text)
        self._append_details("\n".join(lines))
        command = summary.get("command") or []
        if command:
            self._append_details("Lệnh đã chạy: " + " ".join(str(part) for part in command[1:]))
        self._set_inputs_enabled(True)
        self.btn_stop.configure(state="disabled")

    def _copy_peer_instructions(self) -> None:
        text = self._peer_help_text()
        try:
            self.clipboard_clear()
            self.clipboard_append(text)
            self.update()
            self.lbl_status.configure(text="Trạng thái: Đã sao chép hướng dẫn cho máy kia", text_color="#10B981")
        except Exception:
            messagebox.showinfo("Hướng dẫn máy kia", text, parent=self)

    def _close(self) -> None:
        self._closing = True
        self._run_token += 1
        if self._session and self._session.is_running:
            self._session.stop()
        try:
            self.destroy()
        except Exception:
            pass
