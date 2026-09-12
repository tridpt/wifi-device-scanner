"""Cửa sổ chạy một phiên ping hữu hạn với tham số do người dùng chọn."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

import customtkinter as ctk
from tkinter import messagebox

from load_test_window import LoadTestWindow
from ping_monitor import (
    PING_DEFAULT_IN_FLIGHT,
    PING_MODE_ASYNC,
    PING_MODE_SEQUENTIAL,
    UDP_PAYLOAD_DEFAULT_BYTES,
    UDP_PAYLOAD_MAX_BYTES,
    UDP_PAYLOAD_MIN_BYTES,
    PING_PROTOCOL_AUTO,
    PING_PROTOCOL_ICMP,
    PING_PROTOCOL_TCP,
    PING_PROTOCOL_UDP,
    PingSession,
    validate_ping_session_config,
)


MODE_LABELS = {
    PING_MODE_SEQUENTIAL: "Tuần tự - đợi phản hồi",
    PING_MODE_ASYNC: "Bất đồng bộ - gửi tiếp",
}

PROTOCOL_LABELS = {
    PING_PROTOCOL_AUTO: "Tự động (ICMP -> TCP -> UDP)",
    PING_PROTOCOL_ICMP: "Chỉ ICMP",
    PING_PROTOCOL_TCP: "Chỉ TCP",
    PING_PROTOCOL_UDP: "Chỉ UDP DNS (53)",
}
PROTOCOL_BY_LABEL = {label: value for value, label in PROTOCOL_LABELS.items()}


class PingSessionWindow(ctk.CTkToplevel):
    """UI cho một phiên ping modem/máy chủ có thể dừng bất cứ lúc nào."""

    def __init__(self, master, default_target: str = "192.168.1.1"):
        super().__init__(master)
        self.title("Ping tùy chỉnh - Modem / Máy chủ")
        self.geometry("800x720")
        self.minsize(720, 630)
        self.transient(master)

        self._closing = False
        self._session: Optional[PingSession] = None
        self._load_test_window: Optional[LoadTestWindow] = None
        self._input_widgets = []
        self._mode_widgets = []
        self._inputs_enabled = True
        self._run_token = 0

        self.target_var = ctk.StringVar(value=default_target or "192.168.1.1")
        self.count_var = ctk.StringVar(value="10")
        self.duration_var = ctk.StringVar(value="30")
        self.interval_var = ctk.StringVar(value="1")
        self.timeout_var = ctk.StringVar(value="800")
        self.mode_var = ctk.StringVar(value=PING_MODE_SEQUENTIAL)
        self.in_flight_var = ctk.StringVar(value=str(PING_DEFAULT_IN_FLIGHT))
        self.udp_payload_var = ctk.StringVar(value=str(UDP_PAYLOAD_DEFAULT_BYTES))
        self.protocol_var = ctk.StringVar(value=PROTOCOL_LABELS[PING_PROTOCOL_AUTO])

        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self._close)
        self.after(80, self._focus_window)

    def set_target(self, target: str) -> bool:
        """Set a new target while idle; return False while a session is running."""
        target = str(target or "").strip()
        if not target or (self._session and self._session.is_running):
            return False
        self.target_var.set(target)
        self.title(f"Ping tùy chỉnh - {target}")
        return True

    def _focus_window(self) -> None:
        try:
            self.lift()
            self.focus_force()
        except Exception:
            pass

    def _open_load_test(self) -> None:
        """Open a LAN load test pre-filled with the current target."""
        existing = self._load_test_window
        if existing is not None:
            try:
                if existing.winfo_exists():
                    existing.set_target(self.target_var.get())
                    existing.lift()
                    existing.focus_force()
                    return
            except Exception:
                pass
        self._load_test_window = LoadTestWindow(
            self,
            default_target=self.target_var.get(),
        )

    def _build_ui(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

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
            text="🎯 Ping theo phiên",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color=("#075985", "#BAE6FD"),
            anchor="w",
        ).pack(fill="x", padx=18, pady=(13, 2))
        ctk.CTkLabel(
            hero,
            text="Chủ động kiểm tra modem: phiên sẽ dừng khi đủ số lần hoặc hết thời gian tối đa, tùy điều kiện đến trước.",
            font=ctk.CTkFont(size=12),
            text_color=("#0C4A6E", "#BAE6FD"),
            anchor="w",
            wraplength=710,
            justify="left",
        ).pack(fill="x", padx=18, pady=(0, 13))
        self.btn_load_test = ctk.CTkButton(
            hero,
            text="🔥 Mở test chịu tải LAN cho địa chỉ này",
            width=235,
            height=30,
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color="#D97706",
            hover_color="#B45309",
            command=self._open_load_test,
        )
        self.btn_load_test.pack(anchor="e", padx=18, pady=(0, 12))

        form = ctk.CTkFrame(self, fg_color=("#F8FAFC", "#111827"), corner_radius=10)
        form.grid(row=1, column=0, padx=16, pady=(0, 10), sticky="ew")
        for column in (1, 3):
            form.grid_columnconfigure(column, weight=1)

        ctk.CTkLabel(
            form,
            text="Địa chỉ mục tiêu",
            font=ctk.CTkFont(size=12, weight="bold"),
            anchor="w",
        ).grid(row=0, column=0, padx=(14, 8), pady=(14, 6), sticky="w")
        self.entry_target = ctk.CTkEntry(
            form,
            textvariable=self.target_var,
            height=32,
            placeholder_text="Ví dụ: 192.168.1.1 hoặc google.com",
        )
        self.entry_target.grid(row=0, column=1, columnspan=3, padx=(0, 14), pady=(14, 6), sticky="ew")
        self._input_widgets.append(self.entry_target)

        self._add_field(form, 1, 0, "Số lần ping", self.count_var)
        self._add_field(form, 1, 2, "Thời gian tối đa (giây)", self.duration_var)
        self._add_field(form, 2, 0, "Khoảng cách (giây)", self.interval_var)
        self._add_field(form, 2, 2, "Timeout (ms)", self.timeout_var)

        ctk.CTkLabel(
            form,
            text="Kiểu gửi",
            font=ctk.CTkFont(size=11, weight="bold"),
            anchor="w",
        ).grid(row=3, column=0, padx=(14, 6), pady=6, sticky="w")
        mode_frame = ctk.CTkFrame(form, fg_color="transparent")
        mode_frame.grid(row=3, column=1, columnspan=3, padx=(0, 14), pady=6, sticky="ew")
        mode_frame.grid_columnconfigure(1, weight=1)
        for column, (value, label) in enumerate(MODE_LABELS.items()):
            radio = ctk.CTkRadioButton(
                mode_frame,
                text=label,
                variable=self.mode_var,
                value=value,
                command=self._on_mode_changed,
                font=ctk.CTkFont(size=11),
            )
            radio.grid(row=0, column=column, padx=(0, 18), sticky="w")
            self._mode_widgets.append(radio)

        ctk.CTkLabel(
            form,
            text="Giao thức",
            font=ctk.CTkFont(size=11, weight="bold"),
            anchor="w",
        ).grid(row=4, column=0, padx=(14, 6), pady=6, sticky="w")
        self.protocol_menu = ctk.CTkOptionMenu(
            form,
            variable=self.protocol_var,
            values=list(PROTOCOL_BY_LABEL),
            command=self._on_protocol_changed,
            height=30,
            font=ctk.CTkFont(size=11),
        )
        self.protocol_menu.grid(row=4, column=1, padx=(0, 10), pady=6, sticky="ew")
        self._input_widgets.append(self.protocol_menu)

        self._add_field(form, 4, 2, "Yêu cầu đồng thời", self.in_flight_var)
        self.entry_in_flight = self._input_widgets[-1]
        self._add_field(form, 5, 0, "Payload UDP (byte)", self.udp_payload_var)
        self.entry_udp_payload = self._input_widgets[-1]
        self.lbl_mode_hint = ctk.CTkLabel(
            form,
            text="",
            font=ctk.CTkFont(size=11),
            text_color=("#64748B", "#94A3B8"),
            anchor="w",
            wraplength=390,
            justify="left",
        )
        self.lbl_mode_hint.grid(row=6, column=0, columnspan=4, padx=14, pady=(3, 3), sticky="w")

        ctk.CTkLabel(
            form,
            text=(
                "Thời gian tối đa = 0 nghĩa là chạy đủ số lần. UDP dùng truy vấn DNS/53 "
                f"với payload {UDP_PAYLOAD_MIN_BYTES}-{UDP_PAYLOAD_MAX_BYTES} byte "
                "và chỉ tính thành công khi nhận phản hồi thật."
            ),
            font=ctk.CTkFont(size=11),
            text_color=("#64748B", "#94A3B8"),
            anchor="w",
            wraplength=740,
            justify="left",
        ).grid(row=7, column=0, columnspan=4, padx=14, pady=(3, 12), sticky="w")

        self._on_mode_changed()
        self._on_protocol_changed(self.protocol_var.get())

        actions = ctk.CTkFrame(self, fg_color="transparent")
        actions.grid(row=3, column=0, padx=16, pady=(0, 8), sticky="ew")
        actions.grid_columnconfigure(3, weight=1)

        self.btn_start = ctk.CTkButton(
            actions,
            text="▶ Bắt đầu ping",
            width=145,
            height=34,
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#0284C7",
            hover_color="#0369A1",
            command=self._start_session,
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
            command=self._stop_session,
        )
        self.btn_stop.grid(row=0, column=1, padx=(0, 8), sticky="w")

        self.btn_clear = ctk.CTkButton(
            actions,
            text="Xóa nhật ký",
            width=105,
            height=34,
            fg_color=("#E5E7EB", "#374151"),
            text_color=("#111827", "#F9FAFB"),
            hover_color=("#D1D5DB", "#4B5563"),
            command=self._clear_log,
        )
        self.btn_clear.grid(row=0, column=2, padx=(0, 14), sticky="w")

        self.progress = ctk.CTkProgressBar(actions, height=8)
        self.progress.grid(row=0, column=3, padx=(0, 12), sticky="ew")
        self.progress.set(0)

        self.lbl_progress = ctk.CTkLabel(
            actions,
            text="Sẵn sàng",
            width=145,
            anchor="e",
            text_color=("#475569", "#CBD5E1"),
        )
        self.lbl_progress.grid(row=0, column=4, sticky="e")

        result_box = ctk.CTkFrame(self, fg_color=("#FFFFFF", "#0F172A"), corner_radius=10)
        result_box.grid(row=2, column=0, padx=16, pady=(0, 8), sticky="nsew")
        result_box.grid_columnconfigure(0, weight=1)
        result_box.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(
            result_box,
            text="Nhật ký kết quả",
            font=ctk.CTkFont(size=13, weight="bold"),
            anchor="w",
        ).grid(row=0, column=0, padx=14, pady=(11, 5), sticky="w")
        self.log_box = ctk.CTkTextbox(
            result_box,
            wrap="none",
            font=("Consolas", 11),
            activate_scrollbars=True,
        )
        self.log_box.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="nsew")
        self._set_log_text("Chưa có phiên ping. Nhập thông số rồi bấm 'Bắt đầu ping'.")

        summary = ctk.CTkFrame(self, fg_color="transparent")
        summary.grid(row=4, column=0, padx=16, pady=(0, 14), sticky="ew")
        summary.grid_columnconfigure(1, weight=1)
        self.lbl_status = ctk.CTkLabel(
            summary,
            text="Trạng thái: Sẵn sàng",
            font=ctk.CTkFont(size=12, weight="bold"),
            anchor="w",
        )
        self.lbl_status.grid(row=0, column=0, padx=(0, 18), sticky="w")
        self.lbl_summary = ctk.CTkLabel(
            summary,
            text="Chưa có dữ liệu thống kê.",
            font=ctk.CTkFont(size=12),
            text_color=("#475569", "#CBD5E1"),
            anchor="w",
            wraplength=600,
            justify="left",
        )
        self.lbl_summary.grid(row=0, column=1, sticky="w")

    def _add_field(self, parent, row: int, label_column: int, label: str, variable) -> None:
        ctk.CTkLabel(
            parent,
            text=label,
            font=ctk.CTkFont(size=11),
            anchor="w",
        ).grid(row=row, column=label_column, padx=(14, 6), pady=6, sticky="w")
        entry = ctk.CTkEntry(parent, textvariable=variable, width=84, height=30)
        entry.grid(row=row, column=label_column + 1, padx=(0, 10), pady=6, sticky="ew")
        self._input_widgets.append(entry)

    def _set_log_text(self, text: str) -> None:
        self.log_box.configure(state="normal")
        self.log_box.delete("1.0", "end")
        self.log_box.insert("end", text)
        self.log_box.configure(state="disabled")

    def _append_log(self, text: str) -> None:
        self.log_box.configure(state="normal")
        self.log_box.insert("end", text + "\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def _clear_log(self) -> None:
        if self._session and self._session.is_running:
            return
        self._set_log_text("Chưa có phiên ping. Nhập thông số rồi bấm 'Bắt đầu ping'.")
        self.progress.set(0)
        self.lbl_progress.configure(text="Sẵn sàng")
        self.lbl_status.configure(text="Trạng thái: Sẵn sàng")
        self.lbl_summary.configure(text="Chưa có dữ liệu thống kê.")

    def _on_mode_changed(self) -> None:
        """Enable settings that apply only to the selected mode/protocol."""
        if not hasattr(self, "entry_in_flight"):
            return
        running = bool(self._session and self._session.is_running)
        inputs_enabled = getattr(self, "_inputs_enabled", True)
        protocol = PROTOCOL_BY_LABEL.get(self.protocol_var.get(), self.protocol_var.get())
        enabled = self.mode_var.get() == PING_MODE_ASYNC and inputs_enabled and not running
        self.entry_in_flight.configure(state="normal" if enabled else "disabled")
        payload_enabled = (
            protocol in (PING_PROTOCOL_AUTO, PING_PROTOCOL_UDP)
            and inputs_enabled
            and not running
        )
        self.entry_udp_payload.configure(
            state="normal" if payload_enabled else "disabled"
        )
        protocol_hint = {
            PING_PROTOCOL_AUTO: (
                "Tự động sẽ thử ICMP, TCP rồi UDP DNS/53; payload chỉ dùng khi "
                "đến bước UDP."
            ),
            PING_PROTOCOL_ICMP: "Chỉ gửi ICMP.",
            PING_PROTOCOL_TCP: "Chỉ gửi TCP tới các cổng 53, 80, 443.",
            PING_PROTOCOL_UDP: (
                "Chỉ gửi truy vấn UDP DNS tới cổng 53; payload được đệm bằng "
                "EDNS(0) padding."
            ),
        }.get(protocol, "")
        if self.mode_var.get() == PING_MODE_ASYNC:
            mode_hint = "Gửi theo khoảng cách đã chọn, tối đa N yêu cầu cùng lúc; phản hồi có thể về không theo thứ tự."
        else:
            mode_hint = "Gửi 1 yêu cầu rồi đợi phản hồi hoặc timeout trước khi gửi lần kế tiếp."
        self.lbl_mode_hint.configure(text=f"{mode_hint} {protocol_hint}")

    def _on_protocol_changed(self, _value=None) -> None:
        """Refresh the explanation when the transport selector changes."""
        self._on_mode_changed()

    def _read_config(self) -> Dict[str, Any]:
        duration_text = self.duration_var.get().strip()
        duration = float(duration_text) if duration_text else 0.0
        mode = self.mode_var.get()
        protocol = PROTOCOL_BY_LABEL.get(self.protocol_var.get(), self.protocol_var.get())
        in_flight = (
            int(self.in_flight_var.get().strip())
            if mode == PING_MODE_ASYNC
            else PING_DEFAULT_IN_FLIGHT
        )
        udp_payload = (
            int(self.udp_payload_var.get().strip())
            if protocol in (PING_PROTOCOL_AUTO, PING_PROTOCOL_UDP)
            else UDP_PAYLOAD_DEFAULT_BYTES
        )
        return validate_ping_session_config(
            self.target_var.get(),
            int(self.count_var.get().strip()),
            duration,
            float(self.interval_var.get().strip()),
            int(self.timeout_var.get().strip()),
            mode,
            in_flight,
            protocol,
            udp_payload,
        )

    def _set_inputs_enabled(self, enabled: bool) -> None:
        self._inputs_enabled = enabled
        state = "normal" if enabled else "disabled"
        for widget in self._input_widgets:
            widget.configure(state=state)
        for widget in self._mode_widgets:
            widget.configure(state=state)
        self.btn_start.configure(state=state)
        self.btn_clear.configure(state=state)
        self._on_mode_changed()

    def _start_session(self) -> None:
        if self._session and self._session.is_running:
            return
        try:
            config = self._read_config()
        except (TypeError, ValueError) as exc:
            messagebox.showerror("Thông số chưa hợp lệ", str(exc), parent=self)
            return

        self._clear_log()
        mode_label = MODE_LABELS.get(config["mode"], config["mode"])
        protocol_label = PROTOCOL_LABELS.get(config["protocol"], config["protocol"])
        concurrency_text = (
            f" • tối đa {config['max_in_flight']} yêu cầu đồng thời"
            if config["mode"] == PING_MODE_ASYNC
            else ""
        )
        payload_text = (
            f" • payload UDP {config['udp_payload_size']} byte"
            if config["protocol"] in (PING_PROTOCOL_AUTO, PING_PROTOCOL_UDP)
            else ""
        )
        self._append_log(
            f"Bắt đầu: {config['target']} • {config['count']} lần • "
            f"mỗi {config['interval_s']:g}s • timeout {config['timeout_ms']}ms • "
            f"{mode_label}{concurrency_text} • {protocol_label}{payload_text}"
        )
        self._run_token += 1
        run_token = self._run_token
        self._session = PingSession(
            on_result=lambda result, token=run_token: self._queue_result(token, result),
            on_complete=lambda summary, token=run_token: self._queue_complete(token, summary),
            **config,
        )
        self._set_inputs_enabled(False)
        self.btn_stop.configure(state="normal")
        self.progress.set(0)
        self.lbl_progress.configure(text=f"0/{config['count']}")
        self.lbl_status.configure(text="Trạng thái: Đang ping...", text_color="#38BDF8")
        self.lbl_summary.configure(
            text=(
                f"Chế độ: {mode_label} • Giao thức: {protocol_label}"
                + (
                    f" • UDP payload {config['udp_payload_size']} byte"
                    if config["protocol"] in (PING_PROTOCOL_AUTO, PING_PROTOCOL_UDP)
                    else ""
                )
                + " • Đang chờ kết quả..."
            )
        )
        if not self._session.start():
            self._set_inputs_enabled(True)
            self.btn_stop.configure(state="disabled")
            self.lbl_status.configure(text="Trạng thái: Không thể khởi động", text_color="#EF4444")

    def _stop_session(self) -> None:
        if self._session and self._session.is_running:
            self._session.stop()
            self.btn_stop.configure(state="disabled")
            self.lbl_status.configure(text="Trạng thái: Đang dừng...", text_color="#F59E0B")

    def _queue_result(self, run_token: int, result: Dict[str, Any]) -> None:
        if self._closing or run_token != self._run_token:
            return
        try:
            self.after(0, lambda: self._handle_result(run_token, result))
        except Exception:
            pass

    def _handle_result(self, run_token: int, result: Dict[str, Any]) -> None:
        if self._closing or run_token != self._run_token:
            return
        session = self._session
        if not session:
            return
        index = result.get("index", 0)
        timestamp = datetime.fromtimestamp(result.get("timestamp", 0)).strftime("%H:%M:%S")
        latency = result.get("latency_ms")
        method = result.get("method", "-")
        if latency is None:
            line = f"#{index:04d}  {timestamp}  Timeout  [{method}]  ✗"
        else:
            line = f"#{index:04d}  {timestamp}  {latency:>4} ms  [{method}]  ✓"
        self._append_log(line)
        completed = result.get("completed_count", session.completed_count)
        self.progress.set(min(1.0, completed / max(1, session.requested_count)))
        self.lbl_progress.configure(text=f"{completed}/{session.requested_count}")

    def _queue_complete(self, run_token: int, summary: Dict[str, Any]) -> None:
        if self._closing or run_token != self._run_token:
            return
        try:
            self.after(0, lambda: self._handle_complete(run_token, summary))
        except Exception:
            pass

    def _handle_complete(self, run_token: int, summary: Dict[str, Any]) -> None:
        if self._closing or run_token != self._run_token:
            return
        reason_labels = {
            "count": "Đã đủ số lần ping",
            "duration": "Đã hết thời gian tối đa",
            "cancelled": "Đã dừng theo yêu cầu",
            "error": "Phiên gặp lỗi",
        }
        reason = summary.get("stop_reason", "count")
        completed = summary.get("completed_count", 0)
        requested = summary.get("requested_count", completed)
        self.lbl_status.configure(
            text=f"Trạng thái: {reason_labels.get(reason, reason)}",
            text_color="#10B981" if reason == "count" else "#F59E0B" if reason != "error" else "#EF4444",
        )
        self.lbl_progress.configure(text=f"{completed}/{requested}")
        self.progress.set(min(1.0, completed / max(1, requested)))

        min_ms = summary.get("min_ms")
        max_ms = summary.get("max_ms")
        avg_ms = summary.get("avg_ms")
        metrics = "—"
        if min_ms is not None:
            metrics = f"Min {min_ms} ms • Max {max_ms} ms • Avg {avg_ms} ms"
        self.lbl_summary.configure(
            text=(
                f"{summary.get('success_count', 0)}/{completed} thành công • "
                f"Mất {summary.get('loss_rate', 0)}% • {metrics} • "
                f"{summary.get('elapsed_s', 0)} giây • "
                f"{MODE_LABELS.get(summary.get('mode'), summary.get('mode', '-'))} • "
                f"{PROTOCOL_LABELS.get(summary.get('protocol'), summary.get('protocol', '-'))}"
                + (
                    f" • UDP payload {summary.get('udp_payload_size')} byte"
                    if summary.get("protocol") in (PING_PROTOCOL_AUTO, PING_PROTOCOL_UDP)
                    else ""
                )
            )
        )
        self._append_log(
            f"Kết thúc: {reason_labels.get(reason, reason)} — "
            f"{summary.get('success_count', 0)}/{completed} thành công, "
            f"mất {summary.get('loss_rate', 0)}%"
        )
        self._set_inputs_enabled(True)
        self.btn_stop.configure(state="disabled")

    def _close(self) -> None:
        self._closing = True
        self._run_token += 1
        if self._session and self._session.is_running:
            self._session.stop()
        if self._load_test_window is not None:
            try:
                self._load_test_window._close()
            except Exception:
                pass
        try:
            self.destroy()
        except Exception:
            pass
