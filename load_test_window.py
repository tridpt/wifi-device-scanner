"""Cửa sổ test chịu tải có kiểm soát cho thiết bị trong mạng LAN."""

from __future__ import annotations

import time
from datetime import datetime
from typing import Any, Dict, Optional

import customtkinter as ctk
from tkinter import messagebox

from ping_monitor import (
    LOAD_TEST_DEFAULT_DURATION_S,
    LOAD_TEST_DEFAULT_RATE_PPS,
    LOAD_TEST_MAX_DURATION_S,
    LOAD_TEST_MAX_RATE_PPS,
    LOAD_TEST_MIN_DURATION_S,
    LOAD_TEST_MIN_RATE_PPS,
    PING_DEFAULT_IN_FLIGHT,
    PING_MAX_IN_FLIGHT,
    PING_PROTOCOL_ICMP,
    PING_PROTOCOL_TCP,
    PING_PROTOCOL_UDP,
    UDP_PAYLOAD_DEFAULT_BYTES,
    UDP_PAYLOAD_MAX_BYTES,
    UDP_PAYLOAD_MIN_BYTES,
    LoadTestSession,
    validate_load_test_config,
)


PROTOCOL_LABELS = {
    PING_PROTOCOL_UDP: "UDP DNS (cổng 53)",
    PING_PROTOCOL_TCP: "TCP (cổng 53)",
    PING_PROTOCOL_ICMP: "ICMP",
}
PROTOCOL_BY_LABEL = {label: value for value, label in PROTOCOL_LABELS.items()}


class LoadTestWindow(ctk.CTkToplevel):
    """UI cho bài test tải LAN với tốc độ và thời gian được giới hạn."""

    def __init__(self, master, default_target: str = "192.168.1.1"):
        super().__init__(master)
        self.title("Test chịu tải LAN")
        self.geometry("820x720")
        self.minsize(740, 640)
        self.transient(master)

        self._closing = False
        self._session: Optional[LoadTestSession] = None
        self._run_token = 0
        self._inputs_enabled = True
        self._input_widgets = []
        self._shown_results = 0
        self._last_ui_update = 0.0

        self.target_var = ctk.StringVar(value=default_target or "192.168.1.1")
        self.rate_var = ctk.StringVar(value=str(int(LOAD_TEST_DEFAULT_RATE_PPS)))
        self.duration_var = ctk.StringVar(value=str(int(LOAD_TEST_DEFAULT_DURATION_S)))
        self.timeout_var = ctk.StringVar(value="800")
        self.payload_var = ctk.StringVar(value=str(UDP_PAYLOAD_DEFAULT_BYTES))
        self.in_flight_var = ctk.StringVar(value=str(PING_DEFAULT_IN_FLIGHT))
        self.protocol_var = ctk.StringVar(value=PROTOCOL_LABELS[PING_PROTOCOL_UDP])

        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self._close)
        self.after(80, self._focus_window)

    def set_target(self, target: str) -> bool:
        """Set a new target while idle."""
        target = str(target or "").strip()
        if not target or (self._session and self._session.is_running):
            return False
        self.target_var.set(target)
        self.title(f"Test chịu tải LAN - {target}")
        return True

    def _focus_window(self) -> None:
        try:
            self.lift()
            self.focus_force()
        except Exception:
            pass

    def _build_ui(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        hero = ctk.CTkFrame(
            self,
            fg_color=("#FEF3C7", "#451A03"),
            border_width=1,
            border_color="#F59E0B",
            corner_radius=12,
        )
        hero.grid(row=0, column=0, padx=16, pady=(16, 10), sticky="ew")
        ctk.CTkLabel(
            hero,
            text="🔥 Test chịu tải mạng nội bộ",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color=("#92400E", "#FDE68A"),
            anchor="w",
        ).pack(fill="x", padx=18, pady=(13, 2))
        ctk.CTkLabel(
            hero,
            text=(
                "Chỉ dùng cho thiết bị LAN bạn quản lý. Bài test gửi gói theo tốc độ "
                "giới hạn, vẫn thu phản hồi và có thể dừng bất cứ lúc nào."
            ),
            font=ctk.CTkFont(size=12),
            text_color=("#78350F", "#FDE68A"),
            anchor="w",
            wraplength=750,
            justify="left",
        ).pack(fill="x", padx=18, pady=(0, 13))

        form = ctk.CTkFrame(self, fg_color=("#F8FAFC", "#111827"), corner_radius=10)
        form.grid(row=1, column=0, padx=16, pady=(0, 10), sticky="ew")
        for column in (1, 3):
            form.grid_columnconfigure(column, weight=1)

        ctk.CTkLabel(
            form,
            text="Địa chỉ IPv4 nội bộ",
            font=ctk.CTkFont(size=12, weight="bold"),
            anchor="w",
        ).grid(row=0, column=0, padx=(14, 8), pady=(14, 6), sticky="w")
        self.entry_target = ctk.CTkEntry(
            form,
            textvariable=self.target_var,
            height=32,
            placeholder_text="Ví dụ: 192.168.1.1",
        )
        self.entry_target.grid(row=0, column=1, columnspan=3, padx=(0, 14), pady=(14, 6), sticky="ew")
        self._input_widgets.append(self.entry_target)

        self._add_field(form, 1, 0, "Tốc độ (gói/giây)", self.rate_var)
        self._add_field(form, 1, 2, "Thời gian (giây)", self.duration_var)
        self._add_field(form, 2, 0, "Timeout (ms)", self.timeout_var)
        self._add_field(form, 2, 2, "Payload UDP (byte)", self.payload_var)
        self.entry_payload = self._input_widgets[-1]

        ctk.CTkLabel(
            form,
            text="Giao thức",
            font=ctk.CTkFont(size=11, weight="bold"),
            anchor="w",
        ).grid(row=3, column=0, padx=(14, 6), pady=6, sticky="w")
        self.protocol_menu = ctk.CTkOptionMenu(
            form,
            variable=self.protocol_var,
            values=list(PROTOCOL_BY_LABEL),
            command=self._on_protocol_changed,
            height=30,
            font=ctk.CTkFont(size=11),
        )
        self.protocol_menu.grid(row=3, column=1, padx=(0, 10), pady=6, sticky="ew")
        self._input_widgets.append(self.protocol_menu)

        self._add_field(form, 3, 2, "Yêu cầu đồng thời", self.in_flight_var)
        self.entry_in_flight = self._input_widgets[-1]

        ctk.CTkLabel(
            form,
            text=(
                f"Giới hạn an toàn: {LOAD_TEST_MIN_RATE_PPS:g}-{LOAD_TEST_MAX_RATE_PPS:g} gói/giây, "
                f"{LOAD_TEST_MIN_DURATION_S:g}-{LOAD_TEST_MAX_DURATION_S:g} giây, "
                f"tối đa {PING_MAX_IN_FLIGHT} yêu cầu đồng thời. Payload UDP "
                f"{UDP_PAYLOAD_MIN_BYTES}-{UDP_PAYLOAD_MAX_BYTES} byte."
            ),
            font=ctk.CTkFont(size=11),
            text_color=("#64748B", "#94A3B8"),
            anchor="w",
            wraplength=760,
            justify="left",
        ).grid(row=4, column=0, columnspan=4, padx=14, pady=(4, 12), sticky="w")

        self._on_protocol_changed(self.protocol_var.get())

        actions = ctk.CTkFrame(self, fg_color="transparent")
        actions.grid(row=3, column=0, padx=16, pady=(0, 8), sticky="ew")
        actions.grid_columnconfigure(3, weight=1)

        self.btn_start = ctk.CTkButton(
            actions,
            text="▶ Bắt đầu test",
            width=145,
            height=34,
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#D97706",
            hover_color="#B45309",
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
            width=175,
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
            text="Nhật ký test (tối đa 200 dòng hiển thị)",
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
        self._set_log_text("Chưa có bài test. Nhập thông số rồi bấm 'Bắt đầu test'.")

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
            wraplength=620,
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
        self._shown_results = 0
        self._set_log_text("Chưa có bài test. Nhập thông số rồi bấm 'Bắt đầu test'.")
        self.progress.set(0)
        self.lbl_progress.configure(text="Sẵn sàng")
        self.lbl_status.configure(text="Trạng thái: Sẵn sàng")
        self.lbl_summary.configure(text="Chưa có dữ liệu thống kê.")

    def _on_protocol_changed(self, value=None) -> None:
        protocol = PROTOCOL_BY_LABEL.get(value or self.protocol_var.get(), value)
        enabled = protocol == PING_PROTOCOL_UDP and self._inputs_enabled
        if hasattr(self, "entry_payload"):
            self.entry_payload.configure(state="normal" if enabled else "disabled")

    def _read_config(self) -> Dict[str, Any]:
        protocol = PROTOCOL_BY_LABEL.get(self.protocol_var.get(), self.protocol_var.get())
        payload = (
            int(self.payload_var.get().strip())
            if protocol == PING_PROTOCOL_UDP
            else UDP_PAYLOAD_DEFAULT_BYTES
        )
        return validate_load_test_config(
            self.target_var.get(),
            float(self.rate_var.get().strip()),
            float(self.duration_var.get().strip()),
            int(self.timeout_var.get().strip()),
            protocol,
            payload,
            int(self.in_flight_var.get().strip()),
        )

    def _set_inputs_enabled(self, enabled: bool) -> None:
        self._inputs_enabled = enabled
        state = "normal" if enabled else "disabled"
        for widget in self._input_widgets:
            widget.configure(state=state)
        self.btn_start.configure(state=state)
        self.btn_clear.configure(state=state)
        self._on_protocol_changed()

    def _start_test(self) -> None:
        if self._session and self._session.is_running:
            return
        try:
            config = self._read_config()
        except (TypeError, ValueError) as exc:
            messagebox.showerror("Thông số chưa hợp lệ", str(exc), parent=self)
            return

        protocol_label = PROTOCOL_LABELS[config["protocol"]]
        confirm = messagebox.askyesno(
            "Xác nhận test chịu tải",
            (
                f"Gửi khoảng {config['planned_count']:,} gói tới {config['target']}\n"
                f"Tốc độ {config['rate_pps']:g} gói/giây trong {config['duration_s']:g} giây\n"
                f"Giao thức: {protocol_label}\n\n"
                "Chỉ tiếp tục nếu đây là thiết bị trong mạng LAN của bạn."
            ),
            parent=self,
        )
        if not confirm:
            return

        self._clear_log()
        self._shown_results = 0
        self._run_token += 1
        run_token = self._run_token
        self._append_log(
            f"Bắt đầu: {config['target']} • {config['rate_pps']:g} gói/s • "
            f"{config['duration_s']:g}s • {protocol_label} • "
            f"payload {config['udp_payload_size']} byte"
        )
        self._session = LoadTestSession(
            target=config["target"],
            rate_pps=config["rate_pps"],
            duration_s=config["duration_s"],
            timeout_ms=config["timeout_ms"],
            protocol=config["protocol"],
            udp_payload_size=config["udp_payload_size"],
            max_in_flight=config["max_in_flight"],
            on_result=lambda result, token=run_token: self._queue_result(token, result),
            on_complete=lambda summary, token=run_token: self._queue_complete(token, summary),
        )
        self._set_inputs_enabled(False)
        self.btn_stop.configure(state="normal")
        self.progress.set(0)
        self.lbl_progress.configure(text=f"0/{config['planned_count']}")
        self.lbl_status.configure(text="Trạng thái: Đang test...", text_color="#F59E0B")
        self.lbl_summary.configure(text="Đang gửi và thu phản hồi...")
        if not self._session.start():
            self._set_inputs_enabled(True)
            self.btn_stop.configure(state="disabled")

    def _stop_test(self) -> None:
        if self._session and self._session.is_running:
            self._session.stop()
            self.btn_stop.configure(state="disabled")
            self.lbl_status.configure(text="Trạng thái: Đang dừng...", text_color="#F59E0B")

    def _queue_result(self, run_token: int, result: Dict[str, Any]) -> None:
        if self._closing or run_token != self._run_token:
            return
        # At high rates, coalesce counter updates after the visible log cap so
        # thousands of callbacks do not accumulate in Tk's event queue.
        now = time.monotonic()
        if self._shown_results >= 200 and now - self._last_ui_update < 0.1:
            return
        self._last_ui_update = now
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
        if self._shown_results < 200:
            timestamp = datetime.fromtimestamp(result.get("timestamp", 0)).strftime("%H:%M:%S")
            latency = result.get("latency_ms")
            method = result.get("method", "-")
            line = (
                f"#{result.get('index', 0):05d}  {timestamp}  "
                f"{latency:>4} ms  [{method}]  ✓"
                if latency is not None
                else f"#{result.get('index', 0):05d}  {timestamp}  Timeout  [{method}]  ✗"
            )
            self._append_log(line)
            self._shown_results += 1
            if self._shown_results == 200:
                self._append_log("… các dòng tiếp theo được ẩn để giữ giao diện mượt …")
        elapsed = max(0.0, time.monotonic() - (session.started_at or time.monotonic()))
        self.progress.set(min(1.0, elapsed / max(0.001, session.duration_s)))
        self.lbl_progress.configure(
            text=f"{result.get('sent_count', session.sent_count)} đã gửi / "
            f"{result.get('completed_count', session.completed_count)} đã nhận"
        )

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
            "duration": "Đã hết thời gian test",
            "count": "Đã đủ số gói dự kiến",
            "cancelled": "Đã dừng theo yêu cầu",
            "error": "Bài test gặp lỗi",
        }
        reason = summary.get("stop_reason", "duration")
        sent = summary.get("sent_count", 0)
        completed = summary.get("completed_count", 0)
        success = summary.get("success_count", 0)
        self.progress.set(1 if reason in ("duration", "count") else min(1.0, completed / max(1, sent)))
        self.lbl_progress.configure(text=f"{sent} đã gửi / {completed} đã nhận")
        self.lbl_status.configure(
            text=f"Trạng thái: {reason_labels.get(reason, reason)}",
            text_color="#10B981" if reason in ("duration", "count") else "#F59E0B",
        )
        metrics = "—"
        if summary.get("min_ms") is not None:
            metrics = (
                f"Min {summary['min_ms']} ms • Max {summary['max_ms']} ms • "
                f"Avg {summary['avg_ms']} ms"
            )
        self.lbl_summary.configure(
            text=(
                f"{success}/{completed} phản hồi • Mất {summary.get('loss_rate', 0)}% • "
                f"{metrics} • tốc độ thực {summary.get('actual_rate_pps', 0)} gói/s"
            )
        )
        self._append_log(
            f"Kết thúc: {reason_labels.get(reason, reason)} — "
            f"{success}/{completed} phản hồi, mất {summary.get('loss_rate', 0)}%"
        )
        self._set_inputs_enabled(True)
        self.btn_stop.configure(state="disabled")

    def _close(self) -> None:
        self._closing = True
        self._run_token += 1
        if self._session and self._session.is_running:
            self._session.stop()
        try:
            self.destroy()
        except Exception:
            pass
