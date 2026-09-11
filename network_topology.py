"""
network_topology.py - Sơ đồ mạng tương tác trực quan (Interactive Network Topology Map).
Thiết kế chuyên nghiệp, thông minh, hỗ trợ mạng lớn (50 - 100+ thiết bị) không bị rối.
- Cơ chế Multi-Orbit (Xếp thành nhiều tầng quỹ đạo đồng tâm), không bao giờ đè node lên nhau.
- Chế độ Smart Labels: Tự động ẩn nhãn khi đông thiết bị, chỉ hiện nhãn nổi (Tooltip Card) khi hover / click.
- Tự động làm mờ đường dây mạng để chống hiệu ứng nan hoa xe đạp rối mắt, phát sáng đường dây khi rê chuột.
- Bộ lọc danh mục ngay trên thanh công cụ để lọc xem riêng từng nhóm thiết bị.
"""

import math
import tkinter as tk
from typing import Dict, Any, List, Optional, Callable
import customtkinter as ctk

# Bảng màu sắc & biểu tượng danh mục thiết bị
CATEGORY_CONFIG = {
    "router": {"icon": "🌐", "bg": "#0284C7", "border": "#38BDF8", "name": "Router / Gateway"},
    "pc": {"icon": "💻", "bg": "#2563EB", "border": "#60A5FA", "name": "Máy tính / Laptop"},
    "mobile": {"icon": "📱", "bg": "#7C3AED", "border": "#A78BFA", "name": "Điện thoại / Di động"},
    "camera": {"icon": "📷", "bg": "#D97706", "border": "#FBBF24", "name": "Camera quan sát"},
    "iot": {"icon": "⚡", "bg": "#059669", "border": "#34D399", "name": "Thiết bị thông minh / IoT"},
    "private": {"icon": "🔒", "bg": "#4F46E5", "border": "#818CF8", "name": "MAC Riêng tư"},
    "system": {"icon": "📡", "bg": "#475569", "border": "#94A3B8", "name": "Thiết bị mạng"},
    "unknown": {"icon": "❓", "bg": "#334155", "border": "#64748B", "name": "Chưa rõ loại"},
}


class TopologyNode:
    """Mô hình dữ liệu cho 1 điểm node trên sơ đồ mạng."""

    def __init__(self, device: Dict[str, Any], x: float = 0.0, y: float = 0.0):
        self.device = device
        self.ip = device.get("ip", "")
        self.mac = device.get("mac", "")
        self.name = device.get("name", "—")
        self.vendor = device.get("vendor", "Chưa rõ")
        self.category = device.get("category", "unknown")
        self.is_gateway = device.get("is_gateway", False)
        self.is_self = device.get("is_self", False)
        self.is_random_mac = device.get("is_random_mac", False)
        self.rtt_ms = device.get("rtt_ms", 0)

        # Cấu hình hiển thị theo danh mục
        cfg = CATEGORY_CONFIG.get(self.category, CATEGORY_CONFIG["unknown"])
        if self.is_gateway:
            cfg = CATEGORY_CONFIG["router"]
        elif self.is_self:
            cfg = {"icon": "💻", "bg": "#15803D", "border": "#4ADE80", "name": "Máy tính của bạn"}

        self.icon = cfg["icon"]
        self.bg_color = cfg["bg"]
        self.border_color = cfg["border"]
        self.type_name = cfg["name"]

        # Kích thước & Tọa độ trên Canvas
        if self.is_gateway:
            self.radius = 42.0
        elif self.is_self:
            self.radius = 30.0
        else:
            self.radius = 24.0
        self.x = x
        self.y = y


class NetworkTopologyView(ctk.CTkFrame):
    """Giao diện Sơ đồ cấu trúc mạng tương tác (Network Topology Map View)."""

    def __init__(
        self,
        master,
        on_open_port_scan: Optional[Callable[[Dict[str, Any]], None]] = None,
        on_open_mac_blocker: Optional[Callable[[Dict[str, Any]], None]] = None,
        on_open_wol: Optional[Callable[[Dict[str, Any]], None]] = None,
        **kwargs,
    ):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.on_open_port_scan = on_open_port_scan
        self.on_open_mac_blocker = on_open_mac_blocker
        self.on_open_wol = on_open_wol

        self.all_devices_raw: List[Dict[str, Any]] = []
        self.nodes: Dict[str, TopologyNode] = {}
        self.center_node: Optional[TopologyNode] = None
        self.selected_node: Optional[TopologyNode] = None
        self.hovered_node: Optional[TopologyNode] = None

        # Trạng thái kéo thả chuột & Pan Canvas
        self.dragged_node: Optional[TopologyNode] = None
        self.drag_start_x = 0.0
        self.drag_start_y = 0.0
        self.is_panning = False
        self.pan_start_x = 0.0
        self.pan_start_y = 0.0

        # Tùy chọn hiển thị & Phóng to
        self.current_filter = "Tất cả thiết bị"
        self.force_show_all_labels = False
        self.zoom_scale = 1.0

        self._build_ui()

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # --- 1. THANH ĐIỀU KHIỂN SƠ ĐỒ (TOOLBAR) ---
        toolbar = ctk.CTkFrame(self, fg_color=("#E5E7EB", "#1F2937"), corner_radius=8, height=44)
        toolbar.grid(row=0, column=0, padx=5, pady=(5, 5), sticky="ew")
        toolbar.grid_columnconfigure(2, weight=1)

        # Tiêu đề & Đếm số node
        title_box = ctk.CTkFrame(toolbar, fg_color="transparent")
        title_box.grid(row=0, column=0, padx=(12, 6), pady=6, sticky="w")

        lbl_title = ctk.CTkLabel(
            title_box,
            text="🕸️ Sơ đồ mạng",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=("#111827", "#F9FAFB"),
        )
        lbl_title.pack(side="left")

        self.lbl_node_count = ctk.CTkLabel(
            title_box,
            text="(0 thiết bị)",
            font=ctk.CTkFont(size=12),
            text_color=("#6B7280", "#9CA3AF"),
        )
        self.lbl_node_count.pack(side="left", padx=(4, 0))

        # Bộ lọc danh mục ngay trên Toolbar
        filter_box = ctk.CTkFrame(toolbar, fg_color="transparent")
        filter_box.grid(row=0, column=1, padx=6, pady=6, sticky="w")

        ctk.CTkLabel(filter_box, text="Lọc:", font=ctk.CTkFont(size=11), text_color=("#4B5563", "#9CA3AF")).pack(side="left", padx=(0, 4))
        self.opt_category_filter = ctk.CTkOptionMenu(
            filter_box,
            values=["Tất cả thiết bị", "Chỉ Router & Máy tính", "Chỉ Điện thoại", "Chỉ Camera", "Chỉ Thiết bị IoT", "Chỉ MAC Riêng tư"],
            command=self._on_filter_changed,
            height=28,
            width=175,
            font=ctk.CTkFont(size=11),
        )
        self.opt_category_filter.set("Tất cả thiết bị")
        self.opt_category_filter.pack(side="left")

        # Nút chuyển hiển thị nhãn (Checkbox)
        self.chk_labels = ctk.CTkCheckBox(
            toolbar,
            text="Hiện tất cả nhãn",
            command=self._toggle_labels,
            font=ctk.CTkFont(size=11),
            height=28,
        )
        self.chk_labels.grid(row=0, column=2, padx=10, sticky="w")

        # Các nút zoom & sắp xếp góc phải
        btn_box = ctk.CTkFrame(toolbar, fg_color="transparent")
        btn_box.grid(row=0, column=3, padx=10, pady=6, sticky="e")

        btn_zoom_in = ctk.CTkButton(
            btn_box,
            text="🔍+ Phóng to",
            font=ctk.CTkFont(size=11, weight="bold"),
            width=85,
            height=28,
            fg_color="#0284C7",
            hover_color="#0369A1",
            command=self.zoom_in,
        )
        btn_zoom_in.pack(side="left", padx=2)

        btn_zoom_out = ctk.CTkButton(
            btn_box,
            text="🔍- Thu nhỏ",
            font=ctk.CTkFont(size=11),
            width=80,
            height=28,
            fg_color=("#D1D5DB", "#374151"),
            text_color=("#111827", "#F9FAFB"),
            hover_color=("#9CA3AF", "#4B5563"),
            command=self.zoom_out,
        )
        btn_zoom_out.pack(side="left", padx=2)

        btn_radial = ctk.CTkButton(
            btn_box,
            text="🔄 Bố cục quỹ đạo",
            font=ctk.CTkFont(size=11, weight="bold"),
            width=115,
            height=28,
            fg_color="#2563EB",
            hover_color="#1D4ED8",
            command=self.reset_to_radial_layout,
        )
        btn_radial.pack(side="left", padx=2)

        btn_group = ctk.CTkButton(
            btn_box,
            text="🏷️ Phân cụm",
            font=ctk.CTkFont(size=11),
            width=85,
            height=28,
            fg_color=("#D1D5DB", "#374151"),
            text_color=("#111827", "#F9FAFB"),
            hover_color=("#9CA3AF", "#4B5563"),
            command=self.reset_to_grouped_layout,
        )
        btn_group.pack(side="left", padx=2)

        btn_center = ctk.CTkButton(
            btn_box,
            text="🎯 Vừa khung",
            font=ctk.CTkFont(size=11),
            width=80,
            height=28,
            fg_color=("#D1D5DB", "#374151"),
            text_color=("#111827", "#F9FAFB"),
            hover_color=("#9CA3AF", "#4B5563"),
            command=self.zoom_reset,
        )
        btn_center.pack(side="left", padx=2)

        # --- 2. KHUNG CHÍNH CHỨA CANVAS VÀ PANEL THÔNG TIN ---
        main_body = ctk.CTkFrame(self, fg_color="transparent")
        main_body.grid(row=1, column=0, padx=5, pady=(0, 5), sticky="nsew")
        main_body.grid_columnconfigure(0, weight=1)
        main_body.grid_rowconfigure(0, weight=1)

        # Canvas vẽ đồ họa
        self.canvas_container = ctk.CTkFrame(main_body, fg_color="#090D16", corner_radius=8)
        self.canvas_container.grid(row=0, column=0, sticky="nsew")
        self.canvas_container.grid_columnconfigure(0, weight=1)
        self.canvas_container.grid_rowconfigure(0, weight=1)

        self.canvas = tk.Canvas(
            self.canvas_container,
            bg="#090D16",
            bd=0,
            highlightthickness=0,
            relief="ridge",
        )
        self.canvas.grid(row=0, column=0, sticky="nsew")

        # Đăng ký các sự kiện chuột tương tác
        self.canvas.bind("<Configure>", lambda e: self._on_canvas_resize())
        self.canvas.bind("<ButtonPress-1>", self._on_mouse_down)
        self.canvas.bind("<B1-Motion>", self._on_mouse_drag)
        self.canvas.bind("<ButtonRelease-1>", self._on_mouse_up)
        self.canvas.bind("<Motion>", self._on_mouse_hover)
        self.canvas.bind("<Double-Button-1>", self._on_double_click)
        self.canvas.bind("<MouseWheel>", self._on_mouse_wheel)

        # --- 3. PANEL THÔNG TIN THIẾT BỊ ĐƯỢC CHỌN (SIDE CARD CỠ LỚN) ---
        self.detail_card = ctk.CTkFrame(
            main_body,
            width=290,
            fg_color=("#FFFFFF", "#111827"),
            border_width=1,
            border_color="#1E293B",
            corner_radius=8,
        )
        self.detail_card.grid(row=0, column=1, padx=(8, 0), sticky="nsew")
        self.detail_card.grid_propagate(False)

        self._build_detail_card()

    def _build_detail_card(self):
        """Khung chi tiết bên phải to rõ, sắc nét khi nhấp vào 1 node trên sơ đồ."""
        self.detail_card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            self.detail_card,
            text="📌 Thông Tin Thiết Bị",
            font=ctk.CTkFont(size=15, weight="bold"),
            anchor="w",
        ).pack(padx=16, pady=(16, 6), fill="x")

        # Icon to & Tên thiết bị
        self.lbl_card_icon = ctk.CTkLabel(self.detail_card, text="🌐", font=ctk.CTkFont(size=44))
        self.lbl_card_icon.pack(pady=(6, 2))

        self.lbl_card_name = ctk.CTkLabel(
            self.detail_card,
            text="Chưa chọn thiết bị",
            font=ctk.CTkFont(size=14, weight="bold"),
            wraplength=260,
        )
        self.lbl_card_name.pack(padx=12, pady=2)

        self.lbl_card_role = ctk.CTkLabel(
            self.detail_card,
            text="Bấm hoặc rê chuột vào một điểm node trên sơ đồ",
            font=ctk.CTkFont(size=12),
            text_color="#94A3B8",
            wraplength=260,
        )
        self.lbl_card_role.pack(padx=12, pady=(0, 10))

        # Khung thông số
        spec_box = ctk.CTkFrame(self.detail_card, fg_color=("#F3F4F6", "#0F172A"), corner_radius=8)
        spec_box.pack(padx=12, pady=6, fill="x")

        self.lbl_spec_ip = self._create_spec_row(spec_box, "Địa chỉ IP:", "--")
        self.lbl_spec_mac = self._create_spec_row(spec_box, "Địa chỉ MAC:", "--")
        self.lbl_spec_vendor = self._create_spec_row(spec_box, "Nhà sản xuất:", "--")
        self.lbl_spec_rtt = self._create_spec_row(spec_box, "Độ trễ LAN:", "--")

        # Nút hành động nhanh to rõ
        action_label = ctk.CTkLabel(self.detail_card, text="⚡ Thao tác nhanh:", font=ctk.CTkFont(size=12, weight="bold"), anchor="w")
        action_label.pack(padx=16, pady=(14, 6), fill="x")

        self.btn_card_port = ctk.CTkButton(
            self.detail_card,
            text="🔍 Soi Cổng Dịch Vụ (Port Scan)",
            font=ctk.CTkFont(size=12, weight="bold"),
            height=36,
            fg_color="#0284C7",
            hover_color="#0369A1",
            state="disabled",
            command=self._on_click_port_scan,
        )
        self.btn_card_port.pack(padx=12, pady=3, fill="x")

        self.btn_card_block = ctk.CTkButton(
            self.detail_card,
            text="🚫 Trợ Lý Chặn MAC Trên Modem",
            font=ctk.CTkFont(size=12, weight="bold"),
            height=36,
            fg_color="#EF4444",
            hover_color="#DC2626",
            state="disabled",
            command=self._on_click_mac_blocker,
        )
        self.btn_card_block.pack(padx=12, pady=3, fill="x")

        self.btn_card_wol = ctk.CTkButton(
            self.detail_card,
            text="⚡ Đánh Thức Từ Xa (WoL)",
            font=ctk.CTkFont(size=12, weight="bold"),
            height=36,
            fg_color="#D97706",
            hover_color="#B45309",
            state="disabled",
            command=self._on_click_wol,
        )
        self.btn_card_wol.pack(padx=12, pady=3, fill="x")

        # Gợi ý
        hint_label = ctk.CTkLabel(
            self.detail_card,
            text="💡 Mẹo: Lăn chuột để Phóng to / Thu nhỏ. Kéo nền canvas để di chuyển bản đồ.",
            font=ctk.CTkFont(size=11),
            text_color="#64748B",
            wraplength=260,
            justify="left",
        )
        hint_label.pack(padx=14, pady=(14, 10), fill="x", side="bottom")

    def _create_spec_row(self, parent, label: str, default_val: str):
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", padx=10, pady=5)
        ctk.CTkLabel(row, text=label, font=ctk.CTkFont(size=12), text_color="#64748B").pack(side="left")
        val_lbl = ctk.CTkLabel(row, text=default_val, font=ctk.CTkFont(size=12, weight="bold"), anchor="e")
        val_lbl.pack(side="right")
        return val_lbl

    def _toggle_labels(self):
        self.force_show_all_labels = (self.chk_labels.get() == 1)
        self._render()

    def _on_filter_changed(self, choice: str):
        self.current_filter = choice
        self.reset_to_radial_layout()

    def _matches_filter(self, node: TopologyNode) -> bool:
        """Kiểm tra xem node có phù hợp với bộ lọc trên toolbar không."""
        if node.is_gateway:
            return True
        flt = self.current_filter
        if flt == "Chỉ Router & Máy tính":
            return node.is_self or node.category == "pc"
        if flt == "Chỉ Điện thoại":
            return node.category in ("mobile", "private")
        if flt == "Chỉ Camera":
            return node.category == "camera"
        if flt == "Chỉ Thiết bị IoT":
            return node.category == "iot"
        if flt == "Chỉ MAC Riêng tư":
            return node.is_random_mac
        return True

    def update_devices(self, devices: List[Dict[str, Any]], auto_layout: bool = True):
        """Cập nhật dữ liệu thiết bị từ scanner và đồng bộ hóa các điểm node."""
        self.all_devices_raw = devices or []
        if not devices:
            self.nodes.clear()
            self.center_node = None
            self.selected_node = None
            self.lbl_node_count.configure(text="(0 thiết bị)")
            self._render()
            return

        current_ips = {d.get("ip", ""): d for d in devices if d.get("ip")}

        removed_ips = [ip for ip in self.nodes if ip not in current_ips]
        for ip in removed_ips:
            del self.nodes[ip]

        w = max(self.canvas.winfo_width(), 600)
        h = max(self.canvas.winfo_height(), 450)
        cx, cy = w / 2.0, h / 2.0

        for ip, dev in current_ips.items():
            if ip in self.nodes:
                self.nodes[ip].device = dev
            else:
                self.nodes[ip] = TopologyNode(dev, x=cx, y=cy)

        self.center_node = None
        for node in self.nodes.values():
            if node.is_gateway:
                self.center_node = node
                break

        if not self.center_node:
            for node in self.nodes.values():
                if node.ip.endswith(".1"):
                    node.is_gateway = True
                    self.center_node = node
                    break

        self.lbl_node_count.configure(text=f"({len(self.nodes)} thiết bị)")

        if auto_layout:
            self.reset_to_radial_layout()
        else:
            self._render()

    def zoom_in(self, factor: float = 1.18, center_x: Optional[float] = None, center_y: Optional[float] = None):
        """Phóng to toàn bộ sơ đồ mạng."""
        self._zoom(factor, center_x, center_y)

    def zoom_out(self, factor: float = 0.85, center_x: Optional[float] = None, center_y: Optional[float] = None):
        """Thu nhỏ toàn bộ sơ đồ mạng."""
        self._zoom(factor, center_x, center_y)

    def zoom_reset(self):
        """Khôi phục tỉ lệ chuẩn và căn giữa sơ đồ."""
        self.zoom_scale = 1.0
        self.reset_to_radial_layout()

    def _zoom(self, factor: float, center_x: Optional[float] = None, center_y: Optional[float] = None):
        """Thực hiện biến đổi co giãn tọa độ và kích thước node."""
        new_scale = getattr(self, "zoom_scale", 1.0) * factor
        if new_scale < 0.4 or new_scale > 3.5:
            return
        self.zoom_scale = new_scale

        w = max(self.canvas.winfo_width(), 200)
        h = max(self.canvas.winfo_height(), 200)
        cx = center_x if center_x is not None else (w / 2.0)
        cy = center_y if center_y is not None else (h / 2.0)

        for node in self.nodes.values():
            node.x = cx + (node.x - cx) * factor
            node.y = cy + (node.y - cy) * factor
            node.radius = max(18.0, min(node.radius * (factor ** 0.4), 60.0))

        self._render()

    def _on_mouse_wheel(self, event):
        """Lăn chuột để Phóng to / Thu nhỏ sơ đồ mạng mượt mà."""
        if event.delta > 0:
            self.zoom_in(factor=1.12, center_x=event.x, center_y=event.y)
        else:
            self.zoom_out(factor=0.89, center_x=event.x, center_y=event.y)

    def reset_to_radial_layout(self):
        """
        Sắp xếp theo các tầng quỹ đạo đồng tâm (Multi-Orbit Concentric Layout).
        Tận dụng toàn bộ màn hình ngang (Elliptical Orbits) để các node to rõ, thoáng đãng.
        """
        w = self.canvas.winfo_width()
        h = self.canvas.winfo_height()
        if w < 200 or h < 200:
            return

        cx, cy = w / 2.0, h / 2.0
        self.zoom_scale = 1.0

        if self.center_node:
            self.center_node.x = cx
            self.center_node.y = cy
            self.center_node.radius = 42.0

        active_nodes = [n for n in self.nodes.values() if n != self.center_node and self._matches_filter(n)]
        if not active_nodes:
            self._render()
            return

        def sort_priority(n: TopologyNode):
            if n.is_self:
                return -1
            order = {"pc": 1, "mobile": 2, "camera": 3, "iot": 4, "private": 5}
            return order.get(n.category, 9)

        active_nodes.sort(key=sort_priority)
        total = len(active_nodes)

        # Kích thước node to rõ, sắc nét
        node_radius = 24.0 if total > 40 else (28.0 if total > 20 else 34.0)
        for n in active_nodes:
            if n.is_self:
                n.radius = 30.0
            else:
                n.radius = node_radius

        # Tính toán bán kính quỹ đạo hình Elip tương thích theo màn hình ngang rộng
        rx_base = (w / 2.0) * 0.88
        ry_base = (h / 2.0) * 0.86

        if total <= 14:
            rings = [(active_nodes, rx_base * 0.65, ry_base * 0.65, 0.0)]
        elif total <= 30:
            r1 = active_nodes[:10]
            r2 = active_nodes[10:]
            rings = [
                (r1, rx_base * 0.45, ry_base * 0.45, 0.0),
                (r2, rx_base * 0.85, ry_base * 0.85, math.pi / 10),
            ]
        elif total <= 55:
            r1 = active_nodes[:10]
            r2 = active_nodes[10:26]
            r3 = active_nodes[26:]
            rings = [
                (r1, rx_base * 0.35, ry_base * 0.35, 0.0),
                (r2, rx_base * 0.62, ry_base * 0.62, math.pi / 12),
                (r3, rx_base * 0.90, ry_base * 0.90, math.pi / 18),
            ]
        else:
            # Dành cho mạng lớn (như 77 máy trong thực tế): 4 vòng quỹ đạo thoáng đãng
            r1 = active_nodes[:10]
            r2 = active_nodes[10:26]
            r3 = active_nodes[26:48]
            r4 = active_nodes[48:]
            rings = [
                (r1, rx_base * 0.30, ry_base * 0.30, 0.0),
                (r2, rx_base * 0.52, ry_base * 0.52, math.pi / 12),
                (r3, rx_base * 0.74, ry_base * 0.74, math.pi / 18),
                (r4, rx_base * 0.95, ry_base * 0.95, math.pi / 24),
            ]

        for ring_nodes, rx, ry, phase in rings:
            cnt = len(ring_nodes)
            if cnt == 0:
                continue
            step = (2 * math.pi) / cnt
            for i, node in enumerate(ring_nodes):
                ang = -math.pi / 2.0 + phase + i * step
                node.x = cx + rx * math.cos(ang)
                node.y = cy + ry * math.sin(ang)

        self._render()

    def reset_to_grouped_layout(self):
        """Sắp xếp các thiết bị phân cụm theo 4 góc phần tư độc lập."""
        w = self.canvas.winfo_width()
        h = self.canvas.winfo_height()
        if w < 200 or h < 200:
            return

        cx, cy = w / 2.0, h / 2.0
        self.zoom_scale = 1.0

        if self.center_node:
            self.center_node.x = cx
            self.center_node.y = cy
            self.center_node.radius = 42.0

        active_nodes = [n for n in self.nodes.values() if n != self.center_node and self._matches_filter(n)]
        if not active_nodes:
            self._render()
            return

        total = len(active_nodes)
        node_radius = 24.0 if total > 40 else (28.0 if total > 20 else 34.0)
        for n in active_nodes:
            if n.is_self:
                n.radius = 30.0
            else:
                n.radius = node_radius

        groups: Dict[str, List[TopologyNode]] = {
            "pc": [],
            "mobile": [],
            "camera": [],
            "iot": [],
        }

        for n in active_nodes:
            if n.is_self or n.category == "pc":
                groups["pc"].append(n)
            elif n.category in ("mobile", "private"):
                groups["mobile"].append(n)
            elif n.category == "camera":
                groups["camera"].append(n)
            else:
                groups["iot"].append(n)

        quadrants = [
            ("pc", -math.pi * 0.75, groups["pc"]),
            ("mobile", -math.pi * 0.25, groups["mobile"]),
            ("camera", math.pi * 0.75, groups["camera"]),
            ("iot", math.pi * 0.25, groups["iot"]),
        ]

        rx_base = (w / 2.0) * 0.88
        ry_base = (h / 2.0) * 0.86

        for _, base_angle, group_nodes in quadrants:
            cnt = len(group_nodes)
            if cnt == 0:
                continue

            if cnt > 12:
                sub_r1 = group_nodes[:cnt // 2]
                sub_r2 = group_nodes[cnt // 2:]
                sub_rings = [(sub_r1, rx_base * 0.52, ry_base * 0.52), (sub_r2, rx_base * 0.88, ry_base * 0.88)]
            else:
                sub_rings = [(group_nodes, rx_base * 0.70, ry_base * 0.70)]

            for sub_nodes, r_x, r_y in sub_rings:
                s_cnt = len(sub_nodes)
                span = math.pi * 0.38
                step = span / max(s_cnt - 1, 1) if s_cnt > 1 else 0
                start = base_angle - (span / 2.0)
                for idx, node in enumerate(sub_nodes):
                    ang = start + (idx * step) if s_cnt > 1 else base_angle
                    node.x = cx + r_x * math.cos(ang)
                    node.y = cy + r_y * math.sin(ang)

        self._render()

    def center_view(self):
        """Căn chỉnh trọng tâm toàn bộ sơ đồ về giữa Canvas."""
        if not self.nodes:
            return
        w = self.canvas.winfo_width()
        h = self.canvas.winfo_height()
        if w < 100 or h < 100:
            return

        visible = [n for n in self.nodes.values() if self._matches_filter(n)]
        if not visible:
            return

        avg_x = sum(n.x for n in visible) / len(visible)
        avg_y = sum(n.y for n in visible) / len(visible)

        shift_x = (w / 2.0) - avg_x
        shift_y = (h / 2.0) - avg_y

        for n in self.nodes.values():
            n.x += shift_x
            n.y += shift_y

        self._render()

    def _render(self):
        """Vẽ lại toàn bộ Canvas đồ họa một cách tinh tế, thoáng đãng."""
        self.canvas.delete("all")
        w = self.canvas.winfo_width()
        h = self.canvas.winfo_height()
        if w < 100 or h < 100:
            return

        visible_nodes = [n for n in self.nodes.values() if self._matches_filter(n)]
        total_visible = len(visible_nodes)

        # 1. Vẽ lưới vi mô chìm (Micro Grid Dots)
        grid_step = 44
        for gx in range(0, w, grid_step):
            for gy in range(0, h, grid_step):
                self.canvas.create_oval(gx - 1, gy - 1, gx + 1, gy + 1, fill="#131B2A", outline="")

        # 2. Vẽ vòng sóng tỏa sáng từ Router trung tâm (Translucent Elliptical Radii)
        if self.center_node:
            cx, cy = self.center_node.x, self.center_node.y
            rx_base = (w / 2.0) * 0.88 * getattr(self, "zoom_scale", 1.0)
            ry_base = (h / 2.0) * 0.86 * getattr(self, "zoom_scale", 1.0)
            for f_ring, dash_p in [(0.30, (2, 4)), (0.52, (3, 6)), (0.74, (4, 8)), (0.95, (4, 10))]:
                wrx = rx_base * f_ring
                wry = ry_base * f_ring
                self.canvas.create_oval(
                    cx - wrx, cy - wry, cx + wrx, cy + wry,
                    outline="#132342", width=1, dash=dash_p
                )

        # 3. Vẽ các đường liên kết (Links)
        if self.center_node:
            cx, cy = self.center_node.x, self.center_node.y

            for node in visible_nodes:
                if node == self.center_node:
                    continue

                is_active = (node == self.selected_node or node == self.hovered_node)

                if is_active:
                    link_color = "#38BDF8"
                    link_w = 3.0
                    dash_val = ()
                else:
                    if total_visible > 25:
                        link_color = "#162032"
                        link_w = 1.0
                        dash_val = ()
                    else:
                        rtt = node.rtt_ms or 1
                        link_color = "#059669" if rtt <= 10 else ("#D97706" if rtt <= 40 else "#DC2626")
                        link_w = 1.5
                        dash_val = ()

                self.canvas.create_line(
                    cx,
                    cy,
                    node.x,
                    node.y,
                    fill=link_color,
                    width=link_w,
                    dash=dash_val,
                )

                if is_active:
                    mid_x = (cx + node.x) / 2.0
                    mid_y = (cy + node.y) / 2.0
                    self.canvas.create_oval(mid_x - 4, mid_y - 4, mid_x + 4, mid_y + 4, fill="#38BDF8", outline="#090D16")

        # 4. Vẽ các điểm Node thiết bị con
        show_all_labels = self.force_show_all_labels or (total_visible <= 20)

        for node in visible_nodes:
            if node == self.center_node:
                continue
            self._draw_node(node, show_label=show_all_labels)

        # 5. Vẽ Router trung tâm sau cùng để luôn ở vị trí trung tâm nổi bật
        if self.center_node and self.center_node in visible_nodes:
            self._draw_node(self.center_node, is_center=True, show_label=True)

        # 6. Vẽ Tooltip nổi (Floating Info Card) cho Node đang được Hover
        if self.hovered_node and self.hovered_node in visible_nodes:
            self._draw_hover_tooltip(self.hovered_node)

    def _draw_node(self, node: TopologyNode, is_center: bool = False, show_label: bool = False):
        """Vẽ một điểm node hình tròn to rõ chứa icon và viền quầng sáng."""
        x, y = node.x, node.y
        r = node.radius
        is_selected = (node == self.selected_node)
        is_hovered = (node == self.hovered_node)

        # Quầng sáng phát sáng (Glow ring)
        if is_selected:
            self.canvas.create_oval(x - r - 7, y - r - 7, x + r + 7, y + r + 7, outline="#38BDF8", width=3)
        elif is_hovered:
            self.canvas.create_oval(x - r - 5, y - r - 5, x + r + 5, y + r + 5, outline="#60A5FA", width=2.5)
        elif is_center:
            self.canvas.create_oval(x - r - 8, y - r - 8, x + r + 8, y + r + 8, outline="#0284C7", width=2.5)
        elif node.is_self:
            self.canvas.create_oval(x - r - 5, y - r - 5, x + r + 5, y + r + 5, outline="#4ADE80", width=2.5)

        # Thân node hình tròn
        body_color = node.bg_color
        border_col = "#FFFFFF" if is_selected else (node.border_color if not is_center else "#38BDF8")
        self.canvas.create_oval(x - r, y - r, x + r, y + r, fill=body_color, outline=border_col, width=2.5)

        # Biểu tượng Icon ở giữa to rõ
        icon_font_size = 24 if is_center else (18 if (node.is_self or r >= 28) else 15)
        self.canvas.create_text(x, y - 1, text=node.icon, font=("Segoe UI Emoji", icon_font_size))

        # Hiển thị nhãn chữ
        if show_label or node.is_self or is_center or is_selected or is_hovered:
            if node.is_self:
                self.canvas.create_rectangle(x - 30, y + r + 3, x + 30, y + r + 19, fill="#15803D", outline="")
                self.canvas.create_text(x, y + r + 11, text="MÁY NÀY", fill="white", font=("Segoe UI", 9, "bold"))
                label_y = y + r + 24
            elif is_center:
                self.canvas.create_rectangle(x - 32, y + r + 3, x + 32, y + r + 19, fill="#0369A1", outline="")
                self.canvas.create_text(x, y + r + 11, text="ROUTER", fill="white", font=("Segoe UI", 9, "bold"))
                label_y = y + r + 24
            else:
                label_y = y + r + 6

            # Tên/IP hiển thị to rõ
            ip_text = node.ip
            self.canvas.create_text(
                x,
                label_y,
                text=ip_text,
                fill="#F3F4F6",
                font=("Consolas", 10, "bold"),
                anchor="n",
            )

    def _draw_hover_tooltip(self, node: TopologyNode):
        """Vẽ khung nhãn nổi (Tooltip Card) cỡ lớn, sắc nét, to rõ khi rê chuột vào node."""
        x, y = node.x, node.y - node.radius - 14

        name_display = node.name if (node.name and node.name != "—") else node.vendor
        title_text = f"{node.icon}  {node.ip}"
        sub_text = f"{name_display}  •  {node.vendor}"
        if len(sub_text) > 34:
            sub_text = sub_text[:33] + "…"

        tip_w = 270.0
        tip_h = 56.0
        x1 = x - (tip_w / 2.0)
        y1 = y - tip_h
        x2 = x + (tip_w / 2.0)
        y2 = y

        w = self.canvas.winfo_width()
        if x1 < 10:
            shift = 10 - x1
            x1 += shift
            x2 += shift
        elif x2 > w - 10:
            shift = x2 - (w - 10)
            x1 -= shift
            x2 -= shift

        if y1 < 10:
            y1 = node.y + node.radius + 14
            y2 = y1 + tip_h

        # Bóng đổ nổi 3D
        self.canvas.create_rectangle(x1 + 3, y1 + 3, x2 + 3, y2 + 3, fill="#030712", outline="")

        # Khung nền thẻ
        self.canvas.create_rectangle(x1, y1, x2, y2, fill="#0F172A", outline="#38BDF8", width=2)

        # Dòng 1: Icon + IP và Ping
        self.canvas.create_text(x1 + 14, y1 + 18, text=title_text, fill="#38BDF8", font=("Segoe UI", 12, "bold"), anchor="w")
        rtt_val = node.rtt_ms or 1
        rtt_color = "#34D399" if rtt_val <= 10 else ("#FBBF24" if rtt_val <= 40 else "#EF4444")
        self.canvas.create_text(x2 - 14, y1 + 18, text=f"⚡ {rtt_val} ms", fill=rtt_color, font=("Consolas", 10, "bold"), anchor="e")

        # Gạch phân cách
        self.canvas.create_line(x1 + 12, y1 + 32, x2 - 12, y1 + 32, fill="#1E293B", width=1)

        # Dòng 2: Tên máy + Hãng sản xuất
        self.canvas.create_text(x1 + 14, y1 + 44, text=sub_text, fill="#E2E8F0", font=("Segoe UI", 10), anchor="w")

    # --- SỰ KIỆN CHUỘT & KÉO THẢ TƯƠNG TÁC ---

    def _find_node_at(self, x: float, y: float) -> Optional[TopologyNode]:
        """Tìm xem tọa độ chuột (x, y) có nằm trong bán kính node nào không."""
        visible = [n for n in self.nodes.values() if self._matches_filter(n)]
        for node in reversed(visible):
            dist = math.hypot(node.x - x, node.y - y)
            if dist <= node.radius + 6:
                return node
        return None

    def _on_mouse_down(self, event):
        clicked_node = self._find_node_at(event.x, event.y)
        if clicked_node:
            self.selected_node = clicked_node
            self.dragged_node = clicked_node
            self.drag_start_x = event.x
            self.drag_start_y = event.y
            self.is_panning = False
            self._update_detail_card(clicked_node)
            self._render()
        else:
            # Bấm vào khoảng trống nền Canvas -> Bắt đầu chế độ kéo trượt di chuyển (Pan Canvas)
            self.is_panning = True
            self.pan_start_x = event.x
            self.pan_start_y = event.y

    def _on_mouse_drag(self, event):
        if self.dragged_node:
            dx = event.x - self.drag_start_x
            dy = event.y - self.drag_start_y
            self.dragged_node.x += dx
            self.dragged_node.y += dy
            self.drag_start_x = event.x
            self.drag_start_y = event.y
            self._render()
        elif getattr(self, "is_panning", False):
            dx = event.x - self.pan_start_x
            dy = event.y - self.pan_start_y
            for node in self.nodes.values():
                node.x += dx
                node.y += dy
            self.pan_start_x = event.x
            self.pan_start_y = event.y
            self._render()

    def _on_mouse_up(self, event):
        self.dragged_node = None
        self.is_panning = False

    def _on_mouse_hover(self, event):
        hovered = self._find_node_at(event.x, event.y)
        if hovered != self.hovered_node:
            self.hovered_node = hovered
            self.canvas.configure(cursor="hand2" if hovered else "")
            if hovered:
                self._update_detail_card(hovered)
            self._render()

    def _on_double_click(self, event):
        clicked_node = self._find_node_at(event.x, event.y)
        if clicked_node and self.on_open_port_scan:
            self.on_open_port_scan(clicked_node.device)

    def _on_canvas_resize(self):
        self._render()

    def _update_detail_card(self, node: TopologyNode):
        """Hiển thị thông tin node được chọn lên bảng bên phải to rõ."""
        self.lbl_card_icon.configure(text=node.icon)
        self.lbl_card_name.configure(text=node.name if node.name != "—" else node.vendor)
        self.lbl_card_role.configure(text=f"{node.type_name} • [{node.category.upper()}]")

        self.lbl_spec_ip.configure(text=node.ip)
        self.lbl_spec_mac.configure(text=node.mac)
        self.lbl_spec_vendor.configure(text=node.vendor)
        self.lbl_spec_rtt.configure(text=f"{node.rtt_ms} ms" if node.rtt_ms else "1 ms")

        # Bật các nút hành động
        self.btn_card_port.configure(state="normal")
        self.btn_card_block.configure(state="normal" if not node.is_gateway else "disabled")
        self.btn_card_wol.configure(state="normal" if node.category in ("pc", "router") or node.is_self else "disabled")

    def _on_click_port_scan(self):
        if self.selected_node and self.on_open_port_scan:
            self.on_open_port_scan(self.selected_node.device)

    def _on_click_mac_blocker(self):
        if self.selected_node and self.on_open_mac_blocker:
            self.on_open_mac_blocker(self.selected_node.device)

    def _on_click_wol(self):
        if self.selected_node and self.on_open_wol:
            self.on_open_wol(self.selected_node.device)
