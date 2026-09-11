"""
scanner.py - Bộ xử lý quét mạng LAN / Wi-Fi hiệu năng cao cho Windows.
Sử dụng Windows native C-API (SendARP trong iphlpapi.dll) đa luồng.
Hỗ trợ callback thời gian thực, tự động tìm Gateway, Subnet và SSID Wi-Fi.
"""

import ctypes
import socket
import struct
import subprocess
import time
import ipaddress
import re
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from ctypes import wintypes
from itertools import islice
from threading import Lock
from typing import Callable, Optional, Dict, Any, List, Tuple, Iterable
from oui_db import lookup_vendor, is_randomized_mac

# Nạp các API IPv4 native của Windows. GetAdaptersInfo/GetBestInterface
# không phụ thuộc ngôn ngữ hiển thị của Windows như việc parse ipconfig.
class _IpAddrString(ctypes.Structure):
    pass


_IpAddrString._fields_ = [
    ("Next", ctypes.POINTER(_IpAddrString)),
    ("IpAddress", ctypes.c_char * 16),
    ("IpMask", ctypes.c_char * 16),
    ("Context", wintypes.DWORD),
]


class _IpAdapterInfo(ctypes.Structure):
    pass


_IpAdapterInfo._fields_ = [
    ("Next", ctypes.POINTER(_IpAdapterInfo)),
    ("ComboIndex", wintypes.DWORD),
    ("AdapterName", ctypes.c_char * 260),
    ("Description", ctypes.c_char * 132),
    ("AddressLength", wintypes.UINT),
    ("Address", ctypes.c_ubyte * 8),
    ("Index", wintypes.DWORD),
    ("Type", wintypes.UINT),
    ("DhcpEnabled", wintypes.UINT),
    ("CurrentIpAddress", ctypes.POINTER(_IpAddrString)),
    ("IpAddressList", _IpAddrString),
    ("GatewayList", _IpAddrString),
]


try:
    _iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)
except (AttributeError, OSError):
    _iphlpapi = None
    _SendARP = None
    _GetAdaptersInfo = None
    _GetBestInterface = None
else:
    _SendARP = _iphlpapi.SendARP
    _SendARP.argtypes = [
        wintypes.ULONG,
        wintypes.ULONG,
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.ULONG),
    ]
    _SendARP.restype = wintypes.ULONG

    _GetAdaptersInfo = _iphlpapi.GetAdaptersInfo
    _GetAdaptersInfo.argtypes = [
        ctypes.POINTER(_IpAdapterInfo),
        ctypes.POINTER(wintypes.ULONG),
    ]
    _GetAdaptersInfo.restype = wintypes.ULONG

    _GetBestInterface = _iphlpapi.GetBestInterface
    _GetBestInterface.argtypes = [
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    _GetBestInterface.restype = wintypes.ULONG


def _decode_fixed_text(value: bytes) -> str:
    """Giải mã chuỗi C cố định từ API Windows."""
    return value.split(b"\x00", 1)[0].decode("ascii", errors="ignore").strip()


def _iter_ip_addr_strings(head: _IpAddrString):
    """Duyệt danh sách địa chỉ IP liên kết do GetAdaptersInfo trả về."""
    current = head
    seen = set()
    while True:
        yield (
            _decode_fixed_text(current.IpAddress),
            _decode_fixed_text(current.IpMask),
        )
        next_ptr = current.Next
        if not next_ptr:
            return
        address = ctypes.addressof(next_ptr.contents)
        if address in seen:
            return
        seen.add(address)
        current = next_ptr.contents


def _is_usable_ipv4(value: str) -> bool:
    try:
        parsed = ipaddress.IPv4Address(value)
    except (ValueError, TypeError):
        return False
    return not (parsed.is_unspecified or parsed.is_loopback or parsed.is_link_local)


def _get_active_adapter_config() -> Optional[Dict[str, Any]]:
    """
    Lấy IP/mask/gateway của interface đang được Windows chọn cho default route.
    API này tránh chọn nhầm VPN hoặc adapter đầu tiên trong ipconfig.
    """
    if _GetAdaptersInfo is None:
        return None

    best_index = None
    if _GetBestInterface is not None:
        try:
            # GetBestInterface nhận IPv4 ở dạng DWORD theo thứ tự byte của Windows.
            destination = struct.unpack("<I", socket.inet_aton("8.8.8.8"))[0]
            index = wintypes.DWORD()
            if _GetBestInterface(destination, ctypes.byref(index)) == 0:
                best_index = index.value
        except Exception:
            pass

    buffer_size = wintypes.ULONG(0)
    ERROR_BUFFER_OVERFLOW = 111
    ERROR_SUCCESS = 0
    try:
        result = _GetAdaptersInfo(None, ctypes.byref(buffer_size))
        if result not in (ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS) or buffer_size.value == 0:
            return None

        buffer = ctypes.create_string_buffer(buffer_size.value)
        adapter_ptr = ctypes.cast(buffer, ctypes.POINTER(_IpAdapterInfo))
        result = _GetAdaptersInfo(adapter_ptr, ctypes.byref(buffer_size))
        if result != ERROR_SUCCESS:
            return None

        candidates = []
        current_ptr = adapter_ptr
        while current_ptr:
            adapter = current_ptr.contents
            ip_entries = list(_iter_ip_addr_strings(adapter.IpAddressList))
            gateway_entries = list(_iter_ip_addr_strings(adapter.GatewayList))
            usable_ip = next(
                ((ip, mask) for ip, mask in ip_entries if _is_usable_ipv4(ip)),
                None,
            )
            if usable_ip:
                gateway = next(
                    (ip for ip, _ in gateway_entries if _is_usable_ipv4(ip)),
                    "",
                )
                candidates.append(
                    {
                        "ip": usable_ip[0],
                        "mask": usable_ip[1],
                        "gateway": gateway,
                        "interface_index": int(adapter.Index),
                    }
                )
            current_ptr = adapter.Next

        if not candidates:
            return None

        if best_index is not None:
            for candidate in candidates:
                if candidate["interface_index"] == best_index:
                    return candidate

        # Khi route API không trả kết quả, ưu tiên interface có gateway.
        candidates.sort(key=lambda item: (not bool(item["gateway"]), item["interface_index"]))
        return candidates[0]
    except Exception:
        return None


def get_local_subnet_info() -> Tuple[str, str, str]:
    """
    Truy xuất địa chỉ IP, Subnet Mask và CIDR dải mạng thực tế trên Windows.
    Trả về: (local_ip, subnet_mask, network_cidr), ví dụ ('192.168.1.45', '255.255.255.0', '192.168.1.0/24').
    Ưu tiên interface đang được Windows dùng cho default route, không phụ thuộc ngôn ngữ hệ điều hành.
    """
    active_config = _get_active_adapter_config()
    if active_config:
        try:
            ip = active_config["ip"]
            mask = active_config["mask"]
            net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
            return ip, mask, str(net)
        except (KeyError, ValueError, TypeError):
            pass

    # Fallback cho các bản Windows/API bị giới hạn; phần này chỉ dùng khi
    # native adapter API không khả dụng.
    try:
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        out = subprocess.check_output(
            ["ipconfig"],
            shell=False,
            text=True,
            startupinfo=startupinfo,
            errors="replace",
        )

        blocks = out.split("\n\n")
        for block in blocks:
            if "IPv4 Address" in block and "Subnet Mask" in block:
                ip_match = re.search(r"IPv4 Address[.\s]+:\s*([\d.]+)", block)
                mask_match = re.search(r"Subnet Mask[.\s]+:\s*([\d.]+)", block)
                if ip_match and mask_match:
                    ip = ip_match.group(1).strip()
                    mask = mask_match.group(1).strip()
                    if not ip.startswith("127.") and not ip.startswith("169.254."):
                        net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
                        return ip, mask, str(net)
    except Exception:
        pass

    fallback_ip = get_local_ip()
    return fallback_ip, "255.255.255.0", f"{fallback_ip.rsplit('.', 1)[0]}.0/24"


def get_local_ip() -> str:
    """Lấy địa chỉ IP nội bộ đang dùng (không gửi gói tin ra ngoài)."""
    active_config = _get_active_adapter_config()
    if active_config and _is_usable_ipv4(active_config.get("ip", "")):
        return active_config["ip"]

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def get_default_gateway() -> Optional[str]:
    """Tìm địa chỉ IP Gateway mặc định (Router Wi-Fi) bằng bảng định tuyến Windows."""
    active_config = _get_active_adapter_config()
    if active_config:
        gateway = active_config.get("gateway")
        if gateway and _is_usable_ipv4(gateway):
            return gateway

    try:
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        out = subprocess.check_output(
            ["route", "print", "0.0.0.0"],
            shell=False,
            text=True,
            startupinfo=startupinfo,
            stderr=subprocess.DEVNULL,
        )
        for line in out.splitlines():
            parts = line.strip().split()
            if len(parts) >= 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                return parts[2]
    except Exception:
        pass
    return None


def get_wifi_ssid() -> Optional[str]:
    """Lấy tên mạng Wi-Fi (SSID) đang kết nối trên Windows."""
    try:
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        out = subprocess.check_output(
            ["netsh", "wlan", "show", "interfaces"],
            shell=False,
            text=True,
            startupinfo=startupinfo,
            stderr=subprocess.DEVNULL,
        )
        for line in out.splitlines():
            line_strip = line.strip()
            if line_strip.startswith("SSID") and not line_strip.startswith("BSSID"):
                parts = line_strip.split(":", 1)
                if len(parts) > 1:
                    ssid = parts[1].strip()
                    if ssid:
                        return ssid
    except Exception:
        pass
    return None


def get_machine_name() -> str:
    """Lấy tên máy tính hiện tại."""
    try:
        return socket.gethostname()
    except Exception:
        return "Máy tính của bạn"


def get_network_adapters() -> List[Dict[str, Any]]:
    """Return active adapters through the locale-independent discovery helper."""
    try:
        from network_discovery import get_network_adapters as _get_adapters

        return _get_adapters()
    except Exception:
        return []


def send_arp_ping(ip_str: str) -> Optional[tuple[str, float]]:
    """
    Gửi gói tin ARP trực tiếp đến IP.
    Trả về (MAC_Address, RoundTripTime_ms) nếu thiết bị phản hồi, ngược lại None.
    """
    try:
        dest_ip = struct.unpack("<I", socket.inet_aton(ip_str))[0]
        src_ip = 0
        mac = (ctypes.c_ubyte * 6)()
        mac_len = ctypes.c_ulong(6)

        t_start = time.perf_counter()
        if _SendARP is None:
            return None
        res = _SendARP(dest_ip, src_ip, ctypes.byref(mac), ctypes.byref(mac_len))
        elapsed_ms = round((time.perf_counter() - t_start) * 1000, 1)

        if res == 0 and mac_len.value == 6:
            mac_str = ":".join(f"{b:02X}" for b in bytes(mac[:6]))
            return mac_str, max(elapsed_ms, 0.1)
    except Exception:
        pass
    return None


def resolve_hostname(ip_str: str, timeout_sec: float = 0.2) -> str:
    """
    Lấy tên thiết bị qua NetBIOS Name Service (UDP Port 137).
    Rất nhanh (0.2s) và không bị treo tiến trình như reverse DNS mặc định của Windows.
    """
    try:
        nb_query = (
            b"\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b" CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00!\x00\x01"
        )
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout_sec)
        s.sendto(nb_query, (ip_str, 137))
        resp, _ = s.recvfrom(1024)
        s.close()
        if len(resp) > 56:
            raw_name = resp[57:73].split(b"\x00")[0].decode("ascii", errors="ignore").strip()
            if raw_name:
                return raw_name
    except Exception:
        pass

    return "—"


class NetworkScanner:
    """Lớp điều khiển quét mạng đa luồng với cơ chế dừng và báo tiến trình."""

    def __init__(self):
        self.is_scanning = False
        self.should_stop = False
        self.local_ip, self.subnet_mask, self.network_cidr = get_local_subnet_info()
        self.gateway_ip = get_default_gateway() or "192.168.1.1"
        self.wifi_ssid = get_wifi_ssid()
        self.machine_name = get_machine_name()
        self.adapters = get_network_adapters()
        self.selected_adapter_indices: List[Any] = []

    def refresh_network_info(self):
        """Cập nhật lại thông tin cấu hình mạng máy."""
        self.local_ip, self.subnet_mask, self.network_cidr = get_local_subnet_info()
        self.gateway_ip = get_default_gateway() or "192.168.1.1"
        self.wifi_ssid = get_wifi_ssid()
        self.machine_name = get_machine_name()
        self.adapters = get_network_adapters()

    def set_selected_adapters(self, indices: Optional[Iterable[Any]]) -> None:
        """Restrict automatic scans to adapter interface indexes supplied by the UI."""
        self.selected_adapter_indices = list(indices or [])

    def stop_scan(self):
        """Yêu cầu dừng tiến trình quét."""
        self.should_stop = True

    def scan_subnet(
        self,
        base_subnet: Optional[str] = None,
        on_device_found: Optional[Callable[[Dict[str, Any]], None]] = None,
        on_progress: Optional[Callable[[int, int], None]] = None,
        on_completed: Optional[Callable[[List[Dict[str, Any]]], None]] = None,
        max_threads: int = 64,
        retries: int = 1,
        rate_limit_ms: float = 0.0,
        max_hosts: int = 2048,
        include_ipv6: bool = False,
        adapter_configs: Optional[Iterable[Dict[str, Any]]] = None,
        scan_mode: str = "full",
    ):
        """
        Quét dải mạng LAN / Wi-Fi.
        Tự động tính toán toàn bộ dải IP theo Subnet Mask thực tế (/24, /23, /22...)
        hoặc theo dải base_subnet do người dùng chỉ định.
        """
        self.is_scanning = True
        self.should_stop = False
        self.refresh_network_info()

        # Xác định dải IP cần quét dựa trên Subnet thực tế.  Dùng islice và
        # batch futures để CIDR lớn không bao giờ materialize hàng triệu IP.
        target_ips: List[str] = []
        target_ip_set = set()
        explicit_subnet = False
        try:
            max_hosts = max(1, min(int(max_hosts), 65536))
        except (TypeError, ValueError):
            max_hosts = 2048
        if str(scan_mode).lower() == "quick":
            max_hosts = min(max_hosts, 256)
        try:
            retries = max(1, min(int(retries), 4))
        except (TypeError, ValueError):
            retries = 1
        try:
            rate_limit_ms = max(0.0, min(float(rate_limit_ms), 1000.0))
        except (TypeError, ValueError):
            rate_limit_ms = 0.0

        def append_ip(value: Any) -> None:
            """Append a valid target once while preserving the configured cap."""
            if len(target_ips) >= max_hosts:
                return
            try:
                target = str(ipaddress.IPv4Address(str(value).strip()))
            except (ValueError, TypeError):
                return
            if target not in target_ip_set:
                target_ip_set.add(target)
                target_ips.append(target)

        def append_hosts(network: ipaddress.IPv4Network) -> None:
            remaining = max_hosts - len(target_ips)
            if remaining <= 0:
                return
            for host in islice(network.hosts(), remaining):
                append_ip(host)

        def append_adapter_networks(entries: List[Tuple[ipaddress.IPv4Network, List[str]]]) -> None:
            """Interleave adapter subnets so an early broad subnet cannot starve others."""
            if not entries:
                return

            # Probe each adapter's own address/gateway first.  This makes a
            # quick scan useful even when the total cap is shared by VLANs.
            for _, preferred in entries:
                for value in preferred:
                    append_ip(value)

            active = [iter(network.hosts()) for network, _ in entries]
            while active and len(target_ips) < max_hosts:
                remaining = []
                for host_iter in active:
                    try:
                        append_ip(next(host_iter))
                        remaining.append(host_iter)
                    except StopIteration:
                        continue
                    if len(target_ips) >= max_hosts:
                        break
                active = remaining

        if base_subnet:
            try:
                # Trường hợp truyền CIDR như "192.168.1.0/24" hoặc "192.168.0.0/23"
                if "/" in base_subnet:
                    net = ipaddress.IPv4Network(base_subnet.strip(), strict=False)
                    explicit_subnet = True
                    append_hosts(net)
                elif base_subnet.endswith("."):
                    # Trường hợp truyền prefix dạng "192.168.1."
                    target_ips = [f"{base_subnet}{i}" for i in range(1, min(255, max_hosts + 1))]
                    explicit_subnet = bool(target_ips)
            except Exception:
                pass

        if not target_ips:
            configs = list(adapter_configs or [])
            if not configs:
                configs = list(self.adapters or [])
            selected = {str(index) for index in (self.selected_adapter_indices or [])}
            if selected:
                configs = [
                    c for c in configs
                    if str(c.get("index")) in selected or str(c.get("interface_index")) in selected
                ]
            adapter_networks: List[Tuple[ipaddress.IPv4Network, List[str]]] = []
            network_positions: Dict[str, int] = {}
            for config in configs:
                for address in config.get("ipv4", []) or []:
                    try:
                        # PowerShell may return address/prefix objects or plain text.
                        if isinstance(address, dict):
                            ip_value = address.get("IPv4Address") or address.get("IPAddress") or ""
                            prefix = address.get("PrefixLength")
                            if prefix is not None:
                                network = ipaddress.IPv4Network(f"{ip_value}/{prefix}", strict=False)
                                if not explicit_subnet and network.num_addresses > 1024:
                                    # For a broad adapter prefix, probe the
                                    # local /24 first so we do not miss peers
                                    # near the current host.
                                    network = ipaddress.IPv4Network(f"{ip_value}/24", strict=False)
                                key = network.with_prefixlen
                                preferred = [str(ip_value), str(config.get("gateway") or "")]
                                if key in network_positions:
                                    adapter_networks[network_positions[key]][1].extend(preferred)
                                else:
                                    network_positions[key] = len(adapter_networks)
                                    adapter_networks.append((network, preferred))
                                continue
                        else:
                            address_text = str(address)
                            address_parts = address_text.split("/", 1)
                            ip_value = address_parts[0]
                            prefix = address_parts[1] if len(address_parts) > 1 else None
                        if ip_value:
                            network = ipaddress.IPv4Network(f"{ip_value}/{prefix or self.subnet_mask}", strict=False)
                            if not explicit_subnet and network.num_addresses > 1024:
                                network = ipaddress.IPv4Network(f"{ip_value}/24", strict=False)
                            key = network.with_prefixlen
                            preferred = [str(ip_value), str(config.get("gateway") or "")]
                            if key in network_positions:
                                adapter_networks[network_positions[key]][1].extend(preferred)
                            else:
                                network_positions[key] = len(adapter_networks)
                                adapter_networks.append((network, preferred))
                    except (TypeError, ValueError):
                        continue
            append_adapter_networks(adapter_networks)
            if not target_ips:
                try:
                    net = ipaddress.IPv4Network(f"{self.local_ip}/{self.subnet_mask}", strict=False)
                    if net.num_addresses > 1024:
                        net = ipaddress.IPv4Network(f"{self.local_ip}/24", strict=False)
                    append_hosts(net)
                except Exception:
                    parts = self.local_ip.split(".")
                    target_ips = [f"{parts[0]}.{parts[1]}.{parts[2]}.{i}" for i in range(1, min(255, max_hosts + 1))]

        # De-duplicate while retaining order when multiple adapters overlap.
        target_ips = list(dict.fromkeys(target_ips))[:max_hosts]

        total = len(target_ips)
        scanned_count = 0
        found_devices: List[Dict[str, Any]] = []

        rate_lock = Lock()
        next_allowed = [0.0]

        def worker(ip: str):
            if self.should_stop:
                return None
            res = None
            for attempt in range(retries):
                if self.should_stop:
                    return None
                if rate_limit_ms:
                    with rate_lock:
                        now = time.monotonic()
                        wait_for = next_allowed[0] - now
                        if wait_for > 0:
                            time.sleep(wait_for)
                        next_allowed[0] = time.monotonic() + rate_limit_ms / 1000.0
                res = send_arp_ping(ip)
                if res:
                    break
                if attempt + 1 < retries:
                    time.sleep(0.01)
            if res:
                mac, rtt = res
                vendor, hint, category = lookup_vendor(mac)
                is_gateway = (ip == self.gateway_ip)
                is_self = (ip == self.local_ip)

                # Điều chỉnh tên hiển thị mặc định
                if is_gateway:
                    device_name = f"Router Wi-Fi / Gateway ({vendor})"
                    category = "router"
                elif is_self:
                    device_name = f"Máy này ({self.machine_name})"
                    category = "pc"
                else:
                    device_name = resolve_hostname(ip)

                hostname_source = "netbios" if device_name != "—" else ""
                if device_name == "—":
                    try:
                        from network_discovery import resolve_hostname_sources

                        hostname_info = resolve_hostname_sources(ip)
                        if hostname_info.get("hostname"):
                            device_name = hostname_info["hostname"]
                            hostname_source = hostname_info.get("source", "reverse-dns")
                    except Exception:
                        pass

                device_info = {
                    "ip": ip,
                    "mac": mac,
                    "name": device_name,
                    "vendor": vendor,
                    "hint": hint,
                    "category": category,
                    "rtt_ms": rtt,
                    "is_gateway": is_gateway,
                    "is_self": is_self,
                    "is_random_mac": is_randomized_mac(mac),
                    "confidence": 0.62,
                    "confidence_label": "trung bình",
                    "hostname_source": hostname_source,
                }
                return device_info
            return None

        last_progress_time = 0.0
        executor = ThreadPoolExecutor(max_workers=max(1, min(int(max_threads), 128)))
        future_to_ip = {}
        try:
            # Giữ số future đang bay nhỏ để stop/cancel có hiệu lực ngay cả với
            # subnet lớn.  Mỗi lô tối đa 4 lần số worker.
            batch_size = max(1, min(len(target_ips), max(1, int(max_threads)) * 4))
            for start in range(0, len(target_ips), batch_size):
                if self.should_stop:
                    break
                batch = target_ips[start : start + batch_size]
                future_to_ip = {executor.submit(worker, ip): ip for ip in batch}
                pending = set(future_to_ip)
                while pending and not self.should_stop:
                    done, pending = wait(pending, timeout=0.05, return_when=FIRST_COMPLETED)
                    for future in done:
                        scanned_count += 1
                        now = time.time()
                        if on_progress and (scanned_count == total or (now - last_progress_time >= 0.07)):
                            last_progress_time = now
                            try:
                                on_progress(scanned_count, total)
                            except Exception:
                                pass
                        try:
                            dev = future.result()
                            if dev:
                                found_devices.append(dev)
                                if on_device_found:
                                    on_device_found(dev)
                        except Exception:
                            pass
                if self.should_stop:
                    for future in pending:
                        future.cancel()
                    break
        finally:
            if self.should_stop:
                # Hủy các job đang chờ; các ARP đã chạy sẽ tự kết thúc ở worker.
                for future in future_to_ip:
                    future.cancel()
                executor.shutdown(wait=False, cancel_futures=True)
            else:
                executor.shutdown(wait=True)

        # Sắp xếp danh sách: Gateway đầu tiên -> Máy này -> các IP theo thứ tự tăng dần
        def sort_key(d):
            if d.get("is_gateway"):
                return -2
            if d.get("is_self"):
                return -1
            try:
                return int(d["ip"].split(".")[-1])
            except Exception:
                return 999

        if include_ipv6:
            try:
                from network_discovery import enrich_devices, get_ipv6_neighbors

                found_devices = enrich_devices(found_devices, ipv6_neighbors=get_ipv6_neighbors())
            except Exception:
                pass

        found_devices.sort(key=sort_key)
        self.is_scanning = False

        if on_completed:
            try:
                on_completed(found_devices)
            except Exception:
                pass

        return found_devices
