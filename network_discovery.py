"""
Best-effort, local-network discovery helpers.

All probes are limited to standard link-local discovery protocols (mDNS and
SSDP) and the local IPv6 neighbour table.  They enrich ARP results; they do
not attempt credential guessing or intrusive service exploitation.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import struct
import subprocess
import time
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


_ADAPTER_CACHE: Tuple[float, List[Dict[str, Any]]] = (0.0, [])


def _hidden_startupinfo() -> Any:
    if os.name != "nt":
        return None
    try:
        info = subprocess.STARTUPINFO()
        info.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        return info
    except Exception:
        return None


def _run_powershell(command: str, timeout: float = 2.5) -> str:
    """Run a fixed, read-only PowerShell query without invoking a shell."""
    if os.name != "nt":
        return ""
    try:
        return subprocess.check_output(
            [
                "powershell.exe",
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                command,
            ],
            text=True,
            errors="replace",
            timeout=timeout,
            startupinfo=_hidden_startupinfo(),
            stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except Exception:
        return ""


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def get_network_adapters() -> List[Dict[str, Any]]:
    """Return active IPv4/IPv6 adapters using locale-independent PowerShell."""
    global _ADAPTER_CACHE
    if time.monotonic() - _ADAPTER_CACHE[0] < 2.0 and _ADAPTER_CACHE[1]:
        return [dict(item) for item in _ADAPTER_CACHE[1]]
    command = (
        "Get-NetIPConfiguration | Where-Object {$_.IPv4Address -or $_.IPv6Address} | "
        "Select-Object InterfaceIndex,InterfaceAlias,NetProfile,IPv4Address,IPv6Address,"
        "IPv4DefaultGateway,DNSServer | ConvertTo-Json -Compress -Depth 5"
    )
    raw = _run_powershell(command)
    adapters: List[Dict[str, Any]] = []
    if raw:
        try:
            rows = _as_list(json.loads(raw))
            for row in rows:
                if not isinstance(row, dict):
                    continue
                ipv4 = []
                for item in _as_list(row.get("IPv4Address")):
                    if isinstance(item, dict) and (item.get("IPAddress") or item.get("IPv4Address")):
                        address = item.get("IPAddress") or item.get("IPv4Address")
                        prefix = item.get("PrefixLength")
                        ipv4.append(f"{address}/{prefix}" if prefix is not None else str(address))
                    elif item:
                        ipv4.append(str(item))
                ipv6 = []
                for item in _as_list(row.get("IPv6Address")):
                    if isinstance(item, dict) and (item.get("IPAddress") or item.get("IPv6Address")):
                        address = item.get("IPAddress") or item.get("IPv6Address")
                        prefix = item.get("PrefixLength")
                        ipv6.append(f"{address}/{prefix}" if prefix is not None else str(address))
                    elif item:
                        ipv6.append(str(item))
                gateway = row.get("IPv4DefaultGateway") or {}
                if isinstance(gateway, list):
                    gateway = gateway[0] if gateway else {}
                if isinstance(gateway, dict):
                    gateway = gateway.get("NextHop", "")
                dns_values: List[str] = []
                for dns_item in _as_list(row.get("DNSServer")):
                    if isinstance(dns_item, dict):
                        dns_values.extend(str(v) for v in _as_list(dns_item.get("ServerAddresses")))
                    elif dns_item:
                        dns_values.append(str(dns_item))
                adapters.append(
                    {
                        "index": row.get("InterfaceIndex"),
                        "name": row.get("InterfaceAlias") or "",
                        "ipv4": ipv4,
                        "ipv6": ipv6,
                        "gateway": str(gateway or ""),
                        "dns": dns_values,
                    }
                )
        except (TypeError, ValueError, json.JSONDecodeError):
            adapters = []

    if adapters:
        _ADAPTER_CACHE = (time.monotonic(), adapters)
        return [dict(item) for item in adapters]

    # Portable fallback: expose interface names and addresses available from
    # the standard library.  Prefix/gateway details remain unknown.
    try:
        names = {idx: name for idx, name in socket.if_nameindex()}
    except Exception:
        names = {}
    fallback: List[Dict[str, Any]] = []
    try:
        host = socket.gethostname()
        infos = socket.getaddrinfo(host, None)
        addresses: Dict[int, Dict[str, List[str]]] = {}
        for family, _, _, _, sockaddr in infos:
            addr = sockaddr[0]
            key = socket.AF_INET6 if family == socket.AF_INET6 else socket.AF_INET
            addresses.setdefault(key, {"ipv4": [], "ipv6": []})
            addresses[key]["ipv6" if family == socket.AF_INET6 else "ipv4"].append(addr)
        for idx, name in names.items() or [(None, "default")]:
            data = addresses.get(socket.AF_INET, {"ipv4": [], "ipv6": []})
            fallback.append({"index": idx, "name": name, "ipv4": data["ipv4"], "ipv6": data["ipv6"], "gateway": "", "dns": []})
    except Exception:
        pass
    if fallback:
        _ADAPTER_CACHE = (time.monotonic(), fallback)
    return fallback


def _parse_ssdp_response(raw: bytes) -> Dict[str, str]:
    text = raw.decode("utf-8", errors="replace")
    lines = text.split("\r\n")
    result: Dict[str, str] = {"status": lines[0].strip() if lines else ""}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        result[key.strip().lower()] = value.strip()
    return result


def discover_ssdp(timeout: float = 0.8, mx: int = 1, interface: str = "") -> List[Dict[str, Any]]:
    """Discover UPnP devices with a bounded SSDP M-SEARCH request."""
    message = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        f"MX: {max(1, min(int(mx), 3))}\r\n"
        "ST: ssdp:all\r\n\r\n"
    ).encode("ascii")
    results: List[Dict[str, Any]] = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.settimeout(max(0.1, min(float(timeout), 5.0)))
        if interface:
            try:
                sock.bind((interface, 0))
            except OSError:
                pass
        sock.sendto(message, ("239.255.255.250", 1900))
        seen = set()
        deadline = time.monotonic() + max(0.1, min(float(timeout), 5.0))
        while time.monotonic() < deadline:
            try:
                raw, addr = sock.recvfrom(8192)
            except socket.timeout:
                break
            headers = _parse_ssdp_response(raw)
            ip = addr[0] if addr else ""
            key = (ip, headers.get("usn", ""), headers.get("location", ""))
            if key in seen:
                continue
            seen.add(key)
            results.append(
                {
                    "protocol": "ssdp",
                    "ip": ip,
                    "location": headers.get("location", ""),
                    "server": headers.get("server", ""),
                    "usn": headers.get("usn", ""),
                    "st": headers.get("st", ""),
                    "headers": headers,
                    "confidence": 0.82,
                }
            )
    except (OSError, ValueError):
        pass
    finally:
        sock.close()
    return results


def _dns_name(labels: Sequence[str]) -> bytes:
    return b"".join(bytes([len(label)]) + label.encode("idna") for label in labels) + b"\x00"


def _build_dns_query(name: str, qtype: int = 12, ident: int = 0x4D44) -> bytes:
    labels = [part for part in name.rstrip(".").split(".") if part]
    return struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0) + _dns_name(labels) + struct.pack("!HH", qtype, 1)


def _read_dns_name(data: bytes, offset: int) -> Tuple[str, int]:
    labels: List[str] = []
    seen = set()
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if pointer in seen:
                break
            seen.add(pointer)
            part, _ = _read_dns_name(data, pointer)
            if part:
                labels.append(part)
            offset += 2
            break
        if length > 63 or offset + 1 + length > len(data):
            break
        offset += 1
        labels.append(data[offset : offset + length].decode("utf-8", errors="replace"))
        offset += length
    return ".".join(labels), offset


def _parse_dns_answers(data: bytes) -> List[Dict[str, Any]]:
    if len(data) < 12:
        return []
    try:
        _, _, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    except struct.error:
        return []
    offset = 12
    for _ in range(qd):
        _, offset = _read_dns_name(data, offset)
        offset += 4
        if offset > len(data):
            return []
    records: List[Dict[str, Any]] = []
    total = an + ns + ar
    for _ in range(total):
        name, offset = _read_dns_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset : offset + 10])
        offset += 10
        rdata_start = offset
        rdata = data[offset : offset + rdlength]
        offset += rdlength
        value: Any = ""
        if rtype in (12, 5):
            value, _ = _read_dns_name(data, rdata_start)
        elif rtype == 1 and len(rdata) == 4:
            value = socket.inet_ntoa(rdata)
        elif rtype == 28 and len(rdata) == 16:
            value = socket.inet_ntop(socket.AF_INET6, rdata)
        elif rtype == 16:
            chunks = []
            pos = 0
            while pos < len(rdata):
                ln = rdata[pos]
                pos += 1
                chunks.append(rdata[pos : pos + ln].decode("utf-8", errors="replace"))
                pos += ln
            value = " ".join(chunks)
        records.append({"name": name, "type": rtype, "class": rclass, "ttl": ttl, "value": value})
    return records


def discover_mdns(timeout: float = 0.8, interface: str = "") -> List[Dict[str, Any]]:
    """Query common mDNS service directories and return service evidence."""
    query_names = (
        "_services._dns-sd._udp.local",
        "_http._tcp.local",
        "_airplay._tcp.local",
        "_googlecast._tcp.local",
        "_ipp._tcp.local",
        "_rtsp._tcp.local",
    )
    results: List[Dict[str, Any]] = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Join the link-local multicast group so replies are received even
        # when another mDNS listener is already active on the host.
        interface_ip = "0.0.0.0"
        if interface:
            try:
                interface_ip = socket.gethostbyname(interface)
            except OSError:
                interface_ip = str(interface)
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton("224.0.0.251") + socket.inet_aton(interface_ip))
        except OSError:
            pass
        sock.settimeout(max(0.1, min(float(timeout), 5.0)))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        try:
            if interface_ip != "0.0.0.0":
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(interface_ip))
        except OSError:
            pass
        if interface:
            try:
                sock.bind((interface, 0))
            except OSError:
                pass
        for index, query_name in enumerate(query_names, 1):
            sock.sendto(_build_dns_query(query_name, qtype=12, ident=0x4D44 + index), ("224.0.0.251", 5353))
        deadline = time.monotonic() + max(0.1, min(float(timeout), 5.0))
        seen = set()
        while time.monotonic() < deadline:
            try:
                raw, addr = sock.recvfrom(16384)
            except socket.timeout:
                break
            for record in _parse_dns_answers(raw):
                value = record.get("value")
                if not value:
                    continue
                key = (addr[0] if addr else "", record.get("name"), record.get("type"), value)
                if key in seen:
                    continue
                seen.add(key)
                results.append(
                    {
                        "protocol": "mdns",
                        "ip": addr[0] if addr else "",
                        "service": record.get("name", ""),
                        "value": value,
                        "record_type": record.get("type"),
                        "ttl": record.get("ttl"),
                        "confidence": 0.78,
                    }
                )
    except (OSError, ValueError):
        pass
    finally:
        sock.close()
    return results


def get_ipv6_neighbors() -> List[Dict[str, Any]]:
    """Read IPv6 neighbour cache entries without actively probing hosts."""
    results: List[Dict[str, Any]] = []
    raw = _run_powershell(
        "Get-NetNeighbor -AddressFamily IPv6 | "
        "Where-Object {$_.LinkLayerAddress -and $_.State -notin @('Unreachable','Invalid')} | "
        "Select-Object IPAddress,LinkLayerAddress,InterfaceIndex,State | ConvertTo-Json -Compress"
    )
    if raw:
        try:
            for row in _as_list(json.loads(raw)):
                if not isinstance(row, dict):
                    continue
                ip = str(row.get("IPAddress") or "")
                mac = str(row.get("LinkLayerAddress") or "")
                try:
                    ipaddress.IPv6Address(ip.split("%", 1)[0])
                except ValueError:
                    continue
                results.append({"ip": ip, "mac": mac, "interface_index": row.get("InterfaceIndex"), "state": row.get("State", "")})
        except (TypeError, ValueError, json.JSONDecodeError):
            pass
    if results:
        return results

    # netsh output is available on older Windows versions.  Locale-specific
    # words are ignored; only IPv6/MAC patterns are parsed.
    try:
        raw_text = subprocess.check_output(
            ["netsh", "interface", "ipv6", "show", "neighbors"],
            text=True,
            errors="replace",
            timeout=3,
            startupinfo=_hidden_startupinfo(),
            stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except Exception:
        raw_text = ""
    ipv6_re = re.compile(r"(?P<ip>[0-9A-Fa-f:]+(?:%\d+)?)\s+(?P<mac>(?:[0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2})")
    for line in raw_text.splitlines():
        match = ipv6_re.search(line)
        if match:
            results.append({"ip": match.group("ip"), "mac": match.group("mac"), "state": line.strip()})
    return results


def resolve_hostname_sources(ip: str, timeout: float = 0.35, include_dhcp: bool = False) -> Dict[str, str]:
    """Best-effort hostname lookup with an explicit source label.

    DHCP lease names are normally held by the router, not exposed to a client.
    We therefore try reverse DNS first and only query the local DHCP service
    when Windows exposes it; callers can show ``source=unavailable`` honestly.
    """
    value = str(ip or "").strip()
    if not value:
        return {"hostname": "", "source": "unavailable"}
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(max(0.1, min(float(timeout), 2.0)))
        name, _, _ = socket.gethostbyaddr(value)
        if name and name != value:
            return {"hostname": name.rstrip("."), "source": "reverse-dns"}
    except Exception:
        pass
    finally:
        socket.setdefaulttimeout(old_timeout)
    if include_dhcp and os.name == "nt":
        # This command only succeeds on machines administering a DHCP server;
        # it is intentionally bounded and never changes server state.
        escaped = value.replace("'", "''")
        raw = _run_powershell(
            f"Get-DhcpServerv4Lease -ComputerName localhost -IPAddress '{escaped}' -ErrorAction SilentlyContinue | "
            "Select-Object -ExpandProperty HostName | ConvertTo-Json -Compress",
            timeout=0.9,
        )
        try:
            name = json.loads(raw) if raw.strip() else ""
            if isinstance(name, list):
                name = name[0] if name else ""
            if name:
                return {"hostname": str(name).rstrip("."), "source": "dhcp-lease"}
        except (TypeError, ValueError, json.JSONDecodeError):
            pass
    return {"hostname": "", "source": "unavailable"}


def _confidence_label(value: float) -> str:
    if value >= 0.8:
        return "cao"
    if value >= 0.55:
        return "trung bình"
    return "thấp"


def calculate_confidence(device: Dict[str, Any]) -> Tuple[float, str]:
    """Calculate a transparent confidence score from observed evidence."""
    score = 0.45 if device.get("mac") else 0.25
    if device.get("hostname") or (device.get("name") and device.get("name") not in ("—", "")):
        score += 0.15
    services = device.get("services") or []
    if services:
        score += min(0.25, 0.08 * len(services))
    if device.get("ipv6"):
        score += 0.08
    if device.get("is_gateway") or device.get("is_self"):
        score += 0.08
    score = round(min(0.99, score), 2)
    return score, _confidence_label(score)


def enrich_devices(
    devices: Iterable[Dict[str, Any]],
    *,
    ssdp_results: Optional[Iterable[Dict[str, Any]]] = None,
    mdns_results: Optional[Iterable[Dict[str, Any]]] = None,
    ipv6_neighbors: Optional[Iterable[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Merge discovery evidence into ARP device dictionaries."""
    result = [dict(d) for d in devices if isinstance(d, dict)]
    by_ip = {str(d.get("ip", "")).lower(): d for d in result if d.get("ip")}
    by_mac = {re.sub(r"[^0-9a-f]", "", str(d.get("mac", "")).lower()): d for d in result if d.get("mac")}
    for neighbor in ipv6_neighbors or []:
        mac_key = re.sub(r"[^0-9a-f]", "", str(neighbor.get("mac", "")).lower())
        d = by_mac.get(mac_key) if mac_key else None
        if d is None:
            d = by_ip.get(str(neighbor.get("ip", "")).lower())
        if d is None:
            d = {"ip": "", "ipv6": neighbor.get("ip", ""), "mac": neighbor.get("mac", ""), "name": "—", "vendor": "Chưa rõ", "category": "unknown"}
            result.append(d)
            if mac_key:
                by_mac[mac_key] = d
        d["ipv6"] = neighbor.get("ip", "")
        d.setdefault("services", [])
        d["services"].append({"protocol": "ipv6-neighbor", "state": neighbor.get("state", "")})

    for item in list(ssdp_results or []) + list(mdns_results or []):
        ip = str(item.get("ip", "")).lower()
        d = by_ip.get(ip)
        if d is None and ip:
            d = {"ip": ip, "mac": "", "name": "—", "vendor": "Chưa rõ", "category": "unknown"}
            result.append(d)
            by_ip[ip] = d
        if d is None:
            continue
        d.setdefault("services", []).append(dict(item))
        protocol = item.get("protocol")
        if protocol == "ssdp":
            d.setdefault("discovery_names", []).append(item.get("server") or item.get("st") or "UPnP")
        elif protocol == "mdns":
            service = item.get("service") or item.get("value")
            if service:
                d.setdefault("discovery_names", []).append(service)
                if d.get("name") in (None, "", "—"):
                    d["name"] = str(service).rstrip(".")

    for d in result:
        names = d.get("discovery_names") or []
        if names and d.get("name") in (None, "", "—"):
            d["name"] = str(names[0])
        score, label = calculate_confidence(d)
        d["confidence"] = score
        d["confidence_label"] = label
        if d.get("services"):
            d["discovery"] = ", ".join(sorted({str(s.get("protocol", "")) for s in d["services"] if s.get("protocol")}))
    return result


def assess_visibility(
    *,
    expected_hosts: Optional[int],
    devices: Iterable[Dict[str, Any]],
    gateway_reachable: bool = True,
    adapter_count: int = 1,
) -> Dict[str, Any]:
    """Describe likely AP isolation/VLAN limitations without overclaiming."""
    found = list(devices)
    count = len(found)
    expected = int(expected_hosts or 0)
    ratio = (count / expected) if expected > 0 else None
    peer_count = sum(1 for d in found if not d.get("is_gateway") and not d.get("is_self"))
    evidence: List[str] = []
    ap_isolation = False
    vlan = False
    if gateway_reachable and expected >= 8 and peer_count <= 1:
        ap_isolation = True
        evidence.append("Gateway phản hồi nhưng rất ít peer; có thể AP/client isolation hoặc thiết bị đang ngủ.")
    if adapter_count > 1:
        vlan = True
        evidence.append("Có nhiều adapter hoạt động; các VLAN/broadcast domain có thể không nhìn thấy nhau.")
    if ratio is not None and ratio < 0.1 and expected >= 32:
        evidence.append("Tỷ lệ phản hồi thấp; giới hạn broadcast, VLAN hoặc firewall có thể đang che khuất thiết bị.")
    status = "đầy đủ"
    if ap_isolation or vlan or evidence:
        status = "có giới hạn khả năng quan sát"
    return {
        "status": status,
        "expected_hosts": expected,
        "found_hosts": count,
        "coverage_ratio": round(ratio, 3) if ratio is not None else None,
        "ap_isolation_suspected": ap_isolation,
        "vlan_suspected": vlan,
        "evidence": evidence,
        "remediation": [
            "Kiểm tra AP/client isolation và guest Wi-Fi trên router.",
            "Kiểm tra VLAN, subnet route và ACL nếu đang dùng nhiều SSID/adapter.",
            "Thử quét lại khi thiết bị đang thức; kết quả là bằng chứng quan sát, không phải khẳng định tuyệt đối.",
        ] if evidence else [],
    }


def run_local_discovery(timeout: float = 0.8, interface: str = "") -> Dict[str, Any]:
    """Run the non-intrusive discovery probes and return raw evidence."""
    ssdp = discover_ssdp(timeout=timeout, interface=interface)
    mdns = discover_mdns(timeout=timeout, interface=interface)
    ipv6 = get_ipv6_neighbors()
    return {"ssdp": ssdp, "mdns": mdns, "ipv6": ipv6, "timestamp": time.time()}


# Readable aliases for integrations that prefer a scan_* naming convention.
scan_ssdp = discover_ssdp
scan_mdns = discover_mdns
get_ipv6_neighbor_cache = get_ipv6_neighbors
merge_discovery_results = enrich_devices


__all__ = [
    "get_network_adapters",
    "discover_ssdp",
    "discover_mdns",
    "get_ipv6_neighbors",
    "resolve_hostname_sources",
    "enrich_devices",
    "calculate_confidence",
    "assess_visibility",
    "run_local_discovery",
    "scan_ssdp",
    "scan_mdns",
    "get_ipv6_neighbor_cache",
    "merge_discovery_results",
]
