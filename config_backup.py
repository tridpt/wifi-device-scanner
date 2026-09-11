"""Portable, local-only backup and restore for scanner configuration."""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List


BACKUP_FORMAT = "wifi-device-scanner-backup"
BACKUP_VERSION = 1
MAX_BACKUP_BYTES = 10 * 1024 * 1024
MAX_DEVICES = 10000
MAX_MAC_PROFILES = 1000

# Device dictionaries are discovery data, not a credential store. Drop keys
# that could contain secrets if a future discovery module adds them.
SENSITIVE_DEVICE_KEYS = {
    "password",
    "passphrase",
    "psk",
    "network_key",
    "wifi_key",
    "private_key",
    "credential",
    "credentials",
    "secret",
    "token",
}

DEFAULT_SETTINGS = {
    "scan_mode": "full",
    "subnet_preset": "Tự động (Theo card mạng)",
    "cidr": "",
    "device_filter": "Tất cả thiết bị",
    "risk_filter": "Mọi mức rủi ro",
    "room_filter": "Mọi phòng",
    "search_query": "",
    "retry": "Retry 2",
    "rate_limit": "Rate 2 ms",
    "adapter_indices": [],
    "theme": "dark",
}

VALID_SCAN_MODES = {"quick", "full", "new-only"}
VALID_SUBNET_PRESETS = {
    "Tự động (Theo card mạng)",
    "Dải /24 (254 hosts)",
    "Dải /23 (510 hosts)",
    "Dải /22 (1022 hosts)",
    "Tùy chỉnh CIDR...",
}
VALID_DEVICE_FILTERS = {
    "Tất cả thiết bị",
    "Chỉ Router/Gateway",
    "Chỉ Điện thoại / Di động",
    "Chỉ Máy tính",
    "Chỉ MAC Bảo mật",
}
VALID_RISK_FILTERS = {"Mọi mức rủi ro", "Rủi ro cao", "Có cảnh báo", "An toàn / tin cậy"}
VALID_MAC_MODES = {"yes", "daily", "no"}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _safe_json_value(value: Any, depth: int = 0) -> Any:
    """Copy ordinary JSON values and stringify unexpected runtime objects."""
    if depth > 8:
        return str(value)
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, dict):
        return {str(key): _safe_json_value(item, depth + 1) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_safe_json_value(item, depth + 1) for item in value]
    return str(value)


def _without_sensitive_fields(value: Any) -> Any:
    """Remove credential-looking keys from nested discovery metadata too."""
    if isinstance(value, dict):
        return {
            key: _without_sensitive_fields(item)
            for key, item in value.items()
            if str(key).strip().lower() not in SENSITIVE_DEVICE_KEYS
        }
    if isinstance(value, list):
        return [_without_sensitive_fields(item) for item in value]
    return value


def _clean_text(value: Any, max_length: int = 512) -> str:
    return str(value or "").strip()[:max_length]


def _normalise_settings(settings: Any) -> Dict[str, Any]:
    source = settings if isinstance(settings, dict) else {}
    result = dict(DEFAULT_SETTINGS)

    scan_mode = _clean_text(source.get("scan_mode"), 32)
    if scan_mode in VALID_SCAN_MODES:
        result["scan_mode"] = scan_mode

    for key, allowed in (
        ("subnet_preset", VALID_SUBNET_PRESETS),
        ("device_filter", VALID_DEVICE_FILTERS),
        ("risk_filter", VALID_RISK_FILTERS),
    ):
        value = _clean_text(source.get(key), 160)
        if value in allowed:
            result[key] = value

    result["room_filter"] = _clean_text(source.get("room_filter"), 160) or DEFAULT_SETTINGS["room_filter"]
    result["search_query"] = _clean_text(source.get("search_query"), 256)
    result["cidr"] = _clean_text(source.get("cidr"), 64)

    retry = _clean_text(source.get("retry"), 32)
    if retry in {"Retry 1", "Retry 2", "Retry 3"}:
        result["retry"] = retry
    rate_limit = _clean_text(source.get("rate_limit"), 32)
    if rate_limit in {"Rate 0 ms", "Rate 2 ms", "Rate 10 ms", "Rate 25 ms"}:
        result["rate_limit"] = rate_limit

    adapter_indices = source.get("adapter_indices", [])
    if isinstance(adapter_indices, (list, tuple)):
        normalised_indices = []
        for item in adapter_indices[:100]:
            if isinstance(item, bool):
                continue
            try:
                index = int(item)
            except (TypeError, ValueError):
                continue
            if index >= 0 and index not in normalised_indices:
                normalised_indices.append(index)
        result["adapter_indices"] = normalised_indices

    theme = _clean_text(source.get("theme"), 16).lower()
    if theme in {"dark", "light"}:
        result["theme"] = theme
    return result


def _normalise_devices(devices: Any) -> List[Dict[str, Any]]:
    if devices is None:
        return []
    if not isinstance(devices, list):
        raise ValueError("Danh sách thiết bị trong file sao lưu không hợp lệ.")
    if len(devices) > MAX_DEVICES:
        raise ValueError(f"File sao lưu chứa quá nhiều thiết bị (tối đa {MAX_DEVICES}).")

    result: List[Dict[str, Any]] = []
    seen = set()
    for raw in devices:
        if not isinstance(raw, dict):
            continue
        device = _safe_json_value(raw)
        if not isinstance(device, dict):
            continue
        device = _without_sensitive_fields(device)
        identity = _clean_text(
            device.get("fingerprint")
            or device.get("mac")
            or device.get("ip")
            or device.get("ipv6")
            or device.get("name"),
            256,
        )
        if not identity:
            continue
        # Avoid duplicate rows while retaining all harmless discovery fields.
        if identity in seen:
            continue
        seen.add(identity)
        result.append(device)
    return result


def _normalise_mac_profiles(profiles: Any) -> List[Dict[str, str]]:
    if profiles is None:
        return []
    if not isinstance(profiles, list):
        raise ValueError("Danh sách profile MAC trong file sao lưu không hợp lệ.")
    if len(profiles) > MAX_MAC_PROFILES:
        raise ValueError(f"File sao lưu chứa quá nhiều profile Wi-Fi (tối đa {MAX_MAC_PROFILES}).")

    result: List[Dict[str, str]] = []
    seen = set()
    for raw in profiles:
        if not isinstance(raw, dict):
            continue
        ssid = _clean_text(raw.get("ssid"), 256)
        mode = _clean_text(raw.get("mode"), 16).lower()
        if not ssid or mode not in VALID_MAC_MODES or ssid in seen:
            continue
        seen.add(ssid)
        result.append({"ssid": ssid, "mode": mode})
    return result


def build_backup_payload(
    devices: Iterable[Dict[str, Any]],
    settings: Dict[str, Any],
    mac_profiles: Iterable[Dict[str, Any]],
    *,
    created_at: str | None = None,
) -> Dict[str, Any]:
    """Build a validated backup payload without passwords or executable data."""
    payload = {
        "format": BACKUP_FORMAT,
        "version": BACKUP_VERSION,
        "created_at": _clean_text(created_at, 64) or _utc_now(),
        "devices": _normalise_devices(list(devices or [])),
        "settings": _normalise_settings(settings),
        "mac_profiles": _normalise_mac_profiles(list(mac_profiles or [])),
    }
    return validate_backup_payload(payload)


def validate_backup_payload(payload: Any) -> Dict[str, Any]:
    """Validate and normalize untrusted JSON before applying it to the app."""
    if not isinstance(payload, dict):
        raise ValueError("File sao lưu phải là một đối tượng JSON.")
    if payload.get("format") != BACKUP_FORMAT:
        raise ValueError("Không đúng định dạng sao lưu của Wi-Fi Device Scanner.")
    if payload.get("version") != BACKUP_VERSION:
        raise ValueError(f"Phiên bản sao lưu không được hỗ trợ: {payload.get('version')!r}.")

    created_at = _clean_text(payload.get("created_at"), 64) or _utc_now()
    return {
        "format": BACKUP_FORMAT,
        "version": BACKUP_VERSION,
        "created_at": created_at,
        "devices": _normalise_devices(payload.get("devices", [])),
        "settings": _normalise_settings(payload.get("settings", {})),
        "mac_profiles": _normalise_mac_profiles(payload.get("mac_profiles", [])),
    }


def save_backup(path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """Atomically write a UTF-8 JSON backup and return its normalized payload."""
    normalized = validate_backup_payload(payload)
    target = os.path.abspath(path)
    parent = os.path.dirname(target) or os.curdir
    encoded = json.dumps(normalized, ensure_ascii=False, indent=2).encode("utf-8")
    if len(encoded) > MAX_BACKUP_BYTES:
        raise ValueError("File sao lưu vượt quá giới hạn 10 MB.")

    temporary_path = None
    try:
        fd, temporary_path = tempfile.mkstemp(prefix=".wifi-device-scanner-", suffix=".tmp", dir=parent)
        with os.fdopen(fd, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, target)
        temporary_path = None
    finally:
        if temporary_path:
            try:
                os.remove(temporary_path)
            except OSError:
                pass
    return normalized


def load_backup(path: str) -> Dict[str, Any]:
    """Read and validate a backup file without executing any embedded content."""
    target = os.path.abspath(path)
    size = os.path.getsize(target)
    if size > MAX_BACKUP_BYTES:
        raise ValueError("File sao lưu vượt quá giới hạn 10 MB.")
    with open(target, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    return validate_backup_payload(payload)


__all__ = [
    "BACKUP_FORMAT",
    "BACKUP_VERSION",
    "DEFAULT_SETTINGS",
    "build_backup_payload",
    "validate_backup_payload",
    "save_backup",
    "load_backup",
]
