"""
Persistent network history and change tracking.

The scanner deliberately keeps this module independent from the UI so it can be
used by the command line, tests, and background scan workers alike.  A small
SQLite database is stored in the per-user application data directory by
default; callers can pass a path for portable installs or tests.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


PLACEHOLDER_VALUES = {"", "-", "—", "unknown", "không xác định", "chưa rõ"}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _normalise_mac(value: Any) -> str:
    raw = re.sub(r"[^0-9A-Fa-f]", "", _clean(value))
    if len(raw) != 12 or raw == "0" * 12:
        return ""
    return ":".join(raw[i : i + 2] for i in range(0, 12, 2)).upper()


def device_fingerprint(device: Dict[str, Any]) -> str:
    """Return a stable key, preferring MAC and falling back to IP/hostname."""
    mac = _normalise_mac(device.get("mac"))
    if mac:
        return f"mac:{mac}"
    ip = _clean(device.get("ip"))
    if ip:
        return f"ip:{ip.lower()}"
    ipv6 = _clean(device.get("ipv6"))
    if ipv6:
        return f"ipv6:{ipv6.lower()}"
    name = _clean(device.get("name"))
    return f"name:{name.lower()}" if name else "unknown:device"


def default_history_path() -> str:
    """Resolve a writable per-user path without assuming a shell variable."""
    root = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
    if not root:
        root = os.path.join(os.path.expanduser("~"), ".local", "share")
    return os.path.join(root, "WifiDeviceScanner", "history.db")


class NetworkHistory:
    """SQLite-backed snapshots, annotations, and change events."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = os.path.abspath(db_path or default_history_path())
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._initialise()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    @contextmanager
    def _connection(self):
        """Commit or roll back a transaction, then release the Windows file handle."""
        conn = self._connect()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _initialise(self) -> None:
        with self._lock, self._connection() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    started_at TEXT NOT NULL,
                    completed_at TEXT NOT NULL,
                    mode TEXT NOT NULL DEFAULT 'full',
                    cidr TEXT,
                    adapters_json TEXT,
                    visibility_json TEXT,
                    device_count INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    fingerprint TEXT NOT NULL,
                    ip TEXT,
                    ipv6 TEXT,
                    mac TEXT,
                    name TEXT,
                    vendor TEXT,
                    category TEXT,
                    rtt_ms REAL,
                    confidence REAL,
                    hostname_source TEXT,
                    device_json TEXT NOT NULL,
                    UNIQUE(scan_id, fingerprint)
                );
                CREATE INDEX IF NOT EXISTS idx_snapshots_fingerprint
                    ON snapshots(fingerprint);
                CREATE TABLE IF NOT EXISTS device_metadata (
                    fingerprint TEXT PRIMARY KEY,
                    alias TEXT NOT NULL DEFAULT '',
                    notes TEXT NOT NULL DEFAULT '',
                    room TEXT NOT NULL DEFAULT '',
                    trusted INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    fingerprint TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    details_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_events_scan ON events(scan_id);
                CREATE INDEX IF NOT EXISTS idx_events_fingerprint ON events(fingerprint);
                """
            )

    @staticmethod
    def _row_device(row: sqlite3.Row) -> Dict[str, Any]:
        try:
            device = json.loads(row["device_json"] or "{}")
        except (TypeError, ValueError):
            device = {}
        if not isinstance(device, dict):
            device = {}
        device.setdefault("ip", row["ip"] or "")
        device.setdefault("mac", row["mac"] or "")
        device.setdefault("name", row["name"] or "")
        device.setdefault("vendor", row["vendor"] or "")
        device.setdefault("category", row["category"] or "unknown")
        if row["confidence"] is not None:
            device.setdefault("confidence", row["confidence"])
        return device

    def _latest_snapshot_rows(self, conn: sqlite3.Connection) -> List[sqlite3.Row]:
        return list(
            conn.execute(
                """
                SELECT s.* FROM snapshots s
                JOIN scans r ON r.id = s.scan_id
                WHERE r.id = (SELECT id FROM scans ORDER BY id DESC LIMIT 1)
                """
            ).fetchall()
        )

    @staticmethod
    def _metadata_from_row(row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "fingerprint": row["fingerprint"],
            "alias": row["alias"],
            "notes": row["notes"],
            "room": row["room"],
            "trusted": bool(row["trusted"]),
            "updated_at": row["updated_at"],
        }

    def _metadata_map(self, conn: sqlite3.Connection) -> Dict[str, Dict[str, Any]]:
        """Load saved annotations once for a snapshot rather than per device."""
        rows = conn.execute(
            "SELECT fingerprint, alias, notes, room, trusted, updated_at FROM device_metadata"
        ).fetchall()
        return {row["fingerprint"]: self._metadata_from_row(row) for row in rows}

    @staticmethod
    def _apply_metadata_from_map(device: Dict[str, Any], metadata_by_fp: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        result = dict(device)
        fingerprint = device_fingerprint(result)
        meta = metadata_by_fp.get(
            fingerprint,
            {"fingerprint": fingerprint, "alias": "", "notes": "", "room": "", "trusted": False},
        )
        result["fingerprint"] = fingerprint
        result["alias"] = meta.get("alias", "")
        result["notes"] = meta.get("notes", "")
        result["room"] = meta.get("room", "")
        result["trusted"] = bool(meta.get("trusted", False))
        if result["alias"]:
            result["display_name"] = result["alias"]
        return result

    def get_device_metadata(self, device_or_fingerprint: Any) -> Dict[str, Any]:
        fingerprint = (
            device_or_fingerprint
            if isinstance(device_or_fingerprint, str)
            else device_fingerprint(device_or_fingerprint or {})
        )
        with self._lock, self._connection() as conn:
            row = conn.execute(
                "SELECT fingerprint, alias, notes, room, trusted, updated_at "
                "FROM device_metadata WHERE fingerprint = ?",
                (fingerprint,),
            ).fetchone()
        if not row:
            return {"fingerprint": fingerprint, "alias": "", "notes": "", "room": "", "trusted": False}
        return self._metadata_from_row(row)

    def set_device_metadata(
        self,
        device_or_fingerprint: Any,
        alias: Optional[str] = None,
        notes: Optional[str] = None,
        room: Optional[str] = None,
        trusted: Optional[bool] = None,
    ) -> Dict[str, Any]:
        fingerprint = (
            device_or_fingerprint
            if isinstance(device_or_fingerprint, str)
            else device_fingerprint(device_or_fingerprint or {})
        )
        current = self.get_device_metadata(fingerprint)
        values = {
            "alias": current.get("alias", "") if alias is None else _clean(alias),
            "notes": current.get("notes", "") if notes is None else _clean(notes),
            "room": current.get("room", "") if room is None else _clean(room),
            "trusted": int(current.get("trusted", False) if trusted is None else bool(trusted)),
        }
        now = _utc_now()
        with self._lock, self._connection() as conn:
            conn.execute(
                """
                INSERT INTO device_metadata(fingerprint, alias, notes, room, trusted, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(fingerprint) DO UPDATE SET
                  alias=excluded.alias, notes=excluded.notes, room=excluded.room,
                  trusted=excluded.trusted, updated_at=excluded.updated_at
                """,
                (fingerprint, values["alias"], values["notes"], values["room"], values["trusted"], now),
            )
        return {"fingerprint": fingerprint, **values, "trusted": bool(values["trusted"]), "updated_at": now}

    @staticmethod
    def _upsert_metadata_conn(
        conn: sqlite3.Connection,
        fingerprint: str,
        *,
        alias: str = "",
        notes: str = "",
        room: str = "",
        trusted: bool = False,
        updated_at: Optional[str] = None,
    ) -> str:
        """Upsert metadata on an existing transaction (avoids nested DB locks)."""
        stamp = updated_at or _utc_now()
        conn.execute(
            """
            INSERT INTO device_metadata(fingerprint, alias, notes, room, trusted, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(fingerprint) DO UPDATE SET
              alias=excluded.alias, notes=excluded.notes, room=excluded.room,
              trusted=excluded.trusted, updated_at=excluded.updated_at
            """,
            (fingerprint, _clean(alias), _clean(notes), _clean(room), int(bool(trusted)), stamp),
        )
        return stamp

    def apply_metadata(self, device: Dict[str, Any]) -> Dict[str, Any]:
        """Return a copy enriched with the saved alias/room/trusted fields."""
        return self.apply_metadata_many([device])[0]

    def apply_metadata_many(self, devices: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enrich many devices with one metadata query and one SQLite handle."""
        device_list = [dict(device) for device in devices if isinstance(device, dict)]
        if not device_list:
            return []
        with self._lock, self._connection() as conn:
            metadata_by_fp = self._metadata_map(conn)
        return [self._apply_metadata_from_map(device, metadata_by_fp) for device in device_list]

    @staticmethod
    def _device_value(device: Dict[str, Any], key: str) -> str:
        return _clean(device.get(key)).lower()

    def record_scan(
        self,
        devices: Iterable[Dict[str, Any]],
        *,
        mode: str = "full",
        cidr: str = "",
        adapters: Optional[Iterable[Dict[str, Any]]] = None,
        visibility: Optional[Dict[str, Any]] = None,
        started_at: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Persist a scan and return new/removed/changed event details.

        A changed MAC/IP is matched against the prior snapshot by the other
        stable field, so replacing a randomized MAC does not look like a
        disappearance followed by an unrelated new device.
        """
        device_list = [dict(d) for d in devices if isinstance(d, dict)]
        started = started_at or _utc_now()
        completed = _utc_now()
        adapter_list = list(adapters or [])
        visibility = visibility or {}
        with self._lock, self._connection() as conn:
            previous_rows = self._latest_snapshot_rows(conn)
            previous = {row["fingerprint"]: self._row_device(row) for row in previous_rows}
            metadata_by_fp = self._metadata_map(conn)

            def metadata_for(fingerprint: str) -> Dict[str, Any]:
                return metadata_by_fp.get(
                    fingerprint,
                    {"fingerprint": fingerprint, "alias": "", "notes": "", "room": "", "trusted": False},
                )

            previous_by_ip = {
                self._device_value(d, "ip"): (fp, d)
                for fp, d in previous.items()
                if self._device_value(d, "ip")
            }
            previous_by_mac = {
                _normalise_mac(d.get("mac")): (fp, d)
                for fp, d in previous.items()
                if _normalise_mac(d.get("mac"))
            }

            cursor = conn.execute(
                "INSERT INTO scans(started_at, completed_at, mode, cidr, adapters_json, visibility_json, device_count) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    started,
                    completed,
                    _clean(mode) or "full",
                    _clean(cidr),
                    json.dumps(adapter_list, ensure_ascii=False),
                    json.dumps(visibility, ensure_ascii=False),
                    len(device_list),
                ),
            )
            scan_id = int(cursor.lastrowid)
            current_fps = set()
            new_devices: List[Dict[str, Any]] = []
            changed_devices: List[Dict[str, Any]] = []
            matched_previous = set()

            for original in device_list:
                device = dict(original)
                fp = device_fingerprint(device)
                current_fps.add(fp)
                meta = metadata_for(fp)
                # Preserve annotations in the materialized snapshot for easy exports.
                device.update(
                    {
                        "fingerprint": fp,
                        "alias": meta.get("alias", ""),
                        "notes": meta.get("notes", ""),
                        "room": meta.get("room", ""),
                        "trusted": bool(meta.get("trusted", False)),
                    }
                )
                old = previous.get(fp)
                match_type = "same"
                if old is None:
                    ip_key = self._device_value(device, "ip")
                    mac_key = _normalise_mac(device.get("mac"))
                    if ip_key and ip_key in previous_by_ip:
                        old_fp, old = previous_by_ip[ip_key]
                        match_type = "mac_changed"
                    elif mac_key and mac_key in previous_by_mac:
                        old_fp, old = previous_by_mac[mac_key]
                        match_type = "ip_changed"
                    else:
                        match_type = "new"
                if old is not None:
                    old_fp = device_fingerprint(old)
                    matched_previous.add(old_fp)
                    # Carry user annotations across an IP/MAC change when the
                    # new fingerprint has no explicit metadata yet.
                    if old_fp != fp:
                        old_meta = metadata_for(old_fp)
                        new_meta = metadata_for(fp)
                        if (
                            not new_meta.get("alias")
                            and not new_meta.get("notes")
                            and not new_meta.get("room")
                            and not new_meta.get("trusted")
                            and any((old_meta.get("alias"), old_meta.get("notes"), old_meta.get("room"), old_meta.get("trusted")))
                        ):
                            stamp = self._upsert_metadata_conn(
                                conn,
                                fp,
                                alias=old_meta.get("alias", ""),
                                notes=old_meta.get("notes", ""),
                                room=old_meta.get("room", ""),
                                trusted=old_meta.get("trusted", False),
                            )
                            metadata_by_fp[fp] = {
                                "fingerprint": fp,
                                "alias": old_meta.get("alias", ""),
                                "notes": old_meta.get("notes", ""),
                                "room": old_meta.get("room", ""),
                                "trusted": bool(old_meta.get("trusted", False)),
                                "updated_at": stamp,
                            }
                            device.update(
                                {
                                    "alias": old_meta.get("alias", ""),
                                    "notes": old_meta.get("notes", ""),
                                    "room": old_meta.get("room", ""),
                                    "trusted": bool(old_meta.get("trusted", False)),
                                }
                            )
                    ip_changed = self._device_value(old, "ip") != self._device_value(device, "ip")
                    mac_changed = _normalise_mac(old.get("mac")) != _normalise_mac(device.get("mac"))
                    if match_type == "mac_changed" or mac_changed:
                        event_type = "mac_changed"
                    elif match_type == "ip_changed" or ip_changed:
                        event_type = "ip_changed"
                    else:
                        event_type = "changed" if any(
                            self._device_value(old, k) != self._device_value(device, k)
                            for k in ("name", "vendor", "category", "hostname")
                        ) else "same"
                    if event_type != "same":
                        changed_devices.append({"device": device, "previous": old, "event_type": event_type})
                else:
                    event_type = "new"
                    new_devices.append(device)

                conn.execute(
                    """
                    INSERT INTO snapshots(
                        scan_id, fingerprint, ip, ipv6, mac, name, vendor, category,
                        rtt_ms, confidence, hostname_source, device_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        fp,
                        _clean(device.get("ip")),
                        _clean(device.get("ipv6")),
                        _normalise_mac(device.get("mac")),
                        _clean(device.get("name")),
                        _clean(device.get("vendor")),
                        _clean(device.get("category")) or "unknown",
                        device.get("rtt_ms"),
                        device.get("confidence"),
                        _clean(device.get("hostname_source")),
                        json.dumps(device, ensure_ascii=False),
                    ),
                )
                if event_type != "same":
                    details = {"device": device}
                    if old is not None:
                        details["previous"] = old
                    conn.execute(
                        "INSERT INTO events(scan_id, fingerprint, event_type, details_json, created_at) VALUES (?, ?, ?, ?, ?)",
                        (scan_id, fp, event_type, json.dumps(details, ensure_ascii=False), completed),
                    )

            removed_devices: List[Dict[str, Any]] = []
            for fp, old in previous.items():
                if fp not in matched_previous and fp not in current_fps:
                    removed_devices.append(old)
                    conn.execute(
                        "INSERT INTO events(scan_id, fingerprint, event_type, details_json, created_at) VALUES (?, ?, 'removed', ?, ?)",
                        (scan_id, fp, json.dumps({"device": old}, ensure_ascii=False), completed),
                    )

        return {
            "scan_id": scan_id,
            "started_at": started,
            "completed_at": completed,
            "mode": mode,
            "device_count": len(device_list),
            "new": new_devices,
            "removed": removed_devices,
            "changed": changed_devices,
            "events": [
                {"event_type": "new", "device": d} for d in new_devices
            ]
            + [
                {"event_type": item["event_type"], **item} for item in changed_devices
            ]
            + [{"event_type": "removed", "device": d} for d in removed_devices],
            "visibility": visibility,
        }

    def latest_devices(self) -> List[Dict[str, Any]]:
        with self._lock, self._connection() as conn:
            rows = self._latest_snapshot_rows(conn)
            metadata_by_fp = self._metadata_map(conn)
        devices: List[Dict[str, Any]] = []
        for row in rows:
            device = self._apply_metadata_from_map(self._row_device(row), metadata_by_fp)
            device["historical"] = True
            devices.append(device)
        return devices

    def get_device_history(self, device_or_fingerprint: Any, limit: int = 100) -> Dict[str, Any]:
        """Return annotations, last-seen data, and IP/MAC history for one device.

        When a device changes IP or randomized MAC, the change event links the
        old and new fingerprints so the detail page can show one continuous
        timeline instead of two unrelated devices.
        """
        if isinstance(device_or_fingerprint, str):
            fingerprint = _clean(device_or_fingerprint)
            if not fingerprint.startswith(("mac:", "ip:", "ipv6:", "name:", "unknown:")):
                normalized = _normalise_mac(fingerprint)
                fingerprint = f"mac:{normalized}" if normalized else fingerprint
        else:
            fingerprint = device_fingerprint(device_or_fingerprint or {})
        limit = max(1, min(int(limit), 500))

        def payload_fingerprint(payload: Any) -> str:
            if not isinstance(payload, dict):
                return ""
            explicit = _clean(payload.get("fingerprint"))
            if explicit:
                return explicit
            derived = device_fingerprint(payload)
            return "" if derived == "unknown:device" else derived

        default_metadata = {
            "fingerprint": fingerprint,
            "alias": "",
            "notes": "",
            "room": "",
            "trusted": False,
        }
        with self._lock, self._connection() as conn:
            metadata_by_fp = self._metadata_map(conn)
            event_rows = conn.execute(
                "SELECT id, scan_id, fingerprint, event_type, details_json, created_at "
                "FROM events ORDER BY id"
            ).fetchall()

            # Follow MAC/IP change links to collect all known identities.
            known_fingerprints = {fingerprint} if fingerprint else set()
            event_records = []
            for row in event_rows:
                try:
                    details = json.loads(row["details_json"] or "{}")
                except (TypeError, ValueError):
                    details = {}
                candidates = set()
                row_fingerprint = _clean(row["fingerprint"])
                if row_fingerprint and row_fingerprint != "unknown:device":
                    candidates.add(row_fingerprint)
                if isinstance(details, dict):
                    for key in ("device", "previous"):
                        candidate = payload_fingerprint(details.get(key))
                        if candidate:
                            candidates.add(candidate)
                event_records.append((row, details, candidates))

            expanded = True
            while expanded:
                expanded = False
                for _row, _details, candidates in event_records:
                    if known_fingerprints.intersection(candidates):
                        before = len(known_fingerprints)
                        known_fingerprints.update(candidates)
                        expanded = expanded or len(known_fingerprints) != before

            observations: List[Dict[str, Any]] = []
            if known_fingerprints:
                placeholders = ", ".join("?" for _ in known_fingerprints)
                rows = conn.execute(
                    f"""
                    SELECT s.*, r.started_at AS scan_started_at, r.completed_at AS observed_at
                    FROM snapshots s
                    JOIN scans r ON r.id = s.scan_id
                    WHERE s.fingerprint IN ({placeholders})
                    ORDER BY r.id DESC, s.id DESC
                    """,
                    tuple(sorted(known_fingerprints)),
                ).fetchall()
                for row in rows:
                    device = self._apply_metadata_from_map(self._row_device(row), metadata_by_fp)
                    observation = dict(device)
                    observation.update(
                        {
                            "scan_id": row["scan_id"],
                            "observed_at": row["observed_at"],
                            "scan_started_at": row["scan_started_at"],
                            "fingerprint": row["fingerprint"],
                        }
                    )
                    observations.append(observation)

            metadata = metadata_by_fp.get(fingerprint)
            if metadata is None:
                for related in known_fingerprints:
                    if related in metadata_by_fp:
                        metadata = metadata_by_fp[related]
                        break
            metadata = dict(metadata or default_metadata)

            related_events = []
            for row, details, candidates in event_records:
                if known_fingerprints.intersection(candidates):
                    related_events.append(
                        {
                            "id": row["id"],
                            "scan_id": row["scan_id"],
                            "fingerprint": row["fingerprint"],
                            "event_type": row["event_type"],
                            "created_at": row["created_at"],
                            "details": details,
                        }
                    )
            related_events.reverse()

        chronological = list(reversed(observations))

        def value_history(key: str, normalize_mac: bool = False) -> List[Dict[str, Any]]:
            grouped: Dict[str, Dict[str, Any]] = {}
            for observation in chronological:
                value = _normalise_mac(observation.get(key)) if normalize_mac else _clean(observation.get(key))
                if not value or value.lower() in PLACEHOLDER_VALUES:
                    continue
                observed_at = _clean(observation.get("observed_at"))
                entry = grouped.setdefault(
                    value,
                    {
                        "value": value,
                        "first_seen": observed_at,
                        "last_seen": observed_at,
                        "observations": 0,
                    },
                )
                if observed_at and (not entry["first_seen"] or observed_at < entry["first_seen"]):
                    entry["first_seen"] = observed_at
                if observed_at and (not entry["last_seen"] or observed_at > entry["last_seen"]):
                    entry["last_seen"] = observed_at
                entry["observations"] += 1
            return sorted(grouped.values(), key=lambda item: item.get("last_seen") or "", reverse=True)

        return {
            "fingerprint": fingerprint,
            "fingerprints": sorted(known_fingerprints),
            "metadata": metadata,
            "alias": metadata.get("alias", ""),
            "notes": metadata.get("notes", ""),
            "room": metadata.get("room", ""),
            "trusted": bool(metadata.get("trusted", False)),
            "first_seen": chronological[0].get("observed_at") if chronological else None,
            "last_seen": observations[0].get("observed_at") if observations else None,
            "observation_count": len(observations),
            "current": observations[0] if observations else None,
            "observations": observations[:limit],
            "ip_history": value_history("ip"),
            "ipv6_history": value_history("ipv6"),
            "mac_history": value_history("mac", normalize_mac=True),
            "events": related_events[:limit],
        }

    def list_scans(self, limit: int = 50) -> List[Dict[str, Any]]:
        limit = max(1, min(int(limit), 500))
        with self._lock, self._connection() as conn:
            rows = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        result = []
        for row in rows:
            try:
                adapters = json.loads(row["adapters_json"] or "[]")
            except ValueError:
                adapters = []
            try:
                visibility = json.loads(row["visibility_json"] or "{}")
            except ValueError:
                visibility = {}
            result.append({**dict(row), "adapters": adapters, "visibility": visibility})
        return result

    def list_events(self, limit: int = 100, since_scan_id: Optional[int] = None) -> List[Dict[str, Any]]:
        limit = max(1, min(int(limit), 1000))
        query = "SELECT * FROM events"
        params: List[Any] = []
        if since_scan_id is not None:
            query += " WHERE scan_id >= ?"
            params.append(int(since_scan_id))
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        with self._lock, self._connection() as conn:
            rows = conn.execute(query, params).fetchall()
        result = []
        for row in rows:
            try:
                details = json.loads(row["details_json"] or "{}")
            except ValueError:
                details = {}
            result.append({**dict(row), "details": details})
        return result

    def get_scan(self, scan_id: int) -> Optional[Dict[str, Any]]:
        with self._lock, self._connection() as conn:
            scan = conn.execute("SELECT * FROM scans WHERE id = ?", (int(scan_id),)).fetchone()
            if not scan:
                return None
            rows = conn.execute("SELECT * FROM snapshots WHERE scan_id = ?", (int(scan_id),)).fetchall()
            events = conn.execute("SELECT * FROM events WHERE scan_id = ? ORDER BY id", (int(scan_id),)).fetchall()
            metadata_by_fp = self._metadata_map(conn)
        try:
            visibility = json.loads(scan["visibility_json"] or "{}")
        except ValueError:
            visibility = {}
        parsed_events = []
        for row in events:
            try:
                details = json.loads(row["details_json"] or "{}")
            except ValueError:
                details = {}
            parsed_events.append({**dict(row), "details": details})
        return {
            **dict(scan),
            "visibility": visibility,
            "devices": [self._apply_metadata_from_map(self._row_device(row), metadata_by_fp) for row in rows],
            "events": parsed_events,
        }


NetworkHistoryStore = NetworkHistory

__all__ = ["NetworkHistory", "NetworkHistoryStore", "default_history_path", "device_fingerprint"]
