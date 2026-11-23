"""SQLite persistence layer for LanScan Web."""

from __future__ import annotations

import ipaddress
import json
import os
import platform
import socket
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any


def _default_db_path() -> str:
    env_path = os.environ.get("LANSCAN_DB")
    if env_path:
        return env_path
    # Inside Docker container (/data exists and is writable)
    if os.path.isdir("/data") and os.access("/data", os.W_OK):
        return "/data/lanscan.db"
    sys_name = platform.system()
    if sys_name == "Darwin":
        return os.path.expanduser("~/Library/Application Support/LanScanWeb/lanscan.db")
    if sys_name == "Windows":
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
        return os.path.join(base, "LanScanWeb", "lanscan.db")
    return os.path.expanduser("~/.local/share/lanscan-web/lanscan.db")


def _detect_local_subnet() -> str:
    """Detect the host machine's primary IPv4 /24 subnet for zero-config first run."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        finally:
            s.close()
        ip_obj = ipaddress.IPv4Address(local_ip)
        if ip_obj.is_private and not ip_obj.is_loopback:
            net = ipaddress.ip_network(f"{local_ip}/24", strict=False)
            return str(net)
    except Exception:
        pass
    return "192.168.1.0/24"


DB_PATH = _default_db_path()
_lock = threading.Lock()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def get_conn() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def _parse_cidr_bounds(cidr: str) -> tuple[str, str]:
    net = ipaddress.ip_network(cidr.strip(), strict=False)
    hosts = list(net.hosts())
    if hosts:
        return str(hosts[0]), str(hosts[-1])
    return str(net.network_address), str(net.broadcast_address)


def init_db() -> None:
    with _lock, get_conn() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS subnets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                cidr TEXT NOT NULL UNIQUE,
                start_ip TEXT NOT NULL,
                end_ip TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                color TEXT NOT NULL DEFAULT '#2563eb',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS devices (
                ipv4 TEXT PRIMARY KEY,
                ipv6 TEXT DEFAULT '',
                mac TEXT DEFAULT '',
                custom_hostname TEXT DEFAULT '',
                vendor TEXT DEFAULT '',
                identification TEXT DEFAULT '',
                dns_name TEXT DEFAULT '',
                mdns_name TEXT DEFAULT '',
                smb_name TEXT DEFAULT '',
                smb_domain TEXT DEFAULT '',
                subnet_cidr TEXT DEFAULT '',
                is_online INTEGER NOT NULL DEFAULT 0,
                ping_ms REAL,
                ports_json TEXT NOT NULL DEFAULT '[]',
                last_port_scan TEXT DEFAULT '',
                comments TEXT DEFAULT '',
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS oui_cache (
                prefix TEXT PRIMARY KEY,
                vendor TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """
        )

        # Safe schema migration for existing DBs
        cols = {r[1] for r in conn.execute("PRAGMA table_info(devices)").fetchall()}
        migrations = [
            ("device_type", "TEXT DEFAULT 'unknown'"),
            ("extra_json", "TEXT DEFAULT '{}'"),
            ("location", "TEXT DEFAULT ''"),
            ("admin_url", "TEXT DEFAULT ''"),
            ("admin_user", "TEXT DEFAULT ''"),
            ("admin_password", "TEXT DEFAULT ''"),
            ("type_locked", "INTEGER DEFAULT 0"),
        ]
        for col_name, col_def in migrations:
            if col_name not in cols:
                conn.execute(f"ALTER TABLE devices ADD COLUMN {col_name} {col_def}")

        # Seed default subnets if empty
        count = conn.execute("SELECT COUNT(*) FROM subnets").fetchone()[0]
        if count == 0:
            raw_defaults = os.environ.get(
                "DEFAULT_SUBNETS",
                f"Local Network|{_detect_local_subnet()}",
            )
            palette = ["#2563eb", "#7c3aed", "#059669", "#d97706", "#db2777", "#0891b2"]
            now = _utc_now()
            for idx, entry in enumerate(raw_defaults.split(",")):
                entry = entry.strip()
                if not entry:
                    continue
                if "|" in entry:
                    name, cidr = [p.strip() for p in entry.split("|", 1)]
                else:
                    name, cidr = entry, entry
                try:
                    start_ip, end_ip = _parse_cidr_bounds(cidr)
                    norm_cidr = str(ipaddress.ip_network(cidr, strict=False))
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO subnets (name, cidr, start_ip, end_ip, enabled, color, created_at)
                        VALUES (?, ?, ?, ?, 1, ?, ?)
                        """,
                        (name, norm_cidr, start_ip, end_ip, palette[idx % len(palette)], now),
                    )
                except ValueError:
                    continue

        defaults = {
            "auto_quick_ports": "false",
            "scan_timeout_sec": "120",
        }
        for k, v in defaults.items():
            conn.execute(
                "INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (k, v)
            )
        conn.commit()


def list_subnets() -> list[dict[str, Any]]:
    with _lock, get_conn() as conn:
        rows = conn.execute(
            "SELECT id, name, cidr, start_ip, end_ip, enabled, color, created_at FROM subnets ORDER BY id ASC"
        ).fetchall()
        return [dict(r) for r in rows]


def upsert_subnet(
    name: str,
    cidr: str,
    enabled: bool = True,
    color: str = "#2563eb",
    subnet_id: int | None = None,
) -> dict[str, Any]:
    net = ipaddress.ip_network(cidr.strip(), strict=False)
    if net.num_addresses > 4096:
        raise ValueError("El rango máximo permitido por subred es /20 (4096 direcciones).")
    norm_cidr = str(net)
    start_ip, end_ip = _parse_cidr_bounds(norm_cidr)
    now = _utc_now()

    with _lock, get_conn() as conn:
        if subnet_id is not None:
            conn.execute(
                """
                UPDATE subnets
                SET name = ?, cidr = ?, start_ip = ?, end_ip = ?, enabled = ?, color = ?
                WHERE id = ?
                """,
                (name.strip(), norm_cidr, start_ip, end_ip, int(enabled), color, subnet_id),
            )
            row = conn.execute("SELECT * FROM subnets WHERE id = ?", (subnet_id,)).fetchone()
        else:
            conn.execute(
                """
                INSERT INTO subnets (name, cidr, start_ip, end_ip, enabled, color, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(cidr) DO UPDATE SET
                    name = excluded.name,
                    enabled = excluded.enabled,
                    color = excluded.color
                """,
                (name.strip(), norm_cidr, start_ip, end_ip, int(enabled), color, now),
            )
            row = conn.execute("SELECT * FROM subnets WHERE cidr = ?", (norm_cidr,)).fetchone()
        conn.commit()
        return dict(row)


def delete_subnet(subnet_id: int) -> None:
    with _lock, get_conn() as conn:
        conn.execute("DELETE FROM subnets WHERE id = ?", (subnet_id,))
        conn.commit()


def _row_to_device(row: sqlite3.Row) -> dict[str, Any]:
    d = dict(row)
    try:
        d["ports"] = json.loads(d.pop("ports_json") or "[]")
    except Exception:
        d["ports"] = []
    try:
        d["extra"] = json.loads(d.pop("extra_json", "{}") or "{}")
    except Exception:
        d["extra"] = {}
    d["device_type"] = d.get("device_type") or "unknown"
    d["location"] = d.get("location") or ""
    d["admin_url"] = d.get("admin_url") or ""
    d["admin_user"] = d.get("admin_user") or ""
    d["admin_password"] = d.get("admin_password") or ""
    d["type_locked"] = bool(d.get("type_locked", 0))
    d["is_online"] = bool(d["is_online"])
    return d


def list_devices() -> list[dict[str, Any]]:
    with _lock, get_conn() as conn:
        rows = conn.execute("SELECT * FROM devices").fetchall()
        devices = [_row_to_device(r) for r in rows]

    def ip_sort_key(dev: dict[str, Any]) -> tuple[int, str]:
        try:
            return (int(ipaddress.IPv4Address(dev["ipv4"])), dev["ipv4"])
        except Exception:
            return (0, dev["ipv4"])

    devices.sort(key=ip_sort_key)
    return devices


def get_device(ipv4: str) -> dict[str, Any] | None:
    with _lock, get_conn() as conn:
        row = conn.execute("SELECT * FROM devices WHERE ipv4 = ?", (ipv4,)).fetchone()
        return _row_to_device(row) if row else None


def mark_subnet_offline(subnet_cidr: str, seen_ips: set[str]) -> None:
    """Mark devices in a scanned subnet as offline if they did not respond."""
    with _lock, get_conn() as conn:
        rows = conn.execute(
            "SELECT ipv4 FROM devices WHERE subnet_cidr = ?", (subnet_cidr,)
        ).fetchall()
        net = ipaddress.ip_network(subnet_cidr, strict=False)
        all_rows = conn.execute("SELECT ipv4 FROM devices").fetchall()
        target_ips = {r["ipv4"] for r in rows}
        for r in all_rows:
            try:
                if ipaddress.IPv4Address(r["ipv4"]) in net:
                    target_ips.add(r["ipv4"])
            except Exception:
                pass
        for ip in target_ips:
            if ip not in seen_ips:
                conn.execute(
                    "UPDATE devices SET is_online = 0, ping_ms = NULL WHERE ipv4 = ?",
                    (ip,),
                )
        conn.commit()


def upsert_device(data: dict[str, Any]) -> dict[str, Any]:
    ipv4 = data["ipv4"].strip()
    now = _utc_now()
    with _lock, get_conn() as conn:
        existing = conn.execute("SELECT * FROM devices WHERE ipv4 = ?", (ipv4,)).fetchone()
        if existing:
            ex = dict(existing)
            # Keep existing non-empty values when a new scan didn't capture them (e.g. across subnets)
            mac = data.get("mac") or ex["mac"] or ""
            vendor = data.get("vendor") or ex["vendor"] or ""
            identification = data.get("identification") or ex["identification"] or ""
            dns_name = data.get("dns_name") or ex["dns_name"] or ""
            mdns_name = data.get("mdns_name") or ex["mdns_name"] or ""
            smb_name = data.get("smb_name") or ex["smb_name"] or ""
            smb_domain = data.get("smb_domain") or ex["smb_domain"] or ""
            ipv6 = data.get("ipv6") or ex["ipv6"] or ""
            subnet_cidr = data.get("subnet_cidr") or ex["subnet_cidr"] or ""
            is_online = int(data.get("is_online", ex["is_online"]))
            ping_ms = data.get("ping_ms") if "ping_ms" in data else ex["ping_ms"]
            last_seen = now if is_online else ex["last_seen"]

            ports_json = ex["ports_json"]
            last_port_scan = ex["last_port_scan"]
            if "ports" in data and data["ports"] is not None:
                ports_json = json.dumps(data["ports"])
                last_port_scan = now

            conn.execute(
                """
                UPDATE devices SET
                    ipv6 = ?, mac = ?, vendor = ?, identification = ?,
                    dns_name = ?, mdns_name = ?, smb_name = ?, smb_domain = ?,
                    subnet_cidr = ?, is_online = ?, ping_ms = ?,
                    ports_json = ?, last_port_scan = ?, last_seen = ?
                WHERE ipv4 = ?
                """,
                (
                    ipv6, mac, vendor, identification,
                    dns_name, mdns_name, smb_name, smb_domain,
                    subnet_cidr, is_online, ping_ms,
                    ports_json, last_port_scan, last_seen,
                    ipv4,
                ),
            )
        else:
            ports_json = json.dumps(data.get("ports") or [])
            last_port_scan = now if data.get("ports") else ""
            conn.execute(
                """
                INSERT INTO devices (
                    ipv4, ipv6, mac, custom_hostname, vendor, identification,
                    dns_name, mdns_name, smb_name, smb_domain, subnet_cidr,
                    is_online, ping_ms, ports_json, last_port_scan, comments,
                    first_seen, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ipv4,
                    data.get("ipv6", ""),
                    data.get("mac", ""),
                    data.get("custom_hostname", ""),
                    data.get("vendor", ""),
                    data.get("identification", ""),
                    data.get("dns_name", ""),
                    data.get("mdns_name", ""),
                    data.get("smb_name", ""),
                    data.get("smb_domain", ""),
                    data.get("subnet_cidr", ""),
                    int(data.get("is_online", True)),
                    data.get("ping_ms"),
                    ports_json,
                    last_port_scan,
                    data.get("comments", ""),
                    now,
                    now,
                ),
            )
        conn.commit()
        row = conn.execute("SELECT * FROM devices WHERE ipv4 = ?", (ipv4,)).fetchone()
        return _row_to_device(row)


def update_device_meta(
    ipv4: str,
    custom_hostname: str | None = None,
    comments: str | None = None,
    device_type: str | None = None,
    vendor: str | None = None,
    identification: str | None = None,
    location: str | None = None,
    admin_url: str | None = None,
    admin_user: str | None = None,
    admin_password: str | None = None,
) -> dict[str, Any] | None:
    with _lock, get_conn() as conn:
        row = conn.execute("SELECT * FROM devices WHERE ipv4 = ?", (ipv4,)).fetchone()
        if not row:
            return None
        r = dict(row)
        new_host = r["custom_hostname"] if custom_hostname is None else custom_hostname.strip()
        new_comm = r["comments"] if comments is None else comments.strip()
        new_type = r.get("device_type") or "unknown"
        new_locked = int(r.get("type_locked") or 0)
        if device_type is not None and device_type.strip():
            new_type = device_type.strip()
            new_locked = 1
        new_vendor = r["vendor"] if vendor is None else vendor.strip()
        new_ident = r["identification"] if identification is None else identification.strip()
        new_loc = (r.get("location") or "") if location is None else location.strip()
        new_url = (r.get("admin_url") or "") if admin_url is None else admin_url.strip()
        new_user = (r.get("admin_user") or "") if admin_user is None else admin_user.strip()
        new_pass = (r.get("admin_password") or "") if admin_password is None else admin_password
        conn.execute(
            """
            UPDATE devices
            SET custom_hostname = ?, comments = ?, device_type = ?, type_locked = ?,
                vendor = ?, identification = ?, location = ?, admin_url = ?,
                admin_user = ?, admin_password = ?
            WHERE ipv4 = ?
            """,
            (
                new_host, new_comm, new_type, new_locked,
                new_vendor, new_ident, new_loc, new_url,
                new_user, new_pass, ipv4,
            ),
        )
        conn.commit()
        updated = conn.execute("SELECT * FROM devices WHERE ipv4 = ?", (ipv4,)).fetchone()
        return _row_to_device(updated)


def update_device_ports(ipv4: str, ports: list[dict[str, Any]], identification: str | None = None) -> dict[str, Any] | None:
    now = _utc_now()
    with _lock, get_conn() as conn:
        row = conn.execute("SELECT * FROM devices WHERE ipv4 = ?", (ipv4,)).fetchone()
        if not row:
            return None
        new_ident = row["identification"]
        if identification and (not new_ident or len(identification) > len(new_ident)):
            new_ident = identification
        conn.execute(
            """
            UPDATE devices
            SET ports_json = ?, last_port_scan = ?, identification = ?, is_online = 1, last_seen = ?
            WHERE ipv4 = ?
            """,
            (json.dumps(ports), now, new_ident, now, ipv4),
        )
        conn.commit()
        updated = conn.execute("SELECT * FROM devices WHERE ipv4 = ?", (ipv4,)).fetchone()
        return _row_to_device(updated)


def clear_devices(subnet_cidr: str | None = None) -> int:
    with _lock, get_conn() as conn:
        if subnet_cidr:
            cur = conn.execute("DELETE FROM devices WHERE subnet_cidr = ?", (subnet_cidr,))
        else:
            cur = conn.execute("DELETE FROM devices")
        conn.commit()
        return cur.rowcount


def get_settings() -> dict[str, str]:
    with _lock, get_conn() as conn:
        rows = conn.execute("SELECT key, value FROM settings").fetchall()
        return {r["key"]: r["value"] for r in rows}


def update_settings(updates: dict[str, str]) -> dict[str, str]:
    with _lock, get_conn() as conn:
        for k, v in updates.items():
            conn.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (k, str(v)),
            )
        conn.commit()
    return get_settings()


def update_device_enrichment(
    ipv4: str,
    device_type: str,
    extra: dict[str, Any],
    vendor: str | None = None,
    mac: str | None = None,
    identification: str | None = None,
) -> dict[str, Any] | None:
    with _lock, get_conn() as conn:
        row = conn.execute("SELECT * FROM devices WHERE ipv4 = ?", (ipv4,)).fetchone()
        if not row:
            return None
        r = dict(row)
        final_type = r["device_type"] if r.get("type_locked") else device_type
        new_vendor = vendor if vendor else r["vendor"]
        new_mac = mac if mac else r["mac"]
        cur_ident = r["identification"] or ""
        cur_is_garbage = any(
            bad in cur_ident.lower()
            for bad in ("not found", "document error", "404", "403 forbidden", "401 unauthorized", "access error")
        ) or cur_ident.strip().lower() in ("success", "webserver", "index", "login", "document", "error")
        if identification:
            new_ident = identification if (cur_is_garbage or not cur_ident or len(identification) >= len(cur_ident)) else cur_ident
        elif cur_is_garbage:
            new_ident = ""
        else:
            new_ident = cur_ident
        conn.execute(
            """
            UPDATE devices
            SET device_type = ?, extra_json = ?, vendor = ?, mac = ?, identification = ?
            WHERE ipv4 = ?
            """,
            (final_type, json.dumps(extra), new_vendor, new_mac, new_ident, ipv4),
        )
        conn.commit()
        updated = conn.execute("SELECT * FROM devices WHERE ipv4 = ?", (ipv4,)).fetchone()
        return _row_to_device(updated)


def get_cached_oui(prefix: str) -> str | None:
    with _lock, get_conn() as conn:
        row = conn.execute("SELECT vendor FROM oui_cache WHERE prefix = ?", (prefix.upper(),)).fetchone()
        return row["vendor"] if row else None


def set_cached_oui(prefix: str, vendor: str) -> None:
    with _lock, get_conn() as conn:
        conn.execute(
            "INSERT INTO oui_cache (prefix, vendor, updated_at) VALUES (?, ?, ?) ON CONFLICT(prefix) DO UPDATE SET vendor = excluded.vendor, updated_at = excluded.updated_at",
            (prefix.upper(), vendor, _utc_now()),
        )
        conn.commit()
