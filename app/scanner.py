"""Multi-subnet network discovery, fingerprinting, and port scanning engine."""

from __future__ import annotations

import concurrent.futures
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import urllib.request
import xml.etree.ElementTree as ET
from typing import Any, Callable

from . import db, enrichment

IS_WINDOWS = platform.system() == "Windows"
IS_MACOS = platform.system() == "Darwin"
SUBPROC_KWARGS: dict[str, Any] = (
    {"creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)}
    if IS_WINDOWS
    else {}
)

# Supplemental OUI overrides for newer devices & home networking hardware
EXTRA_OUIS: dict[str, str] = {
    "045665": "Nokia Shanghai Bell Co., Ltd.",
    "0C839A": "Huawei Device Co., Ltd.",
    "0CA64C": "Hangzhou Ezviz Software Co., Ltd.",
    "245EBE": "QNAP Systems, Inc.",
    "28395E": "Samsung Electronics Co., Ltd.",
    "3010B3": "Liteon Technology Corporation",
    "641CB0": "Samsung Electronics Co., Ltd.",
    "6C221A": "AltoBeam Inc.",
    "840D8E": "Espressif Inc.",
    "8C8590": "Apple, Inc.",
    "A41437": "Hangzhou Hikvision Digital Technology",
    "A4D73C": "Seiko Epson Corporation",
    "C095CF": "Amazon Technologies Inc.",
    "F0A35A": "Apple, Inc.",
    "F4CFA2": "Espressif Inc.",
}

_oui_cache: dict[str, str] | None = None
_oui_lock = threading.Lock()


def normalize_mac(mac: str) -> str:
    if not mac:
        return ""
    cleaned = re.sub(r"[^0-9a-fA-F]", "", mac).lower()
    if len(cleaned) != 12:
        # Handle macOS single-digit octets like "4:56:65:a6:10:e8"
        parts = re.split(r"[:\-]", mac.strip())
        if len(parts) == 6 and all(re.fullmatch(r"[0-9a-fA-F]{1,2}", p) for p in parts):
            return ":".join(p.zfill(2).lower() for p in parts)
        return ""
    if cleaned == "000000000000" or cleaned == "ffffffffffff":
        return ""
    return ":".join(cleaned[i : i + 2] for i in range(0, 12, 2))


def _load_oui_db() -> dict[str, str]:
    global _oui_cache
    with _oui_lock:
        if _oui_cache is not None:
            return _oui_cache
        table: dict[str, str] = {}
        base_dir = (
            os.path.join(sys._MEIPASS, "app")
            if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS")
            else os.path.dirname(__file__)
        )
        bundled_oui = os.path.join(base_dir, "data", "nmap-mac-prefixes")
        for path in (
            bundled_oui,
            "/usr/share/nmap/nmap-mac-prefixes",
            "/usr/share/arp-scan/ieee-oui.txt",
        ):
            if os.path.exists(path):
                try:
                    with open(path, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            line = line.strip()
                            if not line or line.startswith("#"):
                                continue
                            parts = line.split(None, 1)
                            if len(parts) == 2 and len(parts[0]) == 6:
                                table[parts[0].upper()] = parts[1].strip()
                except Exception:
                    pass
        table.update(EXTRA_OUIS)
        _oui_cache = table
        return _oui_cache


def lookup_vendor(mac: str) -> str:
    norm = normalize_mac(mac)
    if not norm:
        return ""
    prefix = norm.replace(":", "")[:6].upper()
    vendor = _load_oui_db().get(prefix, "")
    if vendor:
        return vendor
    # Check locally-administered (randomized) MAC bit (bit 1 of first octet)
    try:
        first_octet = int(prefix[:2], 16)
        if first_octet & 0x02:
            return "MAC Privada / Aleatoria"
    except ValueError:
        pass
    return ""


def _http_get(url: str, timeout: float = 1.4) -> tuple[str, dict[str, str]]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": "LanScanWeb/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            body = resp.read(32768).decode("utf-8", errors="ignore")
            return body, headers
    except Exception:
        return "", {}


def ssdp_discover(timeout: float = 2.0) -> dict[str, dict[str, str]]:
    """Discover UPnP/SSDP devices on directly attached L2 networks."""
    msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 1\r\n"
        "ST: ssdp:all\r\n\r\n"
    ).encode()
    found: dict[str, dict[str, str]] = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(timeout)
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.sendto(msg, ("239.255.255.250", 1900))
        locs: dict[str, str] = {}
        end = time.time() + timeout
        while time.time() < end:
            try:
                data, addr = sock.recvfrom(4096)
                ip = addr[0]
                text = data.decode("utf-8", errors="ignore")
                for line in text.splitlines():
                    if line.lower().startswith("location:"):
                        loc = line.split(":", 1)[1].strip()
                        if ip not in locs:
                            locs[ip] = loc
            except socket.timeout:
                break
        for ip, loc in locs.items():
            body, _ = _http_get(loc, timeout=1.2)
            if not body:
                continue
            m_name = re.search(r"<friendlyName>([^<]+)</friendlyName>", body, re.I)
            m_model = re.search(r"<modelName>([^<]+)</modelName>", body, re.I)
            m_manuf = re.search(r"<manufacturer>([^<]+)</manufacturer>", body, re.I)
            parts = [p.strip() for p in [
                m_manuf.group(1) if m_manuf else "",
                m_model.group(1) if m_model else "",
                m_name.group(1) if m_name else "",
            ] if p and p.strip()]
            if parts:
                # Deduplicate adjacent identical phrases
                dedup: list[str] = []
                for p in parts:
                    if not any(p.lower() in d.lower() for d in dedup):
                        dedup.append(p)
                found[ip] = {"identification": " · ".join(dedup[:2])}
    except Exception:
        pass
    finally:
        sock.close()
    return found


def _probe_netbios_udp_pure(ip: str) -> dict[str, str]:
    """Pure-Python RFC 1002 NetBIOS NBSTAT query (UDP 137) — works on macOS, Windows & Linux."""
    res = {"smb_name": "", "smb_domain": "", "mac": ""}
    # Standard wildcard NBSTAT request: TXID=0x1337, flags=0, QDCOUNT=1, name="*" encoded
    query = (
        b"\x13\x37\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00"
        b"\x00\x21\x00\x01"
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.8)
    try:
        sock.sendto(query, (ip, 137))
        data, _ = sock.recvfrom(1024)
        if len(data) < 57:
            return res
        num_names = data[56]
        offset = 57
        for _ in range(num_names):
            if offset + 18 > len(data):
                break
            raw_name = data[offset : offset + 15].decode("ascii", errors="ignore").strip()
            suffix = data[offset + 15]
            flags = struct.unpack("!H", data[offset + 16 : offset + 18])[0]
            is_group = bool(flags & 0x8000)
            offset += 18
            if not raw_name or raw_name.startswith("__"):
                continue
            if suffix in (0x00, 0x20) and not is_group and not res["smb_name"]:
                res["smb_name"] = raw_name
            elif suffix == 0x00 and is_group and not res["smb_domain"]:
                res["smb_domain"] = raw_name
        if offset + 6 <= len(data):
            mac_bytes = data[offset : offset + 6]
            mac_str = ":".join(f"{b:02x}" for b in mac_bytes)
            res["mac"] = normalize_mac(mac_str)
    except Exception:
        pass
    finally:
        sock.close()
    return res


def probe_netbios(ip: str) -> dict[str, str]:
    """Query NetBIOS/SMB name, domain/workgroup, and MAC via UDP 137 (pure Python, zero deps)."""
    res = _probe_netbios_udp_pure(ip)
    if res["smb_name"] or res["mac"]:
        return res
    if not shutil.which("nmblookup"):
        return res
    try:
        out = subprocess.check_output(
            ["nmblookup", "-A", ip],
            stderr=subprocess.DEVNULL,
            timeout=1.8,
            **SUBPROC_KWARGS,
        ).decode("utf-8", errors="ignore")
    except Exception:
        return res

    for line in out.splitlines():
        m_mac = re.search(r"MAC Address\s*=\s*([0-9a-fA-F\-:]{17})", line)
        if m_mac:
            res["mac"] = normalize_mac(m_mac.group(1))
            continue
        m_entry = re.match(r"^\s+(\S+)\s+<([0-9a-fA-F]{2})>\s+-\s+(<GROUP>\s+)?[BHM]", line)
        if m_entry:
            name, code, is_group = m_entry.group(1), m_entry.group(2).upper(), bool(m_entry.group(3))
            if name.startswith("__"):
                continue
            if code in ("00", "20") and not is_group and not res["smb_name"]:
                res["smb_name"] = name
            elif code == "00" and is_group and not res["smb_domain"]:
                res["smb_domain"] = name
    return res


def probe_reverse_dns(ip: str) -> str:
    try:
        old = socket.getdefaulttimeout()
        socket.setdefaulttimeout(1.0)
        try:
            host, _, _ = socket.gethostbyaddr(ip)
            if host and host != ip:
                return host
        finally:
            socket.setdefaulttimeout(old)
    except Exception:
        pass
    return ""


def probe_mdns(ip: str) -> str:
    if IS_MACOS:
        try:
            # Check if this is the local Mac itself
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect((ip, 9))
                local_ip = s.getsockname()[0]
            finally:
                s.close()
            if local_ip == ip:
                hn = subprocess.check_output(
                    ["scutil", "--get", "LocalHostName"],
                    stderr=subprocess.DEVNULL,
                    timeout=1.0,
                ).decode("utf-8", errors="ignore").strip()
                if hn:
                    return hn if hn.endswith(".local") else f"{hn}.local"
        except Exception:
            pass
    if shutil.which("avahi-resolve-address"):
        try:
            out = subprocess.check_output(
                ["avahi-resolve-address", ip],
                stderr=subprocess.DEVNULL,
                timeout=1.2,
                **SUBPROC_KWARGS,
            ).decode("utf-8", errors="ignore").strip()
            if out and "\t" in out:
                return out.split("\t", 1)[1].strip()
        except Exception:
            pass
    # On macOS & Windows, gethostbyaddr natively queries Bonjour/mDNS and LLMNR
    if IS_MACOS or IS_WINDOWS:
        hn = probe_reverse_dns(ip)
        if hn.endswith(".local"):
            return hn
    return ""


def probe_device_identification(ip: str) -> dict[str, str]:
    """Fast, safe active fingerprinting for TVs, NAS, cameras, printers, routers."""
    result: dict[str, str] = {"identification": "", "mac": ""}

    # 1. Samsung Smart TV API (Tizen) on port 8001
    try:
        with socket.create_connection((ip, 8001), timeout=0.8):
            body, _ = _http_get(f"http://{ip}:8001/api/v2/", timeout=2.0)
            if body and "Samsung" in body:
                data = json.loads(body)
                dev = data.get("device", {})
                model = dev.get("modelName") or dev.get("model") or ""
                name = dev.get("name") or ""
                os_name = dev.get("OS") or ""
                wifi_mac = normalize_mac(dev.get("wifiMac") or "")
                if wifi_mac:
                    result["mac"] = wifi_mac
                parts = ["Samsung SmartTV", model, f"({os_name})" if os_name else "", name]
                result["identification"] = " ".join(p for p in parts if p).strip()
                return result
    except Exception:
        pass

    # 2. Google Cast / Android TV / Chromecast on port 8008
    try:
        with socket.create_connection((ip, 8008), timeout=0.35):
            body, _ = _http_get(f"http://{ip}:8008/ssdp/device-desc.xml", timeout=1.2)
            if body:
                m_name = re.search(r"<friendlyName>([^<]+)</friendlyName>", body, re.I)
                m_model = re.search(r"<modelName>([^<]+)</modelName>", body, re.I)
                parts = [m_model.group(1) if m_model else "", m_name.group(1) if m_name else ""]
                ident = " · ".join(p.strip() for p in parts if p and p.strip())
                if ident:
                    result["identification"] = ident
                    return result
    except Exception:
        pass

    # 3. QNAP QTS / QuTS hero detection on 8080 or 80
    for port in (8080, 80):
        try:
            with socket.create_connection((ip, port), timeout=0.35):
                body, headers = _http_get(f"http://{ip}:{port}/cgi-bin/authLogin.cgi", timeout=1.2)
                if body and ("<QDocRoot" in body or "displayModelName" in body):
                    m_mod = re.search(r"<displayModelName><!\[CDATA\[([^\]]+)\]\]></displayModelName>", body)
                    m_host = re.search(r"<hostname><!\[CDATA\[([^\]]+)\]\]></hostname>", body)
                    m_ver = re.search(r"<version><!\[CDATA\[([^\]]+)\]\]></version>", body)
                    mod = m_mod.group(1) if m_mod else "NAS"
                    host = m_host.group(1) if m_host else ""
                    ver = m_ver.group(1) if m_ver else ""
                    result["identification"] = f"QNAP {mod}" + (f" ({host})" if host else "") + (f" QTS {ver}" if ver else "")
                    return result
        except Exception:
            pass

    # 4. Generic HTTP/HTTPS title & Server header check (routers, printers, cameras, Jellyfin)
    for scheme, port in (("http", 80), ("https", 443), ("http", 8080), ("http", 8096)):
        try:
            with socket.create_connection((ip, port), timeout=0.35):
                body, headers = _http_get(f"{scheme}://{ip}:{port}/", timeout=1.2)
                title_m = re.search(r"<title[^>]*>([^<]{2,80})</title>", body, re.I)
                raw_title = re.sub(r"\s+", " ", title_m.group(1)).strip() if title_m else ""
                title = raw_title if enrichment.is_useful_title(raw_title) else ""
                server = headers.get("server", "").strip()
                if server.lower() in ("webserver", "http"):
                    server = ""
                if title and server and server.lower() not in title.lower():
                    result["identification"] = f"{title} [{server}]"
                    return result
                if title:
                    result["identification"] = title
                    return result
                if server:
                    result["identification"] = server
                    return result
        except Exception:
            pass

    return result


def read_local_arp_table() -> dict[str, str]:
    """Cross-platform native ARP table reader (Linux /proc/net/arp, macOS arp -an, Windows arp -a)."""
    table: dict[str, str] = {}
    if os.path.exists("/proc/net/arp"):
        try:
            with open("/proc/net/arp", "r", encoding="utf-8", errors="ignore") as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4:
                        mac = normalize_mac(parts[3])
                        if mac:
                            table[parts[0]] = mac
        except Exception:
            pass
        return table

    if IS_MACOS:
        try:
            out = subprocess.check_output(
                ["arp", "-an"], stderr=subprocess.DEVNULL, timeout=3.0
            ).decode("utf-8", errors="ignore")
            for line in out.splitlines():
                m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]+)", line)
                if m:
                    mac = normalize_mac(m.group(2))
                    if mac:
                        table[m.group(1)] = mac
        except Exception:
            pass
        return table

    if IS_WINDOWS:
        try:
            out = subprocess.check_output(
                ["arp", "-a"], stderr=subprocess.DEVNULL, timeout=3.0, **SUBPROC_KWARGS
            ).decode("utf-8", errors="ignore")
            for line in out.splitlines():
                m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})", line)
                if m:
                    mac = normalize_mac(m.group(2))
                    if mac:
                        table[m.group(1)] = mac
        except Exception:
            pass
    return table


def _probe_single_host_alive(ip: str, stop_event: threading.Event) -> dict[str, Any] | None:
    """Zero-false-positive cross-platform liveness check (macOS, Windows, Linux & Docker NAT)."""
    if stop_event.is_set():
        return None

    # 1. Cross-platform ICMP Echo Request
    if IS_WINDOWS:
        ping_cmd = ["ping", "-n", "1", "-w", "750", ip]
    elif IS_MACOS:
        ping_cmd = ["ping", "-c", "1", "-W", "750", ip]
    else:
        ping_cmd = ["ping", "-c", "1", "-W", "1", ip]

    try:
        out = subprocess.check_output(
            ping_cmd,
            stderr=subprocess.DEVNULL,
            timeout=1.8,
            **SUBPROC_KWARGS,
        ).decode("utf-8", errors="ignore")
        # Support English (time=...) and Spanish/localized Windows (tiempo=...)
        m_rtt = re.search(r"(?:time|tiempo|temps|zeit)[=<]\s*([0-9.]+)\s*ms", out, re.I)
        if m_rtt or "ttl=" in out.lower():
            ping_ms = round(float(m_rtt.group(1)), 2) if m_rtt else 1.0
            return {"ipv4": ip, "ipv6": "", "mac": "", "vendor": "", "dns_name": "", "ping_ms": ping_ms}
    except Exception:
        pass

    if stop_event.is_set():
        return None

    # 2. Real TCP connect() on common ports (catches ICMP-firewalled phones, TVs, printers, NAS)
    probe_ports = (80, 443, 22, 445, 548, 8001, 8008, 8080, 8096, 554, 631, 9100, 62078)
    for port in probe_ports:
        if stop_event.is_set():
            return None
        t0 = time.monotonic()
        try:
            with socket.create_connection((ip, port), timeout=0.22):
                rtt = round((time.monotonic() - t0) * 1000.0, 2)
                return {"ipv4": ip, "ipv6": "", "mac": "", "vendor": "", "dns_name": "", "ping_ms": rtt}
        except Exception:
            continue

    return None


def _arp_discover_local_l2(cidr: str) -> dict[str, str]:
    """Run L2 ARP discovery on Linux host mode (when nmap + ip are installed)."""
    found: dict[str, str] = {}
    if IS_WINDOWS or IS_MACOS or not shutil.which("ip") or not shutil.which("nmap"):
        return found
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        out = subprocess.check_output(["ip", "-o", "-4", "addr", "show"], stderr=subprocess.DEVNULL, timeout=2).decode("utf-8", errors="ignore")
        attached = False
        for line in out.splitlines():
            m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
            if m:
                iface_ip = ipaddress.IPv4Address(m.group(1))
                if iface_ip in net:
                    attached = True
                    break
        if not attached:
            return found

        xml_out = subprocess.check_output(
            ["nmap", "-sn", "-PR", "--max-retries", "1", "-oX", "-", cidr],
            stderr=subprocess.DEVNULL,
            timeout=20,
        ).decode("utf-8", errors="ignore")
        root = ET.fromstring(xml_out)
        for h in root.findall("host"):
            status = h.find("status")
            if status is None or status.attrib.get("state") != "up":
                continue
            if status.attrib.get("reason") not in ("arp-response", "localhost-response"):
                continue
            ipv4 = mac = ""
            for addr in h.findall("address"):
                if addr.attrib.get("addrtype") == "ipv4":
                    ipv4 = addr.attrib.get("addr", "")
                elif addr.attrib.get("addrtype") == "mac":
                    mac = normalize_mac(addr.attrib.get("addr", ""))
            if ipv4:
                found[ipv4] = mac
    except Exception:
        pass
    return found


def _nmap_discover_subnet(cidr: str, stop_event: threading.Event) -> list[dict[str, Any]]:
    """Fast, accurate host discovery across usable IPs with zero Docker-NAT false positives."""
    if stop_event.is_set():
        return []

    net = ipaddress.ip_network(cidr, strict=False)
    usable_ips = [str(ip) for ip in net.hosts()]
    if not usable_ips:
        return []

    # Step 1: L2 ARP discovery if directly attached (Linux / QNAP host network)
    l2_arp = _arp_discover_local_l2(cidr)

    # Step 2: Fast parallel ICMP + real TCP connect discovery (works on both macOS Docker Desktop & Linux)
    hosts_by_ip: dict[str, dict[str, Any]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as pool:
        futs = {pool.submit(_probe_single_host_alive, ip, stop_event): ip for ip in usable_ips}
        for fut in concurrent.futures.as_completed(futs):
            if stop_event.is_set():
                break
            try:
                res = fut.result()
                if res:
                    hosts_by_ip[res["ipv4"]] = res
            except Exception:
                pass

    # Merge any L2 ARP-only hosts (e.g. hosts blocking both ICMP and common TCP ports)
    for ip, mac in l2_arp.items():
        if ip in hosts_by_ip:
            if mac and not hosts_by_ip[ip]["mac"]:
                hosts_by_ip[ip]["mac"] = mac
        else:
            hosts_by_ip[ip] = {
                "ipv4": ip,
                "ipv6": "",
                "mac": mac,
                "vendor": lookup_vendor(mac),
                "dns_name": "",
                "ping_ms": None,
            }

    return list(hosts_by_ip.values())


COMMON_SERVICES: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 123: "ntp", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 161: "snmp", 443: "https", 445: "smb", 515: "printer",
    548: "afp", 554: "rtsp", 631: "ipp", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1883: "mqtt", 2049: "nfs", 3000: "http", 3306: "mysql",
    3389: "rdp", 5000: "upnp/http", 5353: "mdns", 5432: "postgresql",
    5900: "vnc", 6379: "redis", 7000: "airplay", 7676: "samsung-upnp",
    7678: "samsung-upnp", 8000: "http-alt", 8001: "samsung-tv",
    8002: "samsung-tv-tls", 8008: "chromecast", 8080: "http-proxy",
    8081: "http-alt", 8096: "jellyfin", 8123: "home-assistant", 8200: "dlna/upnp",
    8443: "https-alt", 8787: "lanscan-web", 8888: "http-alt", 9000: "http-alt",
    9090: "web-admin", 9100: "jetdirect", 9197: "samsung-dlna", 27017: "mongodb",
    32400: "plex", 49152: "upnp", 62078: "iphone-sync",
}


def _expand_port_list(spec: str) -> list[int]:
    ports: set[int] = set()
    for token in spec.split(","):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            a, b = token.split("-", 1)
            lo, hi = max(1, int(a)), min(65535, int(b))
            if lo <= hi:
                ports.update(range(lo, hi + 1))
        else:
            p = int(token)
            if 1 <= p <= 65535:
                ports.add(p)
    return sorted(ports)


def _grab_tcp_banner(ip: str, port: int) -> str:
    try:
        with socket.create_connection((ip, port), timeout=0.6) as s:
            s.settimeout(0.5)
            if port in (80, 8080, 8081, 8096, 8000, 8001, 8123, 8787, 9000, 3000, 32400):
                s.sendall(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
            data = s.recv(512).decode("utf-8", errors="ignore").strip()
            if not data:
                return ""
            for line in data.splitlines():
                if line.lower().startswith("server:"):
                    return line.split(":", 1)[1].strip()[:80]
            first = re.sub(r"[\r\n\t]+", " ", data.splitlines()[0]).strip()
            return first[:80]
    except Exception:
        return ""


def _python_scan_ports(ipv4: str, port_list: list[int]) -> list[dict[str, Any]]:
    """Pure-Python concurrent TCP port scanner (zero external dependencies for macOS/Windows)."""
    open_nums: list[int] = []

    def check_one(p: int) -> int | None:
        try:
            with socket.create_connection((ipv4, p), timeout=0.35):
                return p
        except Exception:
            return None

    workers = min(128, max(16, len(port_list)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for res in pool.map(check_one, port_list):
            if res is not None:
                open_nums.append(res)

    ports: list[dict[str, Any]] = []
    for port_num in sorted(open_nums):
        service = COMMON_SERVICES.get(port_num)
        if not service:
            try:
                service = socket.getservbyport(port_num, "tcp")
            except Exception:
                service = ""
        banner = _grab_tcp_banner(ipv4, port_num)
        is_https = port_num in (443, 8443, 8002) or "https" in service
        is_http = is_https or port_num in (80, 8080, 8081, 8096, 8000, 8123, 8787, 8888, 9000, 32400) or "http" in service
        web_url = f"{'https' if is_https else 'http'}://{ipv4}:{port_num}" if is_http else ""
        ports.append(
            {
                "port": port_num,
                "protocol": "tcp",
                "state": "open",
                "service": service,
                "product": banner,
                "version": "",
                "extrainfo": "",
                "web_url": web_url,
            }
        )
    return ports


def scan_host_ports(
    ipv4: str,
    mode: str = "quick",
    custom_ports: str = "",
) -> dict[str, Any]:
    """Run TCP port + service scan using nmap if installed, or pure-Python scanner on desktop."""
    ipaddress.IPv4Address(ipv4)  # validate IP

    extra_home_ports = "21,22,23,53,80,111,135,139,443,445,515,548,554,631,1433,1883,2049,3000,3306,3389,5000,5353,5432,5900,6379,7000,7676,7678,8000,8001,8002,8008,8080,8081,8096,8123,8200,8443,8787,8888,9000,9090,9100,9197,27017,32400,49152,62078"

    if mode == "custom" and custom_ports.strip():
        cleaned = re.sub(r"\s+", "", custom_ports)
        if not re.fullmatch(r"[0-9,\-]+", cleaned):
            raise ValueError("Invalid port specification. Example: 22,80,443,8000-8100")
        port_args = ["-p", cleaned]
        py_ports = _expand_port_list(cleaned)
    elif mode == "common":
        port_args = ["--top-ports", "1000"]
        py_ports = sorted(set(range(1, 1025)) | set(_expand_port_list(extra_home_ports)))
    elif mode == "full":
        port_args = ["-p", "1-65535", "--min-rate", "600"]
        py_ports = list(range(1, 65536))
    else:
        port_args = ["-p", extra_home_ports]
        py_ports = _expand_port_list(extra_home_ports)

    # Pure-Python fallback when nmap is not installed (standalone macOS / Windows desktop builds)
    if not shutil.which("nmap"):
        ports = _python_scan_ports(ipv4, py_ports)
        ident = None
        if ports:
            fp = enrichment.deep_probe_device(ipv4)
            ident = fp.get("identification") or None
        updated = db.update_device_ports(ipv4, ports, identification=ident)
        if updated:
            dtype, extra = enrichment.classify_and_enrich(updated, updated.get("extra"))
            updated = db.update_device_enrichment(ipv4, dtype, extra) or updated
        return {"ipv4": ipv4, "ports": ports, "device": updated}

    # Stage 1: reliable TCP connect scan via nmap
    stage1_cmd = [
        "nmap",
        "-Pn",
        "-sT",
        "-T3",
        "--max-retries", "2",
        "--host-timeout", "90s" if mode != "full" else "240s",
        *port_args,
        "-oX", "-",
        ipv4,
    ]
    out1 = subprocess.check_output(stage1_cmd, stderr=subprocess.DEVNULL, timeout=260, **SUBPROC_KWARGS).decode("utf-8", errors="ignore")
    open_port_nums: list[int] = []
    try:
        r1 = ET.fromstring(out1)
        h1 = r1.find("host")
        if h1 is not None and h1.find("ports") is not None:
            for p in h1.find("ports").findall("port"):
                st = p.find("state")
                if st is not None and st.attrib.get("state") == "open":
                    open_port_nums.append(int(p.attrib["portid"]))
    except ET.ParseError:
        pass

    # Stage 2: light service/version detection only on confirmed open ports
    out = out1
    if open_port_nums:
        try:
            stage2_cmd = [
                "nmap",
                "-Pn",
                "-sT",
                "-sV",
                "--version-light",
                "-T3",
                "-p", ",".join(str(p) for p in open_port_nums),
                "--host-timeout", "45s",
                "-oX", "-",
                ipv4,
            ]
            out = subprocess.check_output(stage2_cmd, stderr=subprocess.DEVNULL, timeout=55, **SUBPROC_KWARGS).decode("utf-8", errors="ignore")
        except Exception:
            out = out1
    ports: list[dict[str, Any]] = []
    os_hint = ""
    try:
        root = ET.fromstring(out)
        host_el = root.find("host")
        if host_el is not None:
            ports_el = host_el.find("ports")
            if ports_el is not None:
                for p in ports_el.findall("port"):
                    state_el = p.find("state")
                    if state_el is None or state_el.attrib.get("state") != "open":
                        continue
                    port_num = int(p.attrib["portid"])
                    proto = p.attrib.get("protocol", "tcp")
                    svc_el = p.find("service")
                    service = svc_el.attrib.get("name", "") if svc_el is not None else ""
                    product = svc_el.attrib.get("product", "") if svc_el is not None else ""
                    version = svc_el.attrib.get("version", "") if svc_el is not None else ""
                    extrainfo = svc_el.attrib.get("extrainfo", "") if svc_el is not None else ""
                    ostype = svc_el.attrib.get("ostype", "") if svc_el is not None else ""
                    if ostype and not os_hint:
                        os_hint = ostype
                    is_https = port_num in (443, 8443, 8002) or "https" in service or "ssl" in service
                    is_http = is_https or port_num in (80, 8080, 8081, 8096, 8000, 8123, 8787, 8888, 9000, 32400) or "http" in service
                    web_url = f"{'https' if is_https else 'http'}://{ipv4}:{port_num}" if is_http else ""
                    ports.append(
                        {
                            "port": port_num,
                            "protocol": proto,
                            "state": "open",
                            "service": service,
                            "product": product,
                            "version": version,
                            "extrainfo": extrainfo,
                            "web_url": web_url,
                        }
                    )
    except ET.ParseError:
        pass

    ports.sort(key=lambda x: x["port"])
    ident = None
    if ports:
        # Try enriching identification if host didn't have one
        fp = probe_device_identification(ipv4)
        ident = fp.get("identification") or (f"OS: {os_hint}" if os_hint else None)

    updated = db.update_device_ports(ipv4, ports, identification=ident)
    if updated:
        dtype, extra = enrichment.classify_and_enrich(updated, updated.get("extra"))
        updated = db.update_device_enrichment(ipv4, dtype, extra) or updated
    return {
        "ipv4": ipv4,
        "ports": ports,
        "device": updated,
    }


class ScanManager:
    """Coordinates background multi-subnet scans and streams live events."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._listeners: list[Callable[[dict[str, Any]], None]] = []
        self.state: dict[str, Any] = {
            "running": False,
            "current_subnet": "",
            "current_range": "",
            "progress": 0,
            "total_subnets": 0,
            "completed_subnets": 0,
            "found_count": 0,
            "message": "Listo para escanear",
        }

    def subscribe(self, cb: Callable[[dict[str, Any]], None]) -> None:
        with self._lock:
            self._listeners.append(cb)

    def unsubscribe(self, cb: Callable[[dict[str, Any]], None]) -> None:
        with self._lock:
            if cb in self._listeners:
                self._listeners.remove(cb)

    def emit(self, event_type: str, payload: dict[str, Any]) -> None:
        msg = {"type": event_type, "data": payload}
        with self._lock:
            listeners = list(self._listeners)
        for cb in listeners:
            try:
                cb(msg)
            except Exception:
                pass

    def start_scan(self, subnet_ids: list[int] | None = None) -> bool:
        with self._lock:
            if self.state["running"]:
                return False
            all_subnets = db.list_subnets()
            if subnet_ids:
                targets = [s for s in all_subnets if s["id"] in subnet_ids]
            else:
                targets = [s for s in all_subnets if s["enabled"]]
            if not targets:
                return False

            self._stop_event.clear()
            self.state.update(
                {
                    "running": True,
                    "current_subnet": targets[0]["cidr"],
                    "current_range": f"{targets[0]['start_ip']} a {targets[0]['end_ip']}",
                    "progress": 5,
                    "total_subnets": len(targets),
                    "completed_subnets": 0,
                    "found_count": 0,
                    "message": f"Escaneando {targets[0]['name']} ({targets[0]['cidr']})...",
                }
            )
            self._thread = threading.Thread(
                target=self._run_scan, args=(targets,), daemon=True
            )
            self._thread.start()
            return True

    def stop_scan(self) -> None:
        self._stop_event.set()
        with self._lock:
            self.state["message"] = "Deteniendo escaneo..."
        self.emit("status", dict(self.state))

    def _run_scan(self, targets: list[dict[str, Any]]) -> None:
        self.emit("status", dict(self.state))
        settings = db.get_settings()
        auto_quick_ports = settings.get("auto_quick_ports") == "true"

        # One fast SSDP multicast pass on local segment
        ssdp_map = ssdp_discover(timeout=1.6)
        arp_map = read_local_arp_table()

        total_found = 0
        total_subnets = len(targets)

        try:
            for idx, sub in enumerate(targets):
                if self._stop_event.is_set():
                    break
                cidr = sub["cidr"]
                with self._lock:
                    self.state.update(
                        {
                            "current_subnet": cidr,
                            "current_range": f"{sub['start_ip']} a {sub['end_ip']}",
                            "progress": int((idx / total_subnets) * 100) + 5,
                            "message": f"Descubriendo equipos en {sub['name']} ({sub['start_ip']} – {sub['end_ip']})...",
                        }
                    )
                self.emit("status", dict(self.state))

                discovered = _nmap_discover_subnet(cidr, self._stop_event)
                if self._stop_event.is_set():
                    break

                # Refresh ARP map after nmap discovery
                arp_map.update(read_local_arp_table())
                seen_ips = {h["ipv4"] for h in discovered}
                db.mark_subnet_offline(cidr, seen_ips)

                total_hosts = max(1, len(discovered))

                def enrich_one(host_info: dict[str, Any]) -> dict[str, Any]:
                    ip = host_info["ipv4"]
                    mac = host_info["mac"] or arp_map.get(ip, "")
                    nb = probe_netbios(ip)
                    if not mac and nb["mac"]:
                        mac = nb["mac"]
                    deep = enrichment.deep_probe_device(ip)
                    if not mac and deep.get("mac"):
                        mac = normalize_mac(deep["mac"])

                    vendor = host_info["vendor"] or lookup_vendor(mac)
                    if mac and not vendor:
                        vendor = enrichment.lookup_vendor_online(mac)
                    dns_name = host_info["dns_name"] or probe_reverse_dns(ip)
                    mdns_name = probe_mdns(ip)
                    raw_ident = deep.get("identification") or ssdp_map.get(ip, {}).get("identification", "")
                    ident = raw_ident if enrichment.is_useful_title(raw_ident) else ""

                    saved = db.upsert_device(
                        {
                            "ipv4": ip,
                            "ipv6": host_info["ipv6"],
                            "mac": mac,
                            "vendor": vendor,
                            "identification": ident,
                            "dns_name": dns_name,
                            "mdns_name": mdns_name,
                            "smb_name": nb["smb_name"],
                            "smb_domain": nb["smb_domain"],
                            "subnet_cidr": cidr,
                            "is_online": True,
                            "ping_ms": host_info["ping_ms"],
                        }
                    )
                    dtype, extra = enrichment.classify_and_enrich(saved, deep)
                    inferred_vendor = saved.get("vendor") or extra.get("brand") or None
                    best_ident = ident or (
                        f"{extra.get('brand', '')} {extra.get('model', '')}".strip()
                        if extra.get("model")
                        else (f"{extra.get('brand')} · {extra.get('category_label')}" if extra.get("brand") else None)
                    )
                    saved = db.update_device_enrichment(
                        ip,
                        dtype,
                        extra,
                        vendor=inferred_vendor,
                        mac=mac or None,
                        identification=best_ident,
                    ) or saved
                    return saved

                done_count = 0
                discovered_online_ips: list[str] = []
                with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
                    futures = [pool.submit(enrich_one, h) for h in discovered]
                    for fut in concurrent.futures.as_completed(futures):
                        if self._stop_event.is_set():
                            break
                        try:
                            dev = fut.result()
                            done_count += 1
                            total_found += 1
                            discovered_online_ips.append(dev["ipv4"])
                            max_phase1 = 72 if auto_quick_ports else 98
                            pct = int(((idx + (done_count / total_hosts)) / total_subnets) * max_phase1)
                            with self._lock:
                                self.state.update(
                                    {
                                        "progress": min(max_phase1, max(5, pct)),
                                        "found_count": total_found,
                                        "phase": "discovery",
                                        "message": f"{sub['name']}: {done_count}/{len(discovered)}",
                                    }
                                )
                            self.emit("device", dev)
                            self.emit("status", dict(self.state))
                        except Exception:
                            done_count += 1

                with self._lock:
                    self.state["completed_subnets"] = idx + 1
                self.emit("subnet_done", {"cidr": cidr, "seen": len(seen_ips)})

            # Phase 2: Automatic post-discovery Quick Port Scan when enabled
            if auto_quick_ports and not self._stop_event.is_set():
                online_targets = [
                    d["ipv4"]
                    for d in db.list_devices()
                    if d.get("is_online") and d.get("subnet_cidr") in {s["cidr"] for s in targets}
                ]
                self._run_bulk_ports_internal(online_targets, base_progress=72)

        finally:
            stopped = self._stop_event.is_set()
            with self._lock:
                self.state.update(
                    {
                        "running": False,
                        "phase": "idle",
                        "progress": 100 if not stopped else self.state["progress"],
                        "message": (
                            f"Stopped ({total_found} devices)"
                            if stopped
                            else f"Completed: {total_found} online across {total_subnets} subnet(s)"
                        ),
                    }
                )
            self.emit("scan_complete", dict(self.state))

    def _run_bulk_ports_internal(self, target_ips: list[str], base_progress: int = 5) -> None:
        if not target_ips:
            return
        total = len(target_ips)
        done = 0
        with self._lock:
            self.state.update(
                {
                    "phase": "ports",
                    "port_done": 0,
                    "port_total": total,
                    "progress": base_progress,
                    "message": f"Port Scan: 0/{total}",
                }
            )
        self.emit("status", dict(self.state))

        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            futs = {pool.submit(scan_host_ports, ip, "quick"): ip for ip in target_ips}
            for fut in concurrent.futures.as_completed(futs):
                if self._stop_event.is_set():
                    break
                done += 1
                try:
                    res = fut.result()
                    if res and res.get("device"):
                        self.emit("device", res["device"])
                except Exception:
                    pass
                pct = base_progress + int((done / max(1, total)) * (99 - base_progress))
                with self._lock:
                    self.state.update(
                        {
                            "phase": "ports",
                            "port_done": done,
                            "port_total": total,
                            "progress": min(99, pct),
                            "message": f"Port Scan: {done}/{total}",
                        }
                    )
                self.emit("status", dict(self.state))

    def start_bulk_port_scan(self) -> bool:
        with self._lock:
            if self.state["running"]:
                return False
            online_ips = [d["ipv4"] for d in db.list_devices() if d.get("is_online")]
            if not online_ips:
                return False
            self._stop_event.clear()
            self.state.update(
                {
                    "running": True,
                    "phase": "ports",
                    "port_done": 0,
                    "port_total": len(online_ips),
                    "progress": 5,
                    "message": f"Port Scan: 0/{len(online_ips)}",
                }
            )
            self._thread = threading.Thread(
                target=self._run_bulk_port_thread, args=(online_ips,), daemon=True
            )
            self._thread.start()
            return True

    def _run_bulk_port_thread(self, online_ips: list[str]) -> None:
        try:
            self._run_bulk_ports_internal(online_ips, base_progress=5)
        finally:
            stopped = self._stop_event.is_set()
            with self._lock:
                self.state.update(
                    {
                        "running": False,
                        "phase": "idle",
                        "progress": 100 if not stopped else self.state["progress"],
                        "message": f"Port Scan completed ({len(online_ips)} devices)",
                    }
                )
            self.emit("scan_complete", dict(self.state))


def deep_enrich_device(ipv4: str) -> dict[str, Any] | None:
    """Run deep protocol probing + online OUI vendor fallback + brand classification."""
    dev = db.get_device(ipv4)
    if not dev:
        return None
    deep = enrichment.deep_probe_device(ipv4)
    mac = normalize_mac(deep.get("mac") or "") or dev.get("mac") or ""
    vendor = dev.get("vendor") or lookup_vendor(mac)
    if mac and not vendor:
        vendor = enrichment.lookup_vendor_online(mac)
    if vendor:
        dev["vendor"] = vendor
    if mac:
        dev["mac"] = mac
    dtype, extra = enrichment.classify_and_enrich(dev, deep)
    final_vendor = vendor or extra.get("brand") or None
    raw_ident = deep.get("identification") or ""
    clean_ident = raw_ident if enrichment.is_useful_title(raw_ident) else ""
    best_ident = clean_ident or (
        f"{extra.get('brand', '')} {extra.get('model', '')}".strip()
        if extra.get("model")
        else (f"{extra.get('brand')} · {extra.get('category_label')}" if extra.get("brand") else None)
    )
    updated = db.update_device_enrichment(
        ipv4=ipv4,
        device_type=dtype,
        extra=extra,
        vendor=final_vendor,
        mac=mac or None,
        identification=best_ident,
    )
    return updated


scan_manager = ScanManager()
