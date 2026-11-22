"""Device intelligence, brand/model classification, online OUI fallback, and topology builder."""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import ssl
import time
import urllib.parse
import urllib.request
from typing import Any

from . import db

_last_oui_api_call = 0.0


def lookup_vendor_online(mac: str) -> str:
    """Fallback online MAC vendor lookup via maclookup.app with persistent SQLite cache."""
    global _last_oui_api_call
    if not mac:
        return ""
    prefix = re.sub(r"[^0-9a-fA-F]", "", mac).upper()[:6]
    if len(prefix) != 6:
        return ""
    # Skip locally-administered (randomized) MACs
    try:
        if int(prefix[:2], 16) & 0x02:
            return "MAC Privada / Aleatoria"
    except ValueError:
        return ""

    cached = db.get_cached_oui(prefix)
    if cached is not None:
        return cached

    # Respect polite rate limit (~2 req/sec)
    wait = 0.55 - (time.monotonic() - _last_oui_api_call)
    if wait > 0:
        time.sleep(wait)
    _last_oui_api_call = time.monotonic()

    url = f"https://api.maclookup.app/v2/macs/{prefix}"
    req = urllib.request.Request(url, headers={"User-Agent": "LanScanWeb/1.1"})
    try:
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            data = json.loads(resp.read(8192).decode("utf-8", errors="ignore"))
            company = (data.get("company") or "").strip()
            db.set_cached_oui(prefix, company)
            return company
    except Exception:
        return ""


def _http_get_info(url: str, timeout: float = 1.6) -> tuple[str, dict[str, str]]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": "LanScanWeb/1.1"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            body = resp.read(32768).decode("utf-8", errors="ignore")
            return body, headers
    except urllib.error.HTTPError as e:
        headers = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
        try:
            body = e.read(8192).decode("utf-8", errors="ignore")
        except Exception:
            body = ""
        return body, headers
    except Exception:
        return "", {}


def probe_tls_cert(ip: str, ports: tuple[int, ...] = (443, 8443, 8002)) -> dict[str, str]:
    """Extract CN / Organization / SAN from TLS certificate if exposed."""
    for port in ports:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=0.6) as raw_sock:
                with ctx.wrap_socket(raw_sock, server_hostname=ip) as ssock:
                    # getpeercert(False) is empty when verify_mode=CERT_NONE; parse DER lightly via ssl
                    der = ssock.getpeercert(binary_form=True)
                    if not der:
                        continue
                    # Extract printable ASCII tokens from DER Subject/Issuer for quick hints
                    text = re.findall(rb"[A-Za-z0-9._\- ]{4,64}", der)
                    decoded = [t.decode("ascii", errors="ignore").strip() for t in text]
                    interesting = [
                        s for s in decoded
                        if any(k in s.lower() for k in (
                            "qnap", "samsung", "hikvision", "ezviz", "epson", "huawei",
                            "nokia", "apple", "synology", "ubiquiti", "tp-link", "asus",
                            "mikrotik", "local", "nas", "printer", "camera", "router",
                        ))
                    ]
                    if interesting:
                        return {"port": str(port), "hint": " · ".join(dict.fromkeys(interesting[:3]))}
        except Exception:
            continue
    return {}


def probe_snmp_sysdescr(ip: str) -> str:
    """Minimal pure-Python SNMPv2c GET sysDescr.0 (1.3.6.1.2.1.1.1.0) with community 'public'."""
    # Pre-encoded SNMPv2c GET request for OID 1.3.6.1.2.1.1.1.0, community "public"
    packet = bytes.fromhex(
        "302902010104067075626c6963a01c020412345678020100020100300e300c06082b060102010101000500"
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.7)
    try:
        sock.sendto(packet, (ip, 161))
        data, _ = sock.recvfrom(2048)
        # Find OID 2b 06 01 02 01 01 01 00 and extract OCTET STRING (0x04) following it
        oid_bytes = bytes.fromhex("06082b06010201010100")
        idx = data.find(oid_bytes)
        if idx != -1:
            pos = idx + len(oid_bytes)
            if pos + 2 <= len(data) and data[pos] == 0x04:
                length = data[pos + 1]
                start = pos + 2
                if length & 0x80:
                    nbytes = length & 0x7F
                    length = int.from_bytes(data[start : start + nbytes], "big")
                    start += nbytes
                val = data[start : start + length].decode("utf-8", errors="ignore").strip()
                if val:
                    return val[:200]
    except Exception:
        pass
    finally:
        sock.close()
    return ""


def parse_samsung_model(model: str) -> dict[str, str]:
    """Decode Samsung TV model codes like UN50TU7000, UN43AU8000, QN55Q60A."""
    info: dict[str, str] = {}
    m = re.match(r"^(U[NE]|Q[NE]|L[HE])(\d{2})([A-Z]{1,2})(\d{3,4})", model.upper())
    if not m:
        return info
    prefix, inches, series, num = m.groups()
    info["size"] = f'{inches}"'
    series_years = {
        "H": "2014", "J": "2015", "K": "2016", "KU": "2016", "KS": "2016",
        "M": "2017", "MU": "2017", "N": "2018", "NU": "2018", "RU": "2019",
        "TU": "2020", "AU": "2021", "BU": "2022", "CU": "2023", "DU": "2024",
    }
    if series in series_years:
        info["year"] = series_years[series]
    if prefix.startswith("Q"):
        info["panel"] = "QLED"
    elif "U" in series or int(num) >= 6000:
        info["panel"] = "4K UHD"
    else:
        info["panel"] = "Full HD"
    return info


def deep_probe_device(ip: str) -> dict[str, Any]:
    """Actively gather detailed protocol info from a single device."""
    out: dict[str, Any] = {
        "specs": [],
        "links": [],
        "model": "",
        "mac": "",
        "identification": "",
        "protocol_type_hint": "",
    }

    # 1. Samsung SmartTV API v2 (:8001)
    try:
        with socket.create_connection((ip, 8001), timeout=0.8):
            body, _ = _http_get_info(f"http://{ip}:8001/api/v2/", timeout=2.0)
            if body and "Samsung" in body:
                data = json.loads(body)
                dev = data.get("device", {})
                model = dev.get("modelName") or dev.get("model") or ""
                tv_name = dev.get("name") or ""
                os_name = dev.get("OS") or ""
                res = dev.get("resolution") or ""
                net_type = dev.get("networkType") or ""
                wifi_mac = dev.get("wifiMac") or ""
                if wifi_mac:
                    out["mac"] = wifi_mac.lower()
                if model:
                    out["model"] = model
                out["protocol_type_hint"] = "tv"
                parsed = parse_samsung_model(model) if model else {}
                parts = ["Samsung SmartTV", model]
                if parsed.get("size"):
                    parts.append(parsed["size"])
                if os_name:
                    parts.append(f"({os_name})")
                if tv_name:
                    parts.append(tv_name)
                out["identification"] = " ".join(p for p in parts if p)
                if model:
                    out["specs"].append({"label": "Modelo TV", "value": model})
                if parsed.get("size"):
                    out["specs"].append({"label": "Pantalla", "value": f"{parsed['size']} · {parsed.get('panel', '')}".strip(" ·")})
                if parsed.get("year"):
                    out["specs"].append({"label": "Generación", "value": f"Serie {parsed['year']}"})
                if res:
                    out["specs"].append({"label": "Resolución", "value": res})
                if os_name:
                    out["specs"].append({"label": "Sistema", "value": os_name})
                if net_type:
                    out["specs"].append({"label": "Conexión", "value": "Wi-Fi" if net_type == "wireless" else net_type})
                if dev.get("developerMode") is not None:
                    out["specs"].append({"label": "Modo Desarrollador", "value": "Activo" if str(dev.get("developerMode")) == "1" else "Desactivado"})
                return out
    except Exception:
        pass

    # 2. QNAP QTS / QuTS hero (/cgi-bin/authLogin.cgi)
    for port in (8080, 80, 443):
        scheme = "https" if port == 443 else "http"
        try:
            with socket.create_connection((ip, port), timeout=0.6):
                body, _ = _http_get_info(f"{scheme}://{ip}:{port}/cgi-bin/authLogin.cgi", timeout=1.5)
                if body and ("<QDocRoot" in body or "displayModelName" in body):
                    m_mod = re.search(r"<displayModelName><!\[CDATA\[([^\]]+)\]\]></displayModelName>", body)
                    m_host = re.search(r"<hostname><!\[CDATA\[([^\]]+)\]\]></hostname>", body)
                    m_ver = re.search(r"<version><!\[CDATA\[([^\]]+)\]\]></version>", body)
                    m_build = re.search(r"<build><!\[CDATA\[([^\]]+)\]\]></build>", body)
                    mod = m_mod.group(1) if m_mod else "NAS"
                    host = m_host.group(1) if m_host else ""
                    ver = m_ver.group(1) if m_ver else ""
                    build = m_build.group(1) if m_build else ""
                    out["model"] = mod
                    out["protocol_type_hint"] = "nas"
                    prefix = mod if mod.upper().startswith("QNAP") else f"QNAP {mod}"
                    out["identification"] = prefix + (f" ({host})" if host else "") + (f" QTS {ver}" if ver else "")
                    out["specs"].append({"label": "Modelo NAS", "value": mod})
                    if ver:
                        out["specs"].append({"label": "Firmware QTS", "value": f"{ver}.{build}" if build else ver})
                    if host:
                        out["specs"].append({"label": "Nombre NAS", "value": host})
                    out["links"].append({"label": f"Panel QTS (:{port})", "url": f"{scheme}://{ip}:{port}"})
                    break
        except Exception:
            continue

    # 3. HTTP/HTTPS web banners, titles & WWW-Authenticate realms
    for scheme, port in (("http", 80), ("https", 443), ("http", 8080), ("http", 8096)):
        try:
            with socket.create_connection((ip, port), timeout=0.5):
                body, headers = _http_get_info(f"{scheme}://{ip}:{port}/", timeout=1.4)
                server = headers.get("server", "").strip()
                auth_realm = headers.get("www-authenticate", "").strip()
                title_m = re.search(r"<title[^>]*>([^<]{2,80})</title>", body, re.I)
                title = re.sub(r"\s+", " ", title_m.group(1)).strip() if title_m else ""
                if title.lower() in ("index", "login", "document", "home", "404 not found", "403 forbidden", "redirect"):
                    title = ""
                if port == 8096 and ("jellyfin" in body.lower() or "kestrel" in server.lower()):
                    out["links"].append({"label": "Jellyfin (:8096)", "url": f"http://{ip}:8096"})
                else:
                    label = f"Interfaz Web ({scheme.upper()} :{port})"
                    if not any(l["url"] == f"{scheme}://{ip}:{port}" for l in out["links"]):
                        out["links"].append({"label": label, "url": f"{scheme}://{ip}:{port}"})
                if title and not any(s["label"] == "Título Web" for s in out["specs"]):
                    out["specs"].append({"label": "Título Web", "value": title})
                if server and not any(s["label"] == "Servidor HTTP" for s in out["specs"]):
                    out["specs"].append({"label": "Servidor HTTP", "value": server})
                if auth_realm:
                    rm = re.search(r'realm="([^"]+)"', auth_realm, re.I)
                    if rm:
                        out["specs"].append({"label": "Realm Auth", "value": rm.group(1)})
                if not out["identification"]:
                    if title:
                        out["identification"] = title
                    elif server:
                        out["identification"] = server
        except Exception:
            continue

    # 4. TLS certificate hint
    cert = probe_tls_cert(ip)
    if cert.get("hint"):
        out["specs"].append({"label": f"Certificado TLS (:{cert['port']})", "value": cert["hint"]})

    # 5. SNMP sysDescr (great for Epson printers, routers, NAS)
    sysdescr = probe_snmp_sysdescr(ip)
    if sysdescr:
        out["specs"].append({"label": "SNMP sysDescr", "value": sysdescr})
        if not out["identification"]:
            out["identification"] = sysdescr[:70]

    return out


# Brand knowledge base for automatic device classification & rich contextual descriptions
BRAND_PROFILES: list[dict[str, Any]] = [
    {
        "match": ["qnap"],
        "brand": "QNAP",
        "device_type": "nas",
        "category_label": "Servidor NAS",
        "summary": "Servidor de almacenamiento en red QNAP (QTS/QuTS hero) con soporte SMB, SSH, Docker y multimedia.",
    },
    {
        "match": ["synology"],
        "brand": "Synology",
        "device_type": "nas",
        "category_label": "Servidor NAS",
        "summary": "Servidor NAS Synology (DSM).",
    },
    {
        "match": ["samsung"],
        "brand": "Samsung",
        "device_type": "tv",
        "category_label": "Televisor / Dispositivo Samsung",
        "summary": "Equipo Samsung (Smart TV Tizen, electrodoméstico o dispositivo móvil).",
    },
    {
        "match": ["nokia", "alcatel", "sagemcom", "zte", "arris", "technicolor"],
        "brand": "Nokia / ISP",
        "device_type": "router",
        "category_label": "Router / ONT Fibra",
        "summary": "Router / ONT de proveedor de internet (puerta de enlace principal).",
    },
    {
        "match": ["huawei"],
        "brand": "Huawei",
        "device_type": "router",
        "category_label": "Router / Wi-Fi Huawei",
        "summary": "Equipo de red Huawei (router Wi-Fi, mesh o dispositivo móvil).",
    },
    {
        "match": ["tp-link", "ubiquiti", "mikrotik", "netgear", "linksys", "asus", "d-link", "mercusys", "tenda"],
        "brand": "Red / Router",
        "device_type": "router",
        "category_label": "Router / Access Point",
        "summary": "Equipo de infraestructura de red (router, switch o punto de acceso Wi-Fi).",
    },
    {
        "match": ["hikvision", "dnvrs", "dahua"],
        "brand": "Hikvision",
        "device_type": "camera",
        "category_label": "Cámara IP / DVR-NVR",
        "summary": "Sistema de videovigilancia Hikvision (DVR/NVR o cámara IP, típicamente HTTP :80 y RTSP :554).",
    },
    {
        "match": ["ezviz"],
        "brand": "Ezviz",
        "device_type": "camera",
        "category_label": "Cámara Smart Ezviz",
        "summary": "Cámara de seguridad inteligente Ezviz (filial de Hikvision).",
    },
    {
        "match": ["wyze"],
        "brand": "Wyze",
        "device_type": "camera",
        "category_label": "Cámara / Smart Home Wyze",
        "summary": "Cámara IP o dispositivo domótico Wyze Labs.",
    },
    {
        "match": ["epson", "hp inc", "hewlett", "canon", "brother", "xerox", "ricoh", "kyocera"],
        "brand": "Epson / Impresora",
        "device_type": "printer",
        "category_label": "Impresora de Red",
        "summary": "Impresora multifunción en red (soporte IPP/AirPrint/Web Config).",
    },
    {
        "match": ["amazon"],
        "brand": "Amazon",
        "device_type": "media_player",
        "category_label": "Fire TV / Echo Amazon",
        "summary": "Dispositivo Amazon (Fire TV Stick, altavoz Echo/Alexa o Kindle).",
    },
    {
        "match": ["nintendo", "sony interactive", "playstation", "xbox"],
        "brand": "Nintendo",
        "device_type": "console",
        "category_label": "Consola de Videojuegos",
        "summary": "Consola de videojuegos en red (Nintendo Switch / PlayStation / Xbox).",
    },
    {
        "match": ["tuya"],
        "brand": "Tuya Smart",
        "device_type": "iot",
        "category_label": "Dispositivo Smart Home (Tuya)",
        "summary": "Dispositivo domótico Tuya Smart (enchufe, foco, interruptor o sensor Wi-Fi).",
    },
    {
        "match": ["espressif", "shenzhen bilian", "sonoff", "shelly", "broadlink"],
        "brand": "Espressif / IoT",
        "device_type": "iot",
        "category_label": "Dispositivo IoT (ESP32/ESP8266)",
        "summary": "Microcontrolador Wi-Fi Espressif — habitual en focos, enchufes inteligentes, interruptores o sensores domóticos.",
    },
    {
        "match": ["apple"],
        "brand": "Apple",
        "device_type": "computer",
        "category_label": "Dispositivo Apple",
        "summary": "Equipo Apple (MacBook, iMac, iPhone, iPad o Apple TV).",
    },
    {
        "match": ["google", "nest"],
        "brand": "Google",
        "device_type": "media_player",
        "category_label": "Google / Chromecast / Nest",
        "summary": "Dispositivo Google (Chromecast, Google TV, altavoz Nest o teléfono Pixel).",
    },
    {
        "match": ["lg innotek", "lg electronics"],
        "brand": "LG",
        "device_type": "tv",
        "category_label": "Smart TV / Electrodoméstico LG",
        "summary": "Equipo LG con módulo Wi-Fi LG Innotek (Smart TV webOS o electrodoméstico ThinQ).",
    },
    {
        "match": ["altobeam"],
        "brand": "AltoBeam",
        "device_type": "media_player",
        "category_label": "Decodificador / TV Box IoT",
        "summary": "Chipset Wi-Fi/DTV AltoBeam — frecuente en decodificadores de TV, TV Box Android o cámaras.",
    },
    {
        "match": ["liteon", "intel", "realtek", "dell", "lenovo", "hp ", "microsoft"],
        "brand": "PC / Adaptador Wi-Fi",
        "device_type": "computer",
        "category_label": "Computadora / Laptop",
        "summary": "Tarjeta de red o computadora portátil/escritorio.",
    },
]


def classify_and_enrich(
    device: dict[str, Any],
    deep_data: dict[str, Any] | None = None,
) -> tuple[str, dict[str, Any]]:
    """Combine vendor, identification, ports, hostname, and deep probes into rich metadata."""
    deep = deep_data or {}
    ip = device.get("ipv4", "")
    vendor = (device.get("vendor") or "").strip()
    ident = (deep.get("identification") or device.get("identification") or "").strip()
    hostname = (device.get("custom_hostname") or "").strip()
    smb_name = (device.get("smb_name") or "").strip()
    mdns = (device.get("mdns_name") or "").strip()
    ports = device.get("ports") or []
    port_nums = {int(p["port"]) for p in ports if "port" in p}

    combined = " ".join([vendor, ident, hostname, smb_name, mdns]).lower()

    device_type = deep.get("protocol_type_hint") or "unknown"
    brand = ""
    category_label = "Dispositivo de Red"
    summary = ""

    # Match brand profile
    for prof in BRAND_PROFILES:
        if any(k in combined for k in prof["match"]):
            brand = prof["brand"]
            if device_type == "unknown":
                device_type = prof["device_type"]
            category_label = prof["category_label"]
            summary = prof["summary"]
            break

    # Refine device_type using strong signals (IP .1 gateway, ports, hostname keywords)
    is_gateway_ip = ip.endswith(".1")
    if is_gateway_ip and device_type in ("unknown", "computer", "router"):
        device_type = "router"
        category_label = "Router / Puerta de Enlace"
        if not summary:
            summary = f"Gateway principal de la subred {device.get('subnet_cidr', '')}."

    if any(k in combined for k in ("dvr", "nvr", "camara", "cámara", "hikvision", "ezviz", "wyze")):
        device_type = "camera"
        category_label = "Cámara IP / DVR"
    elif any(k in combined for k in ("impresora", "printer", "epson", "laserjet", "deskjet")) or 9100 in port_nums or 631 in port_nums:
        device_type = "printer"
        category_label = "Impresora de Red"
    elif any(k in combined for k in ("smarttv", "tizen", "tv ", "tv40", "tv 40", "allshare", "webos")) or 8001 in port_nums or 7676 in port_nums:
        device_type = "tv"
        category_label = "Televisor Smart TV"
    elif any(k in combined for k in ("firestick", "fire tv", "chromecast", "apple tv", "roku")):
        device_type = "media_player"
        category_label = "Streaming / Media Player"
    elif any(k in combined for k in ("qnap", "synology", "truenas", "openmediavault")):
        device_type = "nas"
        category_label = "Servidor NAS"
    elif any(k in combined for k in ("macbook", "imac", "desktop", "laptop", "pc")) or 548 in port_nums:
        device_type = "computer"
        category_label = "Computadora / Mac"
    elif "mac privada" in combined or 62078 in port_nums:
        if device_type == "unknown":
            device_type = "mobile"
            category_label = "Teléfono / Tablet (MAC Privada)"
            summary = "Dispositivo móvil (iOS/Android/macOS) usando dirección MAC aleatoria para privacidad Wi-Fi."

    if not brand and vendor and vendor != "MAC Privada / Aleatoria":
        brand = vendor.split()[0].rstrip(",.")

    # Build specs list
    specs: list[dict[str, str]] = []
    if brand:
        specs.append({"label": "Marca", "value": brand})
    specs.append({"label": "Categoría", "value": category_label})

    existing_labels = {s["label"] for s in specs}
    for s in deep.get("specs") or []:
        if s["label"] not in existing_labels:
            specs.append(s)
            existing_labels.add(s["label"])

    # Security / diagnostic notes from open ports
    security_notes: list[str] = []
    if 21 in port_nums:
        security_notes.append("Puerto 21 (FTP sin cifrado) abierto — considera usar SFTP o desactivarlo si no lo usas.")
    if 23 in port_nums:
        security_notes.append("Puerto 23 (Telnet) abierto — protocolo inseguro sin cifrado.")
    if 554 in port_nums:
        security_notes.append("Puerto 554 (RTSP) expuesto — stream de cámara/DVR accesible en la LAN.")
    if 3306 in port_nums:
        security_notes.append("Puerto 3306 (MySQL) accesible desde la red local.")
    if 8080 in port_nums and 443 in port_nums and device_type == "nas":
        security_notes.append("Panel QTS accesible tanto por HTTP (:8080) como HTTPS (:443).")

    # Useful links
    links: list[dict[str, str]] = list(deep.get("links") or [])
    for p in ports:
        if p.get("web_url") and not any(l["url"] == p["web_url"] for l in links):
            links.append({"label": f"{p.get('service') or 'Web'} (:{p['port']})", "url": p["web_url"]})

    model = deep.get("model") or ""
    if model and brand:
        q = urllib.parse.quote_plus(f"{brand} {model} especificaciones")
        links.append({"label": f"Buscar ficha técnica ({model})", "url": f"https://www.google.com/search?q={q}"})

    # If Samsung TV model was parsed, build an ultra-clear summary
    if brand == "Samsung" and model:
        parsed = parse_samsung_model(model)
        if parsed.get("size"):
            summary = f"Smart TV Samsung {parsed['size']} modelo {model} ({parsed.get('panel', 'Smart TV')}, serie {parsed.get('year', 'Tizen')})."

    # Default factory credentials reference (diagnostic aid for routers/ONTs when user hasn't saved theirs)
    router_defaults_map = [
        (["nokia", "alcatel"], {"user": "admin / AdminGPON", "password": "Etiqueta trasera del ONT (o ALC#FGU)", "note": "ONT de fibra Nokia — suele usar una clave única impresa en la etiqueta física."}),
        (["huawei"], {"user": "admin / root", "password": "admin / adminHW (o clave de etiqueta Wi-Fi)", "note": "Routers Huawei recientes usan la clave definida en el primer inicio o la etiqueta inferior."}),
        (["tp-link", "mercusys"], {"user": "admin", "password": "admin (o definida en configuración inicial)", "note": "TP-Link modernos piden crear contraseña propia en el primer acceso."}),
        (["mikrotik"], {"user": "admin", "password": "(vacía) o etiqueta trasera", "note": "RouterOS 7+ trae contraseña aleatoria en la etiqueta."}),
        (["ubiquiti", "unifi"], {"user": "ubnt", "password": "ubnt", "note": "UniFi gestionado usa credenciales del controlador."}),
        (["asus"], {"user": "admin", "password": "admin", "note": "Panel web habitualmente en http://router.asus.com"}),
        (["netgear"], {"user": "admin", "password": "password", "note": "Clave impresa en la etiqueta del equipo en modelos recientes."}),
        (["linksys"], {"user": "admin", "password": "admin", "note": "Algunos modelos usan la clave Wi-Fi inicial como acceso."}),
        (["d-link"], {"user": "admin", "password": "(vacía) o admin", "note": "Modelos recientes traen clave única en la tarjeta/etiqueta."}),
        (["zte"], {"user": "admin / user", "password": "admin / user (o etiqueta ISP)", "note": "ONT/Router ZTE provisto por ISP."}),
        (["arris"], {"user": "admin", "password": "password", "note": "Módem/Router Arris."}),
    ]
    default_credentials = None
    if device_type == "router":
        for keys, creds in router_defaults_map:
            if any(k in combined for k in keys):
                default_credentials = creds
                break
        if not default_credentials:
            default_credentials = {
                "user": "admin",
                "password": "admin / password (o etiqueta del equipo)",
                "note": "Referencia genérica de fábrica. Guarda aquí tu contraseña real en «Editar equipo».",
            }

    extra = {
        "brand": brand,
        "model": model,
        "category_label": category_label,
        "summary": summary or (f"Equipo {vendor} conectado en {device.get('subnet_cidr', 'la red local')}." if vendor else "Equipo activo en la red local."),
        "specs": specs,
        "links": links,
        "security_notes": security_notes,
        "default_credentials": default_credentials,
        "enriched": True,
    }
    return device_type, extra


def build_topology(subnets: list[dict[str, Any]], devices: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a multi-subnet network topology graph with automatic cascaded-router detection."""
    sub_by_cidr = {s["cidr"]: s for s in subnets}

    # Group devices by subnet
    groups: dict[str, list[dict[str, Any]]] = {s["cidr"]: [] for s in subnets}
    for dev in devices:
        cidr = dev.get("subnet_cidr") or ""
        if cidr not in groups:
            groups[cidr] = []
        groups[cidr].append(dev)

    # Identify gateway node for each subnet (prefer .1 IP, else first router)
    gateways: dict[str, dict[str, Any]] = {}
    for cidr, devs in groups.items():
        if not cidr:
            continue
        gw_ip = ""
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            gw_ip = str(net.network_address + 1)
        except Exception:
            pass
        gw_dev = next((d for d in devs if d["ipv4"] == gw_ip), None)
        if not gw_dev:
            gw_dev = next((d for d in devs if d.get("device_type") == "router"), None)
        if gw_dev:
            gateways[cidr] = gw_dev
        else:
            # Virtual gateway node so subnet branch always has a clean hub
            sub = sub_by_cidr.get(cidr, {})
            gateways[cidr] = {
                "ipv4": gw_ip or cidr,
                "custom_hostname": f"Router {sub.get('name', cidr)}",
                "vendor": "",
                "identification": cidr,
                "device_type": "router",
                "is_online": any(d.get("is_online") for d in devs),
                "virtual": True,
                "subnet_cidr": cidr,
                "mac": "",
                "ports": [],
                "extra": {"category_label": "Router / Gateway"},
            }

    # Detect cascaded routers: if subnet B's gateway MAC shares its first 5 octets (10 hex chars)
    # with a device inside subnet A (like Huawei WAN 192.168.1.2 -> LAN 192.168.3.1)!
    parent_link: dict[str, dict[str, str]] = {}  # child_cidr -> {"parent_cidr": ..., "wan_ip": ...}
    for child_cidr, child_gw in gateways.items():
        gw_mac = (child_gw.get("mac") or "").replace(":", "").lower()
        if len(gw_mac) != 12:
            continue
        mac_prefix_10 = gw_mac[:10]
        for other_cidr, other_devs in groups.items():
            if other_cidr == child_cidr:
                continue
            for od in other_devs:
                omac = (od.get("mac") or "").replace(":", "").lower()
                if len(omac) == 12 and omac[:10] == mac_prefix_10 and od["ipv4"] != child_gw["ipv4"]:
                    parent_link[child_cidr] = {
                        "parent_cidr": other_cidr,
                        "wan_ip": od["ipv4"],
                    }
                    break
            if child_cidr in parent_link:
                break

    # Also handle the common case where WAN device is .2 on primary subnet without MAC synced yet
    # if vendor matches (e.g. Huawei on .1.2 and .3.1)
    subnet_nodes: list[dict[str, Any]] = []
    for sub in subnets:
        cidr = sub["cidr"]
        devs = groups.get(cidr, [])
        gw = gateways.get(cidr)
        children = [d for d in devs if not gw or d["ipv4"] != gw["ipv4"]]
        subnet_nodes.append(
            {
                "id": sub["id"],
                "name": sub["name"],
                "cidr": cidr,
                "color": sub["color"],
                "gateway": gw,
                "cascaded_from": parent_link.get(cidr),
                "devices": children,
                "online_count": sum(1 for d in devs if d.get("is_online")),
                "total_count": len(devs),
            }
        )

    return {
        "subnets": subnet_nodes,
        "total_devices": len(devices),
        "online_devices": sum(1 for d in devices if d.get("is_online")),
    }
