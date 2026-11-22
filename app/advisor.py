"""Automated Network Architecture & Security Advisor for LanScan Web."""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from typing import Any

from . import enrichment


def _mac_prefix10(mac: str) -> str:
    cleaned = (mac or "").replace(":", "").lower()
    return cleaned[:10] if len(cleaned) == 12 else ""


def analyze_network(
    subnets: list[dict[str, Any]],
    devices: list[dict[str, Any]],
) -> dict[str, Any]:
    """Analyze discovered topology, subnets, device roles, and open ports to produce actionable improvements."""
    topology = enrichment.build_topology(subnets, devices)
    findings: list[dict[str, Any]] = []

    scores = {
        "topology": 100,
        "security": 100,
        "performance": 100,
        "organization": 100,
    }

    active_subnets = [s for s in topology["subnets"] if s["total_count"] > 0]
    online_devices = [d for d in devices if d.get("is_online")]

    if not devices:
        return {
            "overall_score": 0,
            "scores": {"topology": 0, "security": 0, "performance": 0, "organization": 0},
            "summary": {
                "total_devices": 0,
                "online_devices": 0,
                "active_subnets": 0,
                "critical": 0,
                "warning": 0,
                "info": 0,
                "good": 0,
            },
            "findings": [
                {
                    "id": "no-data",
                    "severity": "info",
                    "category": "organization",
                    "title": "Ejecuta un escaneo inicial para auditar tu arquitectura",
                    "description": "Todavía no hay equipos registrados. Pulsa «Start LanScan» y luego «Enriquecer» para que el asesor analice topología, seguridad y rendimiento.",
                    "recommendation": "Inicia un escaneo en tus subredes configuradas y opcionalmente escanea puertos en tus equipos principales (router, NAS, cámaras).",
                    "affected_ips": [],
                }
            ],
            "ip_plan": [],
        }

    # ------------------------------------------------------------------
    # 1. TOPOLOGY: Double NAT / Cascaded Routers / Fragmented Subnets
    # ------------------------------------------------------------------
    cascaded = [s for s in active_subnets if s.get("cascaded_from")]
    routers = [d for d in devices if d.get("device_type") == "router"]
    if len(active_subnets) > 1 or cascaded:
        scores["topology"] -= 25
        scores["performance"] -= 10
        gw_ips = [s["gateway"]["ipv4"] for s in active_subnets if s.get("gateway") and not s["gateway"].get("virtual")]
        for r in routers:
            if r["ipv4"] not in gw_ips:
                gw_ips.append(r["ipv4"])
        sub_list = ", ".join(f"{s['name']} ({s['cidr']})" for s in active_subnets)
        findings.append(
            {
                "id": "double-nat-multi-subnet",
                "severity": "critical",
                "category": "topology",
                "title": f"Posible Doble NAT / Red fragmentada en {len(active_subnets)} subredes",
                "description": (
                    f"Se detectaron múltiples subredes activas ({sub_list}) y {len(routers)} equipo(s) de tipo router. "
                    "Cuando un router secundario corre en modo Router detrás del router principal (Doble NAT), los protocolos de descubrimiento local "
                    "(AirPlay, Chromecast, DLNA, mDNS, impresoras y Smart TVs) no se ven entre subredes y aumenta la latencia."
                ),
                "recommendation": (
                    "Configura el router secundario en modo Access Point / Bridge (AP) conectado por cable LAN-a-LAN al router principal "
                    "para unificar toda la casa bajo una sola subred, o pon el ONT/módem del ISP en modo Bridge dejando un único router principal."
                ),
                "affected_ips": gw_ips[:8],
            }
        )
    else:
        findings.append(
            {
                "id": "single-flat-subnet",
                "severity": "good",
                "category": "topology",
                "title": "Subred unificada detectada",
                "description": "Todos los equipos descubiertos operan dentro de una sola subred, lo que facilita el descubrimiento mDNS, AirPlay, DLNA e impresión local.",
                "recommendation": "Mantén tus puntos de acceso adicionales siempre en modo Access Point (AP) para conservar la red unificada.",
                "affected_ips": [],
            }
        )

    # Extra routers inside the same subnet (e.g. secondary router/repeater like TP-Link on .3.32)
    routers_by_sub: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in routers:
        routers_by_sub[r.get("subnet_cidr") or ""].append(r)
    for cidr, rlist in routers_by_sub.items():
        if len(rlist) > 1:
            scores["topology"] -= 10
            findings.append(
                {
                    "id": f"multiple-routers-{cidr}",
                    "severity": "warning",
                    "category": "topology",
                    "title": f"Múltiples routers/APs detectados en {cidr}",
                    "description": f"Hay {len(rlist)} equipos clasificados como router/AP dentro de {cidr}. Si alguno mantiene su servidor DHCP encendido, causará conflictos de IP y cortes intermitentes.",
                    "recommendation": "Verifica que solo el gateway (.1) tenga DHCP habilitado y que los equipos secundarios trabajen exclusivamente como Access Point / Switch.",
                    "affected_ips": [r["ipv4"] for r in rlist],
                }
            )

    # ------------------------------------------------------------------
    # 2. PERFORMANCE: Multi-homed NAS / Server in the same subnet
    # ------------------------------------------------------------------
    nas_or_servers_by_sub: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for d in devices:
        if d.get("device_type") == "nas":
            nas_or_servers_by_sub[d.get("subnet_cidr") or ""].append(d)

    for cidr, nlist in nas_or_servers_by_sub.items():
        if len(nlist) >= 2:
            # Check if same NAS (matching SMB name, identification, or 5-octet MAC prefix)
            groups_same: dict[str, list[dict[str, Any]]] = defaultdict(list)
            for n in nlist:
                key = (n.get("smb_name") or n.get("identification") or _mac_prefix10(n.get("mac", "")) or n["ipv4"]).lower()
                groups_same[key].append(n)
            for key, dup_nics in groups_same.items():
                if len(dup_nics) >= 2:
                    scores["performance"] -= 18
                    scores["topology"] -= 8
                    ips = [x["ipv4"] for x in dup_nics]
                    findings.append(
                        {
                            "id": f"multihomed-nas-{cidr}",
                            "severity": "warning",
                            "category": "performance",
                            "title": f"NAS con múltiples IPs en la misma subred ({', '.join(ips)})",
                            "description": (
                                "Un mismo servidor NAS tiene 2 interfaces activas con distintas IPs en la misma subred sin enlace agregado. "
                                "Esto puede generar ruteo asimétrico, anuncios DLNA/SMB duplicados y no suma velocidad en transferencias individuales."
                            ),
                            "recommendation": (
                                "Deja una sola interfaz conectada, o configura Port Trunking (Balance-alb / LACP 802.3ad si tu switch lo soporta) "
                                "para una única IP. Si tu NAS soporta 2.5GbE, un switch 2.5GbE económico multiplicará x2.5 el rendimiento real."
                            ),
                            "affected_ips": ips,
                        }
                    )

    # ------------------------------------------------------------------
    # 3. SECURITY: IoT & Cameras sharing LAN with NAS / Computers
    # ------------------------------------------------------------------
    iot_and_cams = [d for d in devices if d.get("device_type") in ("iot", "camera")]
    core_assets = [d for d in devices if d.get("device_type") in ("nas", "computer")]
    if len(iot_and_cams) >= 3:
        scores["security"] -= 18
        iot_count = sum(1 for d in iot_and_cams if d.get("device_type") == "iot")
        cam_count = sum(1 for d in iot_and_cams if d.get("device_type") == "camera")
        findings.append(
            {
                "id": "iot-camera-segmentation",
                "severity": "warning",
                "category": "security",
                "title": f"{len(iot_and_cams)} dispositivos IoT y cámaras sin aislamiento dedicado",
                "description": (
                    f"Se detectaron {iot_count} dispositivo(s) IoT (Espressif/Tuya/Smart Home) y {cam_count} cámara(s)/DVR "
                    f"en la red doméstica junto con {len(core_assets)} equipo(s) sensibles (NAS/computadoras). "
                    "Los equipos IoT y cámaras económicas suelen recibir pocas actualizaciones de firmware y son un vector frecuente de movimiento lateral."
                ),
                "recommendation": (
                    "Crea una red Wi-Fi IoT / Invitados aislada (o una VLAN dedicada para IoT/Cámaras si tu router soporta VLANs 802.1Q) "
                    "con reglas de firewall que impidan el acceso desde IoT hacia tu NAS y computadoras personales."
                ),
                "affected_ips": [d["ipv4"] for d in iot_and_cams[:10]],
            }
        )

    # ------------------------------------------------------------------
    # 4. SECURITY: Open insecure / sensitive ports across devices
    # ------------------------------------------------------------------
    ftp_ips, telnet_ips, rtsp_ips, db_ips, http_admin_ips = [], [], [], [], []
    scanned_port_devices = 0
    for d in devices:
        ports = d.get("ports") or []
        if ports:
            scanned_port_devices += 1
        pnums = {int(p["port"]) for p in ports if "port" in p}
        if 21 in pnums:
            ftp_ips.append(d["ipv4"])
        if 23 in pnums:
            telnet_ips.append(d["ipv4"])
        if 554 in pnums:
            rtsp_ips.append(d["ipv4"])
        if pnums & {3306, 5432, 6379, 27017}:
            db_ips.append(d["ipv4"])
        if 8080 in pnums and 443 in pnums and d.get("device_type") in ("nas", "router"):
            http_admin_ips.append(d["ipv4"])

    if telnet_ips:
        scores["security"] -= 25
        findings.append(
            {
                "id": "open-telnet",
                "severity": "critical",
                "category": "security",
                "title": "Puerto Telnet (23) abierto sin cifrado",
                "description": "Telnet transmite usuarios y contraseñas en texto plano por la red.",
                "recommendation": "Desactiva Telnet inmediatamente en los equipos afectados y usa SSH o HTTPS.",
                "affected_ips": telnet_ips,
            }
        )

    if ftp_ips:
        scores["security"] -= 15
        findings.append(
            {
                "id": "open-ftp",
                "severity": "warning",
                "category": "security",
                "title": "Servicio FTP sin cifrado (puerto 21) activo",
                "description": "FTP tradicional expone credenciales y transferencias en texto plano dentro de la LAN.",
                "recommendation": "Desactiva el servicio FTP si no es imprescindible, o migra a SFTP (sobre SSH puerto 22) / SMB3 cifrado.",
                "affected_ips": ftp_ips,
            }
        )

    if http_admin_ips:
        scores["security"] -= 8
        findings.append(
            {
                "id": "http-admin-alongside-https",
                "severity": "info",
                "category": "security",
                "title": "Panel administrativo accesible por HTTP (:8080) además de HTTPS",
                "description": "El servidor NAS/Router mantiene abierto el panel web sin cifrar en el puerto 8080.",
                "recommendation": "Activa «Forzar conexión segura (HTTPS)» en la configuración general del equipo para redirigir automáticamente todo el tráfico administrativo.",
                "affected_ips": http_admin_ips,
            }
        )

    if rtsp_ips:
        scores["security"] -= 8
        findings.append(
            {
                "id": "open-rtsp",
                "severity": "info",
                "category": "security",
                "title": "Streams de video RTSP (puerto 554) accesibles en la LAN",
                "description": "Se detectaron equipos con streaming RTSP abierto.",
                "recommendation": "Asegúrate de que las cámaras/DVR tengan autenticación digest habilitada, contraseñas fuertes y estén en una red aislada.",
                "affected_ips": rtsp_ips,
            }
        )

    if db_ips:
        scores["security"] -= 8
        findings.append(
            {
                "id": "exposed-db-ports",
                "severity": "info",
                "category": "security",
                "title": "Puertos de base de datos accesibles en la red local",
                "description": "Hay servicios de base de datos (MySQL/PostgreSQL/Redis/Mongo) escuchando en la LAN.",
                "recommendation": "Verifica que tengan contraseñas robustas y que nunca se reenvíen (port-forwarding) hacia Internet en el router.",
                "affected_ips": db_ips,
            }
        )

    if scanned_port_devices == 0:
        scores["security"] -= 10
        findings.append(
            {
                "id": "no-port-scans-yet",
                "severity": "info",
                "category": "security",
                "title": "Aún no se han auditado puertos abiertos",
                "description": "Ningún equipo tiene resultados de Port Scan todavía, por lo que no se pueden evaluar servicios expuestos.",
                "recommendation": "Selecciona tus equipos clave (routers, NAS, DVR/cámaras) y ejecuta «Port Scan · Rápido» en el panel Details, o activa el escaneo automático de puertos en Config.",
                "affected_ips": [d["ipv4"] for d in devices if d.get("device_type") in ("router", "nas", "camera")][:6],
            }
        )

    # ------------------------------------------------------------------
    # 5. PERFORMANCE / PRIVACY: Local DNS & Ad-blocking recommendation
    # ------------------------------------------------------------------
    has_nas = any(d.get("device_type") == "nas" for d in devices)
    has_smart_tv = any(d.get("device_type") == "tv" for d in devices)
    has_local_dns = any(
        any(int(p["port"]) == 53 for p in (d.get("ports") or []))
        and d.get("device_type") != "router"
        for d in devices
    )
    if has_nas and not has_local_dns:
        scores["performance"] -= 6
        nas_ips = [d["ipv4"] for d in devices if d.get("device_type") == "nas"]
        findings.append(
            {
                "id": "local-dns-adblocker",
                "severity": "info",
                "category": "performance",
                "title": "Oportunidad: DNS local + bloqueo de anuncios (AdGuard Home / Pi-hole)",
                "description": (
                    "Tienes un servidor NAS encendido 24/7"
                    + (" y Smart TVs en la red" if has_smart_tv else "")
                    + ", pero no se detectó un servidor DNS local dedicado."
                ),
                "recommendation": (
                    "Despliega AdGuard Home o Pi-hole en Docker en tu NAS y configúralo como DNS en el DHCP de tu router: "
                    "acelera la resolución DNS con caché local, crea nombres amigables (ej. nas.casa) y elimina anuncios en Smart TVs y móviles."
                ),
                "affected_ips": nas_ips[:2],
            }
        )

    # ------------------------------------------------------------------
    # 6. ORGANIZATION: Inventory completeness, router credentials & IP plan
    # ------------------------------------------------------------------
    unnamed = [d for d in devices if not (d.get("custom_hostname") or "").strip()]
    unknown_type = [d for d in devices if (d.get("device_type") or "unknown") == "unknown"]
    routers_no_creds = [r for r in routers if not (r.get("admin_password") or "").strip()]

    if len(unnamed) > len(devices) * 0.5:
        scores["organization"] -= 18
        findings.append(
            {
                "id": "unlabeled-devices",
                "severity": "info",
                "category": "organization",
                "title": f"{len(unnamed)} de {len(devices)} equipos sin nombre personalizado",
                "description": "Etiquetar tus equipos (ej. «Router Sala», «TV Dormitorio», «Sensor Puerta») permite detectar al instante intrusos o dispositivos desconocidos en futuros escaneos.",
                "recommendation": "Haz doble clic sobre los equipos principales o usa «Editar Equipo» para asignarles nombre, categoría y ubicación física.",
                "affected_ips": [d["ipv4"] for d in unnamed[:8]],
            }
        )
    else:
        findings.append(
            {
                "id": "well-labeled-inventory",
                "severity": "good",
                "category": "organization",
                "title": "Buen nivel de etiquetado de inventario",
                "description": f"Más de la mitad de tus equipos ({len(devices) - len(unnamed)}/{len(devices)}) ya cuentan con nombre personalizado.",
                "recommendation": "Continúa etiquetando cualquier dispositivo nuevo que aparezca en la red.",
                "affected_ips": [],
            }
        )

    if unknown_type:
        scores["organization"] -= min(15, len(unknown_type) * 3)
        findings.append(
            {
                "id": "unknown-devices",
                "severity": "info",
                "category": "organization",
                "title": f"{len(unknown_type)} equipo(s) sin categoría o marca identificada",
                "description": "Algunos equipos no expusieron banners HTTP/SMB o su MAC aún no fue sincronizada.",
                "recommendation": "Ejecuta «Enriquecer» en la barra superior (y ./scripts/macos-arp-sync.sh si usas Docker Desktop en macOS) o clasifícalos manualmente desde «Editar Equipo».",
                "affected_ips": [d["ipv4"] for d in unknown_type[:8]],
            }
        )

    if routers_no_creds:
        scores["organization"] -= 8
        findings.append(
            {
                "id": "routers-undocumented-creds",
                "severity": "info",
                "category": "organization",
                "title": f"{len(routers_no_creds)} router(s) sin credenciales documentadas localmente",
                "description": "Documentar usuario, URL de panel y contraseña real en tu base local te ahorra tiempo ante caídas de red y te ayuda a verificar que no quedaron claves de fábrica.",
                "recommendation": "Selecciona cada router, verifica que cambiaste la clave por defecto de fábrica y guarda tu acceso en «Editar Equipo».",
                "affected_ips": [r["ipv4"] for r in routers_no_creds],
            }
        )

    # Suggested DHCP IP Reservation Plan based on detected primary subnet
    primary_prefix = "192.168.1"
    if active_subnets:
        try:
            net = ipaddress.ip_network(active_subnets[0]["cidr"], strict=False)
            parts = str(net.network_address).split(".")
            primary_prefix = ".".join(parts[:3])
        except Exception:
            pass

    ip_plan = [
        {"range": f"{primary_prefix}.1", "role": "Router / Gateway Principal", "example": "ONT o Router principal con servidor DHCP"},
        {"range": f"{primary_prefix}.2 – .9", "role": "Access Points y Switches", "example": "Routers secundarios en modo AP / Bridge y switches gestionados"},
        {"range": f"{primary_prefix}.10 – .19", "role": "Servidores y NAS", "example": "QNAP / Synology / Docker / AdGuard Home (IP fija)"},
        {"range": f"{primary_prefix}.20 – .29", "role": "Cámaras IP y DVR/NVR", "example": "Hikvision, Ezviz, Wyze (idealmente en VLAN IoT/Cámaras)"},
        {"range": f"{primary_prefix}.30 – .49", "role": "Smart TVs, Impresoras y Consolas", "example": "TVs Samsung/LG, Epson, Fire TV, Nintendo"},
        {"range": f"{primary_prefix}.50 – .99", "role": "Domótica e IoT", "example": "Espressif ESP32/ESP8266, Tuya, enchufes y sensores"},
        {"range": f"{primary_prefix}.100 – .250", "role": "Pool DHCP Dinámico", "example": "Laptops, celulares, tablets e invitados"},
    ]

    # Clamp scores & sort findings by severity
    for k in scores:
        scores[k] = max(10, min(100, scores[k]))
    overall = round(
        scores["topology"] * 0.30
        + scores["security"] * 0.35
        + scores["performance"] * 0.20
        + scores["organization"] * 0.15
    )

    sev_rank = {"critical": 0, "warning": 1, "info": 2, "good": 3}
    findings.sort(key=lambda f: sev_rank.get(f["severity"], 9))

    return {
        "overall_score": overall,
        "scores": scores,
        "summary": {
            "total_devices": len(devices),
            "online_devices": len(online_devices),
            "active_subnets": len(active_subnets),
            "critical": sum(1 for f in findings if f["severity"] == "critical"),
            "warning": sum(1 for f in findings if f["severity"] == "warning"),
            "info": sum(1 for f in findings if f["severity"] == "info"),
            "good": sum(1 for f in findings if f["severity"] == "good"),
        },
        "findings": findings,
        "ip_plan": ip_plan,
    }
