"""Bilingual (EN / ES) Automated Network Architecture & Security Advisor for LanScan Web."""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from typing import Any

from . import enrichment


def _mac_prefix10(mac: str) -> str:
    cleaned = (mac or "").replace(":", "").lower()
    return cleaned[:10] if len(cleaned) == 12 else ""


def _pick(lang: str, en: str, es: str) -> str:
    return es if lang == "es" else en


def analyze_network(
    subnets: list[dict[str, Any]],
    devices: list[dict[str, Any]],
    lang: str = "en",
) -> dict[str, Any]:
    """Analyze discovered topology, subnets, device roles, and open ports in EN or ES."""
    lang = "es" if (lang or "").lower().startswith("es") else "en"
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
                    "title": _pick(
                        lang,
                        "Run an initial scan to audit your network architecture",
                        "Ejecuta un escaneo inicial para auditar tu arquitectura",
                    ),
                    "description": _pick(
                        lang,
                        "No devices have been recorded yet. Click «Start LanScan» and then «Enrich» so the advisor can analyze topology, security, and performance.",
                        "Todavía no hay equipos registrados. Pulsa «Start LanScan» y luego «Enriquecer» para que el asesor analice topología, seguridad y rendimiento.",
                    ),
                    "recommendation": _pick(
                        lang,
                        "Start a scan across your configured subnets and optionally run a Port Scan on key infrastructure (routers, NAS, cameras).",
                        "Inicia un escaneo en tus subredes configuradas y opcionalmente escanea puertos en tus equipos principales (router, NAS, cámaras).",
                    ),
                    "affected_ips": [],
                }
            ],
            "ip_plan": [],
        }

    # 1. TOPOLOGY: Double NAT / Cascaded Routers / Fragmented Subnets
    cascaded = [s for s in active_subnets if s.get("cascaded_from")]
    routers = [d for d in devices if d.get("device_type") == "router"]
    if len(active_subnets) > 1 or cascaded:
        scores["topology"] -= 25
        scores["performance"] -= 10
        gw_ips = [
            s["gateway"]["ipv4"]
            for s in active_subnets
            if s.get("gateway") and not s["gateway"].get("virtual")
        ]
        for r in routers:
            if r["ipv4"] not in gw_ips:
                gw_ips.append(r["ipv4"])
        sub_list = ", ".join(f"{s['name']} ({s['cidr']})" for s in active_subnets)
        findings.append(
            {
                "id": "double-nat-multi-subnet",
                "severity": "critical",
                "category": "topology",
                "title": _pick(
                    lang,
                    f"Possible Double NAT / Network fragmented across {len(active_subnets)} subnets",
                    f"Posible Doble NAT / Red fragmentada en {len(active_subnets)} subredes",
                ),
                "description": _pick(
                    lang,
                    f"Multiple active subnets were detected ({sub_list}) along with {len(routers)} router device(s). "
                    "When a secondary router operates in Router mode behind the main router (Double NAT), local discovery protocols "
                    "(AirPlay, Chromecast, DLNA, mDNS, printers, and Smart TVs) cannot see across subnets and latency increases.",
                    f"Se detectaron múltiples subredes activas ({sub_list}) y {len(routers)} equipo(s) de tipo router. "
                    "Cuando un router secundario corre en modo Router detrás del router principal (Doble NAT), los protocolos de descubrimiento local "
                    "(AirPlay, Chromecast, DLNA, mDNS, impresoras y Smart TVs) no se ven entre subredes y aumenta la latencia.",
                ),
                "recommendation": _pick(
                    lang,
                    "Switch the secondary router to Access Point / Bridge (AP) mode wired LAN-to-LAN to the primary router "
                    "to unify the home into a single flat subnet, or place the ISP ONT/modem in Bridge mode behind one main router.",
                    "Configura el router secundario en modo Access Point / Bridge (AP) conectado por cable LAN-a-LAN al router principal "
                    "para unificar toda la casa bajo una sola subred, o pon el ONT/módem del ISP en modo Bridge dejando un único router principal.",
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
                "title": _pick(lang, "Unified subnet detected", "Subred unificada detectada"),
                "description": _pick(
                    lang,
                    "All discovered devices operate within a single subnet, keeping mDNS, AirPlay, DLNA, and local printing seamless.",
                    "Todos los equipos descubiertos operan dentro de una sola subred, lo que facilita el descubrimiento mDNS, AirPlay, DLNA e impresión local.",
                ),
                "recommendation": _pick(
                    lang,
                    "Keep any additional Wi-Fi nodes in Access Point (AP) mode to preserve a clean unified network.",
                    "Mantén tus puntos de acceso adicionales siempre en modo Access Point (AP) para conservar la red unificada.",
                ),
                "affected_ips": [],
            }
        )

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
                    "title": _pick(
                        lang,
                        f"Multiple routers/APs detected in {cidr}",
                        f"Múltiples routers/APs detectados en {cidr}",
                    ),
                    "description": _pick(
                        lang,
                        f"There are {len(rlist)} router/AP devices inside {cidr}. If more than one runs a DHCP server, IP conflicts and intermittent drops will occur.",
                        f"Hay {len(rlist)} equipos clasificados como router/AP dentro de {cidr}. Si alguno mantiene su servidor DHCP encendido, causará conflictos de IP y cortes intermitentes.",
                    ),
                    "recommendation": _pick(
                        lang,
                        "Ensure only the primary gateway (.1) runs DHCP and secondary devices operate strictly as Access Points or Switches.",
                        "Verifica que solo el gateway (.1) tenga DHCP habilitado y que los equipos secundarios trabajen exclusivamente como Access Point / Switch.",
                    ),
                    "affected_ips": [r["ipv4"] for r in rlist],
                }
            )

    # 2. PERFORMANCE: Multi-homed NAS in the same subnet
    nas_by_sub: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for d in devices:
        if d.get("device_type") == "nas":
            nas_by_sub[d.get("subnet_cidr") or ""].append(d)

    for cidr, nlist in nas_by_sub.items():
        if len(nlist) >= 2:
            groups_same: dict[str, list[dict[str, Any]]] = defaultdict(list)
            for n in nlist:
                key = (
                    n.get("smb_name")
                    or n.get("identification")
                    or _mac_prefix10(n.get("mac", ""))
                    or n["ipv4"]
                ).lower()
                groups_same[key].append(n)
            for _, dup_nics in groups_same.items():
                if len(dup_nics) >= 2:
                    scores["performance"] -= 18
                    scores["topology"] -= 8
                    ips = [x["ipv4"] for x in dup_nics]
                    findings.append(
                        {
                            "id": f"multihomed-nas-{cidr}",
                            "severity": "warning",
                            "category": "performance",
                            "title": _pick(
                                lang,
                                f"NAS with multiple IPs on the same subnet ({', '.join(ips)})",
                                f"NAS con múltiples IPs en la misma subred ({', '.join(ips)})",
                            ),
                            "description": _pick(
                                lang,
                                "The same NAS has 2 active network interfaces with separate IPs on the same subnet without link aggregation. "
                                "This can cause asymmetric routing, duplicate DLNA/SMB announcements, and does not boost single-client transfer speeds.",
                                "Un mismo servidor NAS tiene 2 interfaces activas con distintas IPs en la misma subred sin enlace agregado. "
                                "Esto puede generar ruteo asimétrico, anuncios DLNA/SMB duplicados y no suma velocidad en transferencias individuales.",
                            ),
                            "recommendation": _pick(
                                lang,
                                "Use a single cable or configure Port Trunking (Balance-alb / 802.3ad LACP if supported by your switch) for one unified IP. "
                                "If your NAS has 2.5GbE ports, an affordable 2.5GbE switch yields a real 2.5x throughput boost.",
                                "Deja una sola interfaz conectada, o configura Port Trunking (Balance-alb / LACP 802.3ad si tu switch lo soporta) "
                                "para una única IP. Si tu NAS soporta 2.5GbE, un switch 2.5GbE económico multiplicará x2.5 el rendimiento real.",
                            ),
                            "affected_ips": ips,
                        }
                    )

    # 3. SECURITY: IoT & Cameras sharing LAN with NAS / Computers
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
                "title": _pick(
                    lang,
                    f"{len(iot_and_cams)} IoT devices & cameras without dedicated isolation",
                    f"{len(iot_and_cams)} dispositivos IoT y cámaras sin aislamiento dedicado",
                ),
                "description": _pick(
                    lang,
                    f"Detected {iot_count} IoT device(s) (Espressif/Tuya/Smart Home) and {cam_count} camera/DVR device(s) "
                    f"sharing the same LAN as {len(core_assets)} sensitive asset(s) (NAS/computers). "
                    "Budget IoT modules and cameras rarely receive security patches and pose a lateral movement risk.",
                    f"Se detectaron {iot_count} dispositivo(s) IoT (Espressif/Tuya/Smart Home) y {cam_count} cámara(s)/DVR "
                    f"en la red doméstica junto con {len(core_assets)} equipo(s) sensibles (NAS/computadoras). "
                    "Los equipos IoT y cámaras económicas suelen recibir pocas actualizaciones de firmware y son un vector frecuente de movimiento lateral.",
                ),
                "recommendation": _pick(
                    lang,
                    "Move cameras and IoT devices onto an isolated Guest/IoT Wi-Fi network (or a dedicated 802.1Q IoT VLAN) "
                    "with firewall rules blocking unsolicited traffic toward your NAS and personal computers.",
                    "Crea una red Wi-Fi IoT / Invitados aislada (o una VLAN dedicada para IoT/Cámaras si tu router soporta VLANs 802.1Q) "
                    "con reglas de firewall que impidan el acceso desde IoT hacia tu NAS y computadoras personales.",
                ),
                "affected_ips": [d["ipv4"] for d in iot_and_cams[:10]],
            }
        )

    # 4. SECURITY: Open insecure / sensitive ports
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
                "title": _pick(lang, "Unencrypted Telnet port (23) open", "Puerto Telnet (23) abierto sin cifrado"),
                "description": _pick(
                    lang,
                    "Telnet transmits credentials and commands in plaintext across the network.",
                    "Telnet transmite usuarios y contraseñas en texto plano por la red.",
                ),
                "recommendation": _pick(
                    lang,
                    "Disable Telnet immediately on affected devices and use SSH or HTTPS instead.",
                    "Desactiva Telnet inmediatamente en los equipos afectados y usa SSH o HTTPS.",
                ),
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
                "title": _pick(lang, "Unencrypted FTP service (port 21) active", "Servicio FTP sin cifrado (puerto 21) activo"),
                "description": _pick(
                    lang,
                    "Plain FTP exposes credentials and file transfers in cleartext on the LAN.",
                    "FTP tradicional expone credenciales y transferencias en texto plano dentro de la LAN.",
                ),
                "recommendation": _pick(
                    lang,
                    "Disable FTP if unused, or migrate to SFTP (over SSH port 22) / encrypted SMB3.",
                    "Desactiva el servicio FTP si no es imprescindible, o migra a SFTP (sobre SSH puerto 22) / SMB3 cifrado.",
                ),
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
                "title": _pick(
                    lang,
                    "Admin panel accessible over HTTP (:8080) alongside HTTPS",
                    "Panel administrativo accesible por HTTP (:8080) además de HTTPS",
                ),
                "description": _pick(
                    lang,
                    "The NAS/Router still serves its web admin interface over unencrypted HTTP port 8080.",
                    "El servidor NAS/Router mantiene abierto el panel web sin cifrar en el puerto 8080.",
                ),
                "recommendation": _pick(
                    lang,
                    "Enable «Force secure connection (HTTPS)» in general settings to automatically redirect all admin traffic.",
                    "Activa «Forzar conexión segura (HTTPS)» en la configuración general del equipo para redirigir automáticamente todo el tráfico administrativo.",
                ),
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
                "title": _pick(lang, "RTSP video streams (port 554) reachable on LAN", "Streams de video RTSP (puerto 554) accesibles en la LAN"),
                "description": _pick(
                    lang,
                    "Devices with open RTSP streaming ports were detected.",
                    "Se detectaron equipos con streaming RTSP abierto.",
                ),
                "recommendation": _pick(
                    lang,
                    "Ensure cameras/DVRs enforce strong digest authentication and live on an isolated network segment.",
                    "Asegúrate de que las cámaras/DVR tengan autenticación digest habilitada, contraseñas fuertes y estén en una red aislada.",
                ),
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
                "title": _pick(lang, "Database ports reachable on the local network", "Puertos de base de datos accesibles en la red local"),
                "description": _pick(
                    lang,
                    "Database services (MySQL/PostgreSQL/Redis/Mongo) are listening on the LAN.",
                    "Hay servicios de base de datos (MySQL/PostgreSQL/Redis/Mongo) escuchando en la LAN.",
                ),
                "recommendation": _pick(
                    lang,
                    "Verify strong passwords are set and confirm these ports are never port-forwarded to the Internet.",
                    "Verifica que tengan contraseñas robustas y que nunca se reenvíen (port-forwarding) hacia Internet en el router.",
                ),
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
                "title": _pick(lang, "Open ports have not been audited yet", "Aún no se han auditado puertos abiertos"),
                "description": _pick(
                    lang,
                    "No device has Port Scan results yet, so exposed network services cannot be fully assessed.",
                    "Ningún equipo tiene resultados de Port Scan todavía, por lo que no se pueden evaluar servicios expuestos.",
                ),
                "recommendation": _pick(
                    lang,
                    "Select key devices (routers, NAS, cameras/DVRs) and run «Port Scan · Quick» in Details, or enable auto quick port scan in Config.",
                    "Selecciona tus equipos clave (routers, NAS, DVR/cámaras) y ejecuta «Port Scan · Rápido» en el panel Details, o activa el escaneo automático de puertos en Config.",
                ),
                "affected_ips": [
                    d["ipv4"]
                    for d in devices
                    if d.get("device_type") in ("router", "nas", "camera")
                ][:6],
            }
        )

    # 5. PERFORMANCE / PRIVACY: Local DNS & Ad-blocking
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
                "title": _pick(
                    lang,
                    "Opportunity: Local DNS + Network-wide Ad Blocking (AdGuard Home / Pi-hole)",
                    "Oportunidad: DNS local + bloqueo de anuncios (AdGuard Home / Pi-hole)",
                ),
                "description": _pick(
                    lang,
                    "You already run a 24/7 NAS"
                    + (" with Smart TVs on the network" if has_smart_tv else "")
                    + ", yet no dedicated local DNS server was detected.",
                    "Tienes un servidor NAS encendido 24/7"
                    + (" y Smart TVs en la red" if has_smart_tv else "")
                    + ", pero no se detectó un servidor DNS local dedicado.",
                ),
                "recommendation": _pick(
                    lang,
                    "Deploy AdGuard Home or Pi-hole in Docker on your NAS and set it as the DHCP DNS server: speeds up lookups via local caching, adds friendly local hostnames (e.g. nas.home), and removes ads on Smart TVs and phones.",
                    "Despliega AdGuard Home o Pi-hole en Docker en tu NAS y configúralo como DNS en el DHCP de tu router: acelera la resolución DNS con caché local, crea nombres amigables (ej. nas.casa) y elimina anuncios en Smart TVs y móviles.",
                ),
                "affected_ips": nas_ips[:2],
            }
        )

    # 6. ORGANIZATION: Inventory, unknown types, router creds
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
                "title": _pick(
                    lang,
                    f"{len(unnamed)} of {len(devices)} devices lack a custom hostname",
                    f"{len(unnamed)} de {len(devices)} equipos sin nombre personalizado",
                ),
                "description": _pick(
                    lang,
                    "Labeling your devices (e.g. «Living Room Router», «Bedroom TV», «Front Door Sensor») makes it easy to spot unknown or unauthorized devices immediately.",
                    "Etiquetar tus equipos (ej. «Router Sala», «TV Dormitorio», «Sensor Puerta») permite detectar al instante intrusos o dispositivos desconocidos en futuros escaneos.",
                ),
                "recommendation": _pick(
                    lang,
                    "Double-click key devices or click «Edit Device» to assign custom hostnames, categories, and physical locations.",
                    "Haz doble clic sobre los equipos principales o usa «Editar Equipo» para asignarles nombre, categoría y ubicación física.",
                ),
                "affected_ips": [d["ipv4"] for d in unnamed[:8]],
            }
        )
    else:
        findings.append(
            {
                "id": "well-labeled-inventory",
                "severity": "good",
                "category": "organization",
                "title": _pick(lang, "Strong device inventory labeling", "Buen nivel de etiquetado de inventario"),
                "description": _pick(
                    lang,
                    f"Over half of your devices ({len(devices) - len(unnamed)}/{len(devices)}) already have custom hostnames assigned.",
                    f"Más de la mitad de tus equipos ({len(devices) - len(unnamed)}/{len(devices)}) ya cuentan con nombre personalizado.",
                ),
                "recommendation": _pick(
                    lang,
                    "Keep labeling newly discovered devices to maintain a clean inventory.",
                    "Continúa etiquetando cualquier dispositivo nuevo que aparezca en la red.",
                ),
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
                "title": _pick(
                    lang,
                    f"{len(unknown_type)} device(s) without an identified category or brand",
                    f"{len(unknown_type)} equipo(s) sin categoría o marca identificada",
                ),
                "description": _pick(
                    lang,
                    "Some devices did not expose HTTP/SMB banners or their MAC address has not been synced yet.",
                    "Algunos equipos no expusieron banners HTTP/SMB o su MAC aún no fue sincronizada.",
                ),
                "recommendation": _pick(
                    lang,
                    "Click «Enrich» in the top toolbar (and run ./scripts/macos-arp-sync.sh on macOS Docker Desktop) or classify them manually via «Edit Device».",
                    "Ejecuta «Enriquecer» en la barra superior (y ./scripts/macos-arp-sync.sh si usas Docker Desktop en macOS) o clasifícalos manualmente desde «Editar Equipo».",
                ),
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
                "title": _pick(
                    lang,
                    f"{len(routers_no_creds)} router(s) without locally documented credentials",
                    f"{len(routers_no_creds)} router(s) sin credenciales documentadas localmente",
                ),
                "description": _pick(
                    lang,
                    "Recording the admin URL, username, and password in your private local SQLite DB saves time during outages and confirms factory defaults were changed.",
                    "Documentar usuario, URL de panel y contraseña real en tu base local te ahorra tiempo ante caídas de red y te ayuda a verificar que no quedaron claves de fábrica.",
                ),
                "recommendation": _pick(
                    lang,
                    "Select each router, confirm you replaced any factory-default password, and store your local access details via «Edit Device».",
                    "Selecciona cada router, verifica que cambiaste la clave por defecto de fábrica y guarda tu acceso en «Editar Equipo».",
                ),
                "affected_ips": [r["ipv4"] for r in routers_no_creds],
            }
        )

    # Suggested DHCP IP Reservation Plan
    primary_prefix = "192.168.1"
    if active_subnets:
        try:
            net = ipaddress.ip_network(active_subnets[0]["cidr"], strict=False)
            parts = str(net.network_address).split(".")
            primary_prefix = ".".join(parts[:3])
        except Exception:
            pass

    ip_plan = [
        {
            "range": f"{primary_prefix}.1",
            "role": _pick(lang, "Primary Router / Gateway", "Router / Gateway Principal"),
            "example": _pick(lang, "Main ONT or primary router running DHCP", "ONT o Router principal con servidor DHCP"),
        },
        {
            "range": f"{primary_prefix}.2 – .9",
            "role": _pick(lang, "Access Points & Switches", "Access Points y Switches"),
            "example": _pick(lang, "Secondary routers in AP / Bridge mode and managed switches", "Routers secundarios en modo AP / Bridge y switches gestionados"),
        },
        {
            "range": f"{primary_prefix}.10 – .19",
            "role": _pick(lang, "Servers & NAS", "Servidores y NAS"),
            "example": _pick(lang, "QNAP / Synology / Docker / AdGuard Home (static IP)", "QNAP / Synology / Docker / AdGuard Home (IP fija)"),
        },
        {
            "range": f"{primary_prefix}.20 – .29",
            "role": _pick(lang, "IP Cameras & DVR/NVR", "Cámaras IP y DVR/NVR"),
            "example": _pick(lang, "Hikvision, Ezviz, Wyze (ideally on IoT/Camera VLAN)", "Hikvision, Ezviz, Wyze (idealmente en VLAN IoT/Cámaras)"),
        },
        {
            "range": f"{primary_prefix}.30 – .49",
            "role": _pick(lang, "Smart TVs, Printers & Consoles", "Smart TVs, Impresoras y Consolas"),
            "example": _pick(lang, "Samsung/LG TVs, Epson, Fire TV, Nintendo", "TVs Samsung/LG, Epson, Fire TV, Nintendo"),
        },
        {
            "range": f"{primary_prefix}.50 – .99",
            "role": _pick(lang, "Smart Home & IoT", "Domótica e IoT"),
            "example": _pick(lang, "Espressif ESP32/ESP8266, Tuya, smart plugs & sensors", "Espressif ESP32/ESP8266, Tuya, enchufes y sensores"),
        },
        {
            "range": f"{primary_prefix}.100 – .250",
            "role": _pick(lang, "Dynamic DHCP Pool", "Pool DHCP Dinámico"),
            "example": _pick(lang, "Laptops, smartphones, tablets & guest devices", "Laptops, celulares, tablets e invitados"),
        },
    ]

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
