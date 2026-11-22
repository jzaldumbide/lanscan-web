"""FastAPI web server for LanScan Web."""

from __future__ import annotations

import asyncio
import csv
import io
import json
import os
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import advisor, db, enrichment
from .scanner import deep_enrich_device, lookup_vendor, normalize_mac, scan_host_ports, scan_manager

app = FastAPI(title="LanScan Web", version="1.0.0")

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")


@app.on_event("startup")
def _startup() -> None:
    db.init_db()


class SubnetPayload(BaseModel):
    name: str
    cidr: str
    enabled: bool = True
    color: str = "#2563eb"


class ScanStartPayload(BaseModel):
    subnet_ids: list[int] | None = None


class DeviceMetaPayload(BaseModel):
    custom_hostname: str | None = None
    comments: str | None = None
    device_type: str | None = None
    vendor: str | None = None
    identification: str | None = None
    location: str | None = None
    admin_url: str | None = None
    admin_user: str | None = None
    admin_password: str | None = None


class PortScanPayload(BaseModel):
    mode: str = "quick"  # quick | common | full | custom
    custom_ports: str = ""


class ArpEntry(BaseModel):
    ipv4: str
    mac: str
    subnet_cidr: str = ""
    mdns_name: str = ""


class ArpSyncPayload(BaseModel):
    entries: list[ArpEntry]


class SettingsPayload(BaseModel):
    auto_quick_ports: bool | None = None


@app.get("/")
def index() -> FileResponse:
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


@app.get("/api/bootstrap")
def bootstrap() -> dict[str, Any]:
    return {
        "subnets": db.list_subnets(),
        "devices": db.list_devices(),
        "scan_state": dict(scan_manager.state),
        "settings": db.get_settings(),
    }


@app.get("/api/subnets")
def get_subnets() -> list[dict[str, Any]]:
    return db.list_subnets()


@app.post("/api/subnets")
def create_subnet(payload: SubnetPayload) -> dict[str, Any]:
    try:
        return db.upsert_subnet(
            name=payload.name,
            cidr=payload.cidr,
            enabled=payload.enabled,
            color=payload.color,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.put("/api/subnets/{subnet_id}")
def edit_subnet(subnet_id: int, payload: SubnetPayload) -> dict[str, Any]:
    try:
        return db.upsert_subnet(
            name=payload.name,
            cidr=payload.cidr,
            enabled=payload.enabled,
            color=payload.color,
            subnet_id=subnet_id,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.delete("/api/subnets/{subnet_id}")
def remove_subnet(subnet_id: int) -> dict[str, str]:
    db.delete_subnet(subnet_id)
    return {"status": "deleted"}


@app.get("/api/devices")
def get_devices() -> list[dict[str, Any]]:
    return db.list_devices()


@app.patch("/api/devices/{ipv4}")
def patch_device(ipv4: str, payload: DeviceMetaPayload) -> dict[str, Any]:
    updated = db.update_device_meta(
        ipv4=ipv4,
        custom_hostname=payload.custom_hostname,
        comments=payload.comments,
        device_type=payload.device_type,
        vendor=payload.vendor,
        identification=payload.identification,
        location=payload.location,
        admin_url=payload.admin_url,
        admin_user=payload.admin_user,
        admin_password=payload.admin_password,
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Equipo no encontrado")
    dtype, extra = enrichment.classify_and_enrich(updated, updated.get("extra"))
    updated = db.update_device_enrichment(ipv4, dtype, extra) or updated
    scan_manager.emit("device", updated)
    return updated


@app.get("/api/topology")
def get_topology() -> dict[str, Any]:
    return enrichment.build_topology(db.list_subnets(), db.list_devices())


@app.get("/api/recommendations")
def get_recommendations() -> dict[str, Any]:
    return advisor.analyze_network(db.list_subnets(), db.list_devices())


@app.post("/api/devices/{ipv4}/enrich")
async def enrich_single_device(ipv4: str) -> dict[str, Any]:
    dev = db.get_device(ipv4)
    if not dev:
        raise HTTPException(status_code=404, detail="Equipo no encontrado")
    updated = await asyncio.to_thread(deep_enrich_device, ipv4)
    if not updated:
        raise HTTPException(status_code=404, detail="Equipo no encontrado")
    scan_manager.emit("device", updated)
    return updated


@app.post("/api/enrich-all")
async def enrich_all_devices() -> dict[str, Any]:
    devices = db.list_devices()
    enriched_count = 0

    def _run_all() -> int:
        import concurrent.futures
        cnt = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            futs = [pool.submit(deep_enrich_device, d["ipv4"]) for d in devices]
            for fut in concurrent.futures.as_completed(futs):
                try:
                    u = fut.result()
                    if u:
                        scan_manager.emit("device", u)
                        cnt += 1
                except Exception:
                    pass
        return cnt

    enriched_count = await asyncio.to_thread(_run_all)
    return {"enriched": enriched_count}


@app.delete("/api/devices")
def clear_all_devices(subnet_cidr: str | None = Query(default=None)) -> dict[str, Any]:
    deleted = db.clear_devices(subnet_cidr=subnet_cidr)
    scan_manager.emit("cleared", {"subnet_cidr": subnet_cidr, "deleted": deleted})
    return {"deleted": deleted}


@app.post("/api/scan/start")
def start_scan(payload: ScanStartPayload) -> dict[str, Any]:
    started = scan_manager.start_scan(subnet_ids=payload.subnet_ids)
    if not started:
        if scan_manager.state["running"]:
            raise HTTPException(status_code=409, detail="Ya hay un escaneo en progreso")
        raise HTTPException(status_code=400, detail="No hay subredes activas seleccionadas")
    return {"started": True, "state": dict(scan_manager.state)}


@app.post("/api/scan/stop")
def stop_scan() -> dict[str, Any]:
    scan_manager.stop_scan()
    return {"stopping": True}


@app.post("/api/devices/{ipv4}/port-scan")
async def port_scan_device(ipv4: str, payload: PortScanPayload) -> dict[str, Any]:
    dev = db.get_device(ipv4)
    if not dev:
        raise HTTPException(status_code=404, detail="Equipo no encontrado")
    scan_manager.emit("port_scan_start", {"ipv4": ipv4, "mode": payload.mode})
    try:
        result = await asyncio.to_thread(
            scan_host_ports, ipv4, payload.mode, payload.custom_ports
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al escanear puertos: {e}")
    if result.get("device"):
        scan_manager.emit("device", result["device"])
    scan_manager.emit("port_scan_done", {"ipv4": ipv4, "count": len(result["ports"])})
    return result


@app.post("/api/arp-sync")
def arp_sync(payload: ArpSyncPayload) -> dict[str, Any]:
    """Ingest host-level ARP/mDNS entries (useful on macOS Docker Desktop to supply L2 MACs)."""
    updated_count = 0
    for item in payload.entries:
        mac = normalize_mac(item.mac)
        if not mac:
            continue
        vendor = lookup_vendor(mac)
        if not vendor:
            vendor = enrichment.lookup_vendor_online(mac)
        existing = db.get_device(item.ipv4)
        subnet_cidr = item.subnet_cidr
        if not subnet_cidr and existing:
            subnet_cidr = existing.get("subnet_cidr", "")
        if not subnet_cidr:
            # Guess /24
            parts = item.ipv4.split(".")
            if len(parts) == 4:
                subnet_cidr = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        saved = db.upsert_device(
            {
                "ipv4": item.ipv4,
                "mac": mac,
                "vendor": vendor,
                "mdns_name": item.mdns_name,
                "subnet_cidr": subnet_cidr,
                "is_online": existing["is_online"] if existing else True,
            }
        )
        dtype, extra = enrichment.classify_and_enrich(saved, saved.get("extra"))
        saved = db.update_device_enrichment(item.ipv4, dtype, extra, vendor=vendor or None) or saved
        scan_manager.emit("device", saved)
        updated_count += 1
    return {"synced": updated_count}


@app.put("/api/settings")
def save_settings(payload: SettingsPayload) -> dict[str, str]:
    updates: dict[str, str] = {}
    if payload.auto_quick_ports is not None:
        updates["auto_quick_ports"] = "true" if payload.auto_quick_ports else "false"
    return db.update_settings(updates)


@app.get("/api/export.csv")
def export_csv() -> StreamingResponse:
    devices = db.list_devices()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        [
            "IPv4",
            "MAC",
            "Hostname",
            "Online",
            "Ping_ms",
            "Vendor",
            "Identification",
            "DNS_Name",
            "mDNS_Name",
            "SMB_Name",
            "SMB_Domain",
            "Subnet",
            "Open_Ports",
            "Comments",
            "Last_Seen",
        ]
    )
    for d in devices:
        ports_str = "; ".join(
            f"{p['port']}/{p['protocol']}({p.get('service','')})" for p in d.get("ports", [])
        )
        writer.writerow(
            [
                d["ipv4"],
                d["mac"],
                d["custom_hostname"],
                "online" if d["is_online"] else "offline",
                d["ping_ms"] if d["ping_ms"] is not None else "",
                d["vendor"],
                d["identification"],
                d["dns_name"],
                d["mdns_name"],
                d["smb_name"],
                d["smb_domain"],
                d["subnet_cidr"],
                ports_str,
                d["comments"],
                d["last_seen"],
            ]
        )
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="lanscan-devices.csv"'},
    )


@app.get("/api/events")
async def sse_events() -> StreamingResponse:
    loop = asyncio.get_running_loop()
    queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=256)

    def on_event(msg: dict[str, Any]) -> None:
        try:
            loop.call_soon_threadsafe(queue.put_nowait, msg)
        except Exception:
            pass

    scan_manager.subscribe(on_event)

    async def gen():
        try:
            yield f"data: {json.dumps({'type': 'status', 'data': dict(scan_manager.state)})}\n\n"
            while True:
                try:
                    msg = await asyncio.wait_for(queue.get(), timeout=20.0)
                    yield f"data: {json.dumps(msg)}\n\n"
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            scan_manager.unsubscribe(on_event)

    return StreamingResponse(gen(), media_type="text/event-stream")


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
