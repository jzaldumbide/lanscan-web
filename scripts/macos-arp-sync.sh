#!/usr/bin/env bash
# Sincroniza la tabla ARP nativa de macOS con LanScan Web en Docker local
# (en macOS Docker Desktop corre en una VM NAT y no ve direcciones MAC capa 2 directamente).
# Uso:
#   ./scripts/macos-arp-sync.sh            # una sola vez
#   ./scripts/macos-arp-sync.sh --watch    # cada 30 segundos en segundo plano

API_URL="${LANSCAN_URL:-http://localhost:8787/api/arp-sync}"

sync_once() {
  python3 - "$API_URL" <<'PY'
import json, re, subprocess, sys, urllib.request

api_url = sys.argv[1]
out = subprocess.check_output(["arp", "-an"]).decode("utf-8", errors="ignore")
entries = []
for line in out.splitlines():
    m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]+)\s+on\s+(\S+)", line)
    if not m:
        continue
    ip, mac, iface = m.group(1), m.group(2), m.group(3)
    if ip.endswith(".255") or ip.startswith(("224.", "239.", "169.254.", "127.")):
        continue
    if mac in ("ff:ff:ff:ff:ff:ff", "(incomplete)"):
        continue
    parts = mac.split(":")
    if len(parts) == 6:
        mac = ":".join(p.zfill(2).lower() for p in parts)
    entries.append({"ipv4": ip, "mac": mac})

req = urllib.request.Request(
    api_url,
    data=json.dumps({"entries": entries}).encode("utf-8"),
    headers={"Content-Type": "application/json"},
    method="POST",
)
with urllib.request.urlopen(req, timeout=5) as resp:
    res = json.loads(resp.read().decode("utf-8"))
    print(f"ARP sync OK: {res.get('synced', 0)} equipos actualizados con MAC/Vendor")
PY
}

if [[ "${1:-}" == "--watch" ]]; then
  echo "Sincronizando tabla ARP de macOS cada 30s hacia $API_URL (Ctrl+C para detener)..."
  while true; do
    sync_once || true
    sleep 30
  done
else
  sync_once
fi
