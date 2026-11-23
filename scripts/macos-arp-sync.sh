#!/usr/bin/env bash
# Syncs macOS native ARP table (MACs) + mDNS/Bonjour hostnames into local LanScan Web Docker container.
# (macOS Docker Desktop runs inside a NAT VM and cannot read physical Wi-Fi Layer-2 ARP or multicast mDNS directly.)
# Usage:
#   ./scripts/macos-arp-sync.sh            # one-time sync
#   ./scripts/macos-arp-sync.sh --watch    # continuous sync every 20 seconds

API_URL="${LANSCAN_URL:-http://localhost:8787/api/arp-sync}"

sync_once() {
  python3 - "$API_URL" <<'PY'
import json, re, socket, subprocess, sys, urllib.request

api_url = sys.argv[1]
out = subprocess.check_output(["arp", "-an"]).decode("utf-8", errors="ignore")

local_hn = ""
try:
    local_hn = subprocess.check_output(["scutil", "--get", "LocalHostName"], stderr=subprocess.DEVNULL).decode().strip()
    if local_hn and not local_hn.endswith(".local"):
        local_hn += ".local"
except Exception:
    pass

local_ips = set()
try:
    if_out = subprocess.check_output(["ifconfig"]).decode("utf-8", errors="ignore")
    for m in re.finditer(r"inet\s+(\d+\.\d+\.\d+\.\d+)", if_out):
        local_ips.add(m.group(1))
except Exception:
    pass

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

    mdns_name = ""
    if ip in local_ips and local_hn:
        mdns_name = local_hn
    else:
        try:
            old_t = socket.getdefaulttimeout()
            socket.setdefaulttimeout(0.4)
            try:
                hn = socket.gethostbyaddr(ip)[0]
                if hn and hn != ip:
                    mdns_name = hn
            finally:
                socket.setdefaulttimeout(old_t)
        except Exception:
            pass

    entries.append({"ipv4": ip, "mac": mac, "mdns_name": mdns_name})

req = urllib.request.Request(
    api_url,
    data=json.dumps({"entries": entries}).encode("utf-8"),
    headers={"Content-Type": "application/json"},
    method="POST",
)
with urllib.request.urlopen(req, timeout=15) as resp:
    res = json.loads(resp.read().decode("utf-8"))
    print(f"macOS ARP/mDNS sync OK: {res.get('synced', 0)} devices enriched with MAC/Vendor/mDNS")
PY
}

if [[ "${1:-}" == "--watch" ]]; then
  echo "Syncing macOS ARP + mDNS every 20s to $API_URL (Ctrl+C to stop)..."
  while true; do
    sync_once || true
    sleep 20
  done
else
  sync_once
fi
