#!/usr/bin/env bash
#
# fetch-samples.sh - download pcap test captures for shuck.
#
# Pulls from Wireshark source repo's test/captures directory via the raw GitHub mirror

set -euo pipefail

BASE="https://raw.githubusercontent.com/wireshark/wireshark/master/test/captures"
DEST="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)/samples"

mkdir -p "$DEST"

plain_files=(
  "arp.pcap"      # ARP - "Who has X? Tell Y" summaries
  "dns_port.pcap" # DNS on port 53, name compression
  "dns-mdns.pcap" # mDNS via port 5353
  "dhcp.pcap"     # UDP 67/68 -> Application Data stub
  "http.pcap"     # TCP options walk, HTTP undissected payload
  "dhcp.pcapng"   # pcapng reader + IDB tracking
)

gz_files=(
  "dns+icmp.pcapng.gz" # pcapng path + ICMP (not yet dissected) path
)

fetch() {
  local name="$1"
  echo "  $name"
  curl -fsSL -o "$DEST/$name" "$BASE/$name"
}

echo "Fetching plain captures into $DEST"
for f in "${plain_files[@]}"; do
  fetch "$f"
done

echo "Fetching + decompressing gzip captures"
for gz in "${gz_files[@]}"; do
  fetch "$gz"
  gunzip -f "$DEST/$gz"
  echo "    -> ${gz%.gz}"
done

echo
echo "Done. Sanity check (first 4 bytes = capture magic):"
for f in "$DEST"/*.pcap "$DEST"/*.pcapng; do
  [ -e "$f" ] || continue
  printf "  %-22s " "$(basename "$f")"
  od -An -tx1 -N4 "$f" | tr -s ' '
done

cat <<'EOF'

Magic reference:
  d4 c3 b2 a1   pcap classic, us, little endian (PCAP_MAGIC_US_LE)
  0a 0d 0d 0a   pcapng (PCAPNG_MAGIC)

Example run command:
  cargo run -- sample/dns_port.pcap

EOF
