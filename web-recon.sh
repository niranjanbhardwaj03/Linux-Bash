#!/bin/bash

TARGET="$1"

if [ -z "$TARGET" ]; then
    echo "Usage: $0 example.test"
    exit 1
fi

DATE=$(date +"%Y%m%d_%H%M%S")
OUT="recon_${TARGET}_${DATE}"

mkdir -p "$OUT"

echo "[+] Target: $TARGET"
echo "[+] Output: $OUT"

# 1. Subdomain discovery
echo "[+] Discovering subdomains..."
subfinder -d "$TARGET" -silent > "$OUT/subdomains.txt"

# 2. DNS resolution
echo "[+] Resolving DNS..."
dnsx -l "$OUT/subdomains.txt" -silent \
    > "$OUT/resolved.txt"

# 3. Identify live HTTP/HTTPS services
echo "[+] Finding HTTP services..."
httpx -l "$OUT/resolved.txt" -silent \
    -status-code \
    -title \
    -tech-detect \
    > "$OUT/httpx.txt"

# 4. Extract live URLs
awk '{print $1}' "$OUT/httpx.txt" > "$OUT/live_urls.txt"

# 5. Basic Nmap scan
echo "[+] Running Nmap..."
nmap -sV --top-ports 100 \
    -iL "$OUT/resolved.txt" \
    -oA "$OUT/nmap"

# 6. Technology detection
echo "[+] Running WhatWeb..."
while read -r url; do
    whatweb "$url"
done < "$OUT/live_urls.txt" \
    > "$OUT/whatweb.txt"

# 7. Nuclei scan
echo "[+] Running Nuclei..."
nuclei -l "$OUT/live_urls.txt" \
    -severity low,medium,high,critical \
    -o "$OUT/nuclei.txt"

echo
echo "======================================"
echo " Recon completed"
echo " Results: $OUT"
echo "======================================"