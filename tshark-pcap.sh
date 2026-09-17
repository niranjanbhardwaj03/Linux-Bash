#!/bin/bash

# ============================================================
# HTTP / HTTPS UNIQUE REQUEST EXTRACTOR
#
# Input:
#   PCAP file from 100 MB to several GB
#
# Output:
#   Unique HTTP URLs
#   HTTPS hostnames / SNI
#
# Requirements:
#   tshark
#   sort
#   awk
#
# Install:
#   sudo apt install tshark
#
# Usage:
#   chmod +x extract_urls.sh
#   ./extract_urls.sh
# ============================================================

set -u

# ------------------------------------------------------------
# Check tshark
# ------------------------------------------------------------

if ! command -v tshark >/dev/null 2>&1
then
    echo "ERROR: tshark is not installed."
    echo
    echo "Install it with:"
    echo
    echo "    sudo apt install tshark"
    echo
    exit 1
fi


# ------------------------------------------------------------
# Ask for PCAP
# ------------------------------------------------------------

echo
echo "============================================================"
echo "       HTTP / HTTPS UNIQUE REQUEST EXTRACTOR"
echo "============================================================"
echo

read -r -p "Enter path to PCAP file: " PCAP

PCAP="${PCAP/#\~/$HOME}"

echo


# ------------------------------------------------------------
# Validate PCAP
# ------------------------------------------------------------

if [ ! -f "$PCAP" ]
then
    echo "ERROR: PCAP file does not exist:"
    echo "    $PCAP"
    exit 1
fi


# ------------------------------------------------------------
# File information
# ------------------------------------------------------------

FILE_SIZE=$(stat -c%s "$PCAP")

echo "------------------------------------------------------------"
echo "PCAP INFORMATION"
echo "------------------------------------------------------------"
echo
echo "File:"
echo "    $PCAP"
echo
echo "Size:"
echo "    $(numfmt --to=iec "$FILE_SIZE")"
echo


# ------------------------------------------------------------
# Output directory
# ------------------------------------------------------------

BASE_NAME=$(basename "$PCAP")
BASE_NAME="${BASE_NAME%.pcap}"

OUTPUT_DIR="/tmp/${BASE_NAME}_url_results"

mkdir -p "$OUTPUT_DIR"


HTTP_RAW="$OUTPUT_DIR/http_raw.txt"
HTTP_UNIQUE="$OUTPUT_DIR/http_unique_urls.txt"

HTTPS_RAW="$OUTPUT_DIR/https_raw.txt"
HTTPS_UNIQUE="$OUTPUT_DIR/https_unique_hosts.txt"

ALL_UNIQUE="$OUTPUT_DIR/all_unique_requests.txt"


# ============================================================
# HTTP
# ============================================================

echo
echo "------------------------------------------------------------"
echo "EXTRACTING HTTP REQUESTS"
echo "------------------------------------------------------------"
echo

echo "Reading PCAP..."
echo


tshark \
    -r "$PCAP" \
    -Y 'http.request' \
    -T fields \
    -e http.request.full_uri \
    -e http.host \
    -e http.request.uri \
    2>/dev/null |
awk -F '\t' '
{
    full_uri=$1
    host=$2
    uri=$3

    if (full_uri != "")
    {
        print full_uri
    }
    else if (host != "" && uri != "")
    {
        print "http://" host uri
    }
}
' > "$HTTP_RAW"


# ------------------------------------------------------------
# Remove duplicates
# ------------------------------------------------------------

if [ -s "$HTTP_RAW" ]
then

    sort -u "$HTTP_RAW" > "$HTTP_UNIQUE"

else

    touch "$HTTP_UNIQUE"

fi


HTTP_COUNT=$(wc -l < "$HTTP_UNIQUE")


echo
echo "Unique HTTP URLs:"
echo "    $HTTP_COUNT"
echo


# ============================================================
# HTTPS
# ============================================================

echo
echo "------------------------------------------------------------"
echo "EXTRACTING HTTPS HOSTNAMES"
echo "------------------------------------------------------------"
echo

echo "NOTE:"
echo "HTTPS URL paths are encrypted unless TLS is decrypted."
echo "We therefore extract TLS SNI / hostname information."
echo


tshark \
    -r "$PCAP" \
    -Y 'tls.handshake.extensions_server_name' \
    -T fields \
    -e tls.handshake.extensions_server_name \
    2>/dev/null |
grep -v '^$' |
sort -u > "$HTTPS_UNIQUE"


HTTPS_COUNT=$(wc -l < "$HTTPS_UNIQUE")


echo
echo "Unique HTTPS hosts:"
echo "    $HTTPS_COUNT"
echo


# ============================================================
# Create combined result
# ============================================================

echo
echo "------------------------------------------------------------"
echo "CREATING COMBINED RESULT"
echo "------------------------------------------------------------"
echo


{
    echo "================ HTTP URLS ================"

    cat "$HTTP_UNIQUE"

    echo
    echo "============= HTTPS HOSTNAMES ============="

    cat "$HTTPS_UNIQUE"

} > "$ALL_UNIQUE"


# ============================================================
# Display result
# ============================================================

echo
echo "============================================================"
echo "                    PROCESS COMPLETED"
echo "============================================================"
echo

echo "PCAP:"
echo "    $PCAP"
echo

echo "HTTP unique URLs:"
echo "    $HTTP_COUNT"
echo

echo "HTTPS unique hosts:"
echo "    $HTTPS_COUNT"
echo

echo "Results:"
echo "    $OUTPUT_DIR"
echo

echo "HTTP URLs:"
echo "    $HTTP_UNIQUE"
echo

echo "HTTPS hosts:"
echo "    $HTTPS_UNIQUE"
echo

echo "Combined:"
echo "    $ALL_UNIQUE"
echo

echo "============================================================"
