#!/bin/bash
# =========================================================
# PCAP Common Values + Number of PCAPs Containing Each Value
# =========================================================
# Directory containing PCAP files
read -p "Enter PCAP Files Path: " PCAP_DIR
# Output directory
OUT_DIR="./common_results"
mkdir -p "$OUT_DIR"

# ---------------------------------------------------------
# Find all PCAP/PCAPNG files
# ---------------------------------------------------------
mapfile -t PCAPS < <(
    find "$PCAP_DIR" -type f \
        \( -iname "*.pcap" -o -iname "*.pcapng" \) |
    sort
)

TOTAL=${#PCAPS[@]}
if [ "$TOTAL" -eq 0 ]; then
    echo "No PCAP files found in $PCAP_DIR"
    exit 1
fi
echo "Found $TOTAL PCAP files."

# ---------------------------------------------------------
# Function:
# The value appeared in that many different PCAP files.
# ---------------------------------------------------------
find_common()
{
    local NAME="$1"
    local TSHARK_FIELD="$2"
    echo ""
    echo "================================================="
    echo "Processing $NAME ..."
    echo "================================================="
    TEMP_DIR=$(mktemp -d)
    # -----------------------------------------------------
    # Extract UNIQUE values from each PCAP
    # -----------------------------------------------------
    PCAP_INDEX=0
    for PCAP in "${PCAPS[@]}"; do
        BASENAME=$(basename "$PCAP")
        OUTPUT="$TEMP_DIR/pcap_${PCAP_INDEX}.txt"
        echo "  Reading: $BASENAME"
        tshark -r "$PCAP" \
            -T fields \
            -e "$TSHARK_FIELD" \
            2>/dev/null |
            sed '/^$/d' |
            sort -u > "$OUTPUT"
        ((PCAP_INDEX++))
    done

    # -----------------------------------------------------
    # Combine all values from all PCAPs
    # -----------------------------------------------------

    cat "$TEMP_DIR"/pcap_*.txt |
        sort -u > "$TEMP_DIR/all_values.txt"

    # -----------------------------------------------------
    # Count how many DIFFERENT PCAP files contain each value
    # Important:
    # Because each PCAP was already "sort -u",
    # a value is counted only ONCE per PCAP.
    # -----------------------------------------------------
    > "$TEMP_DIR/counts.txt"
    while IFS= read -r VALUE; do
        COUNT=0
        for FILE in "$TEMP_DIR"/pcap_*.txt; do
            if grep -Fxq "$VALUE" "$FILE"; then
                ((COUNT++))
            fi
        done
        
      # Only keep values appearing in 2 or more PCAPs
        if [ "$COUNT" -ge 2 ]; then
            printf "%s\t%s\n" "$VALUE" "$COUNT" >> "$TEMP_DIR/counts.txt"
        fi
    done < "$TEMP_DIR/all_values.txt"

    # ------------------------------------------------
    # 1. Highest PCAP count first
    # 2. Value alphabetically
    # -----------------------------------------------------
    sort -t $'\t' -k2,2nr -k1,1 \
        "$TEMP_DIR/counts.txt" \
        > "$OUT_DIR/${NAME}_common.txt"

    # -----------------------------------------------------
    # Count number of repeated/common values
    # -----------------------------------------------------

    COMMON_COUNT=$(wc -l < "$OUT_DIR/${NAME}_common.txt")
    echo ""
    echo "  Repeated $NAME values: $COMMON_COUNT"
    echo "  Result: $OUT_DIR/${NAME}_common.txt"

    # -----------------------------------------------------
    # Display result
    # -----------------------------------------------------
    if [ "$COMMON_COUNT" -gt 0 ]; then
        echo ""
        echo "  Value                                  PCAP Count"
        echo "  -------------------------------------- ----------"
        awk -F '\t' '{printf "  %-38s %d\n", $1, $2}' \
            "$OUT_DIR/${NAME}_common.txt"
    else
        echo "  No values found in multiple PCAP files."
    fi
    rm -rf "$TEMP_DIR"
}

# =========================================================
# IP addresses
# =========================================================

find_common "ip_src" "ip.src"
find_common "ip_dst" "ip.dst"

# =========================================================
# TCP ports
# =========================================================

find_common "tcp_srcport" "tcp.srcport"
find_common "tcp_dstport" "tcp.dstport"

# =========================================================
# UDP ports
# =========================================================

find_common "udp_srcport" "udp.srcport"
find_common "udp_dstport" "udp.dstport"

# =========================================================
# DNS queries
# =========================================================

find_common "dns_queries" "dns.qry.name"

# =========================================================
# TLS SNI / Server Names
# =========================================================

find_common "tls_sni" "tls.handshake.extensions_server_name"

# =========================================================
# Finished
# =========================================================
echo ""
echo "================================================="
echo "Finished."
echo "Results are in: $OUT_DIR"
echo "================================================="
