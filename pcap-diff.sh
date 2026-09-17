#!/bin/bash

# Directory containing your PCAP files
read -p "enter the file path: " PCAP_DIR

# Output directory
OUT_DIR="./common_results"

mkdir -p "$OUT_DIR"

# Find all PCAP/PCAPNG files
mapfile -t PCAPS < <(find "$PCAP_DIR" -type f \( -iname "*.pcap" -o -iname "*.pcapng" \) | sort)

TOTAL=${#PCAPS[@]}

if [ "$TOTAL" -eq 0 ]; then
    echo "No PCAP files found in $PCAP_DIR"
    exit 1
fi

echo "Found $TOTAL PCAP files."

# ---------------------------------------------------------
# Function: find values common to ALL PCAP files
# ---------------------------------------------------------
find_common()
{
    local NAME="$1"
    local TSHARK_FIELD="$2"

    echo ""
    echo "Processing $NAME ..."

    TEMP_DIR=$(mktemp -d)

    # Extract unique values from each PCAP separately
    for PCAP in "${PCAPS[@]}"; do

        BASENAME=$(basename "$PCAP")
        OUTPUT="$TEMP_DIR/$BASENAME.txt"

        echo "  Reading: $BASENAME"

        tshark -r "$PCAP" \
            -T fields \
            -e "$TSHARK_FIELD" \
            2>/dev/null |
            sed '/^$/d' |
            sort -u > "$OUTPUT"

    done

    # Start with values from first PCAP
    cp "$TEMP_DIR/$(basename "${PCAPS[0]}").txt" \
       "$TEMP_DIR/common.txt"

    # Intersect with every other PCAP
    for ((i=1; i<TOTAL; i++)); do

        BASENAME=$(basename "${PCAPS[$i]}")

        comm -12 \
            "$TEMP_DIR/common.txt" \
            "$TEMP_DIR/$BASENAME.txt" \
            > "$TEMP_DIR/new_common.txt"

        mv "$TEMP_DIR/new_common.txt" "$TEMP_DIR/common.txt"

    done

    # Save result
    cp "$TEMP_DIR/common.txt" "$OUT_DIR/${NAME}_common.txt"

    COUNT=$(wc -l < "$TEMP_DIR/common.txt")

    echo "  Common $NAME: $COUNT"
    echo "  Result: $OUT_DIR/${NAME}_common.txt"

    rm -rf "$TEMP_DIR"
}


# ---------------------------------------------------------
# Extract common source/destination IP addresses
# ---------------------------------------------------------

find_common "ip" "ip.src"
find_common "ip_dst" "ip.dst"


# ---------------------------------------------------------
# Common TCP source/destination ports
# ---------------------------------------------------------

find_common "tcp_srcport" "tcp.srcport"
find_common "tcp_dstport" "tcp.dstport"


# ---------------------------------------------------------
# Common UDP source/destination ports
# ---------------------------------------------------------

find_common "udp_srcport" "udp.srcport"
find_common "udp_dstport" "udp.dstport"


# ---------------------------------------------------------
# Common DNS queries
# ---------------------------------------------------------

find_common "dns_queries" "dns.qry.name"


# ---------------------------------------------------------
# Common TLS SNI / server names
# ---------------------------------------------------------

find_common "tls_sni" "tls.handshake.extensions_server_name"


echo ""
echo "======================================"
echo "Finished."
echo "Results are in: $OUT_DIR"
echo "======================================"
