#!/bin/bash

# ============================================================
# PCAP HTTP/HTTPS URL DEDUPLICATOR
#
# INPUT:
#   100 MB - 5 GB+ PCAP
#
# OUTPUT:
#   A new .pcap containing ONE representative packet
#   for each unique HTTP URL / HTTPS hostname.
#
# PROCESS:
#
#   PCAP
#     |
#     v
#   tshark
#     |
#     v
#   HTTP URL / HTTPS SNI extraction
#     |
#     v
#   URL normalization
#     |
#     v
#   sort
#     |
#     v
#   remove duplicates
#     |
#     v
#   collect packet/frame numbers
#     |
#     v
#   editcap
#     |
#     v
#   filtered .pcap
#     |
#     v
#   final size check
#
# REQUIREMENTS:
#   tshark
#   editcap
#
# Install:
#   sudo apt update
#   sudo apt install tshark wireshark-common
#
# ============================================================

set -u

# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------

OUTPUT_BASE="/tmp"


# ============================================================
# FUNCTIONS
# ============================================================

format_size()
{
    local SIZE="$1"

    numfmt --to=iec-i --suffix=B "$SIZE" 2>/dev/null || \
    echo "${SIZE} bytes"
}


ask_yes_no()
{
    local QUESTION="$1"

    while true
    do
        read -r -p "$QUESTION [y/n]: " ANSWER

        case "$ANSWER" in

            y|Y|yes|YES|Yes)
                return 0
                ;;

            n|N|no|NO|No)
                return 1
                ;;

            *)
                echo "Please enter y or n."

        esac
    done
}


check_dependencies()
{
    echo
    echo "Checking required programs..."
    echo

    if ! command -v tshark >/dev/null 2>&1
    then
        echo "ERROR: tshark is not installed."
        echo
        echo "Install:"
        echo "    sudo apt install tshark"
        echo
        exit 1
    fi


    if ! command -v editcap >/dev/null 2>&1
    then
        echo "ERROR: editcap is not installed."
        echo
        echo "Install:"
        echo "    sudo apt install wireshark-common"
        echo
        exit 1
    fi


    echo "tshark : $(command -v tshark)"
    echo "editcap: $(command -v editcap)"
    echo
}


# ============================================================
# MAIN
# ============================================================

echo
echo "============================================================"
echo "       HTTP / HTTPS PCAP URL DEDUPLICATOR"
echo "============================================================"
echo


# ------------------------------------------------------------
# Dependencies
# ------------------------------------------------------------

check_dependencies


# ------------------------------------------------------------
# Ask for PCAP
# ------------------------------------------------------------

read -r -p "Enter path to PCAP file: " INPUT_PCAP

INPUT_PCAP="$(echo "$INPUT_PCAP" | sed 's/^ *//;s/ *$//')"

INPUT_PCAP="${INPUT_PCAP/#\~/$HOME}"

echo


# ------------------------------------------------------------
# Validate
# ------------------------------------------------------------

if [ ! -f "$INPUT_PCAP" ]
then
    echo "ERROR: PCAP file does not exist:"
    echo
    echo "    $INPUT_PCAP"
    echo
    exit 1
fi


if [ ! -r "$INPUT_PCAP" ]
then
    echo "ERROR: Cannot read PCAP:"
    echo
    echo "    $INPUT_PCAP"
    echo
    exit 1
fi


# ------------------------------------------------------------
# Original file information
# ------------------------------------------------------------

ORIGINAL_SIZE=$(stat -c%s "$INPUT_PCAP")

INPUT_NAME=$(basename "$INPUT_PCAP")
INPUT_NAME="${INPUT_NAME%.pcap}"


echo "------------------------------------------------------------"
echo "INPUT PCAP"
echo "------------------------------------------------------------"
echo
echo "File:"
echo "    $INPUT_PCAP"
echo
echo "Original size:"
echo "    $(format_size "$ORIGINAL_SIZE")"
echo


# ------------------------------------------------------------
# Create temporary working directory
# ------------------------------------------------------------

WORK_DIR=$(mktemp -d "/tmp/pcap_url_filter_XXXXXX")


if [ ! -d "$WORK_DIR" ]
then
    echo "ERROR: Could not create temporary directory."
    exit 1
fi


# ------------------------------------------------------------
# Cleanup when script exits
# ------------------------------------------------------------

cleanup()
{
    rm -rf "$WORK_DIR"
}

trap cleanup EXIT


# ------------------------------------------------------------
# Temporary files
# ------------------------------------------------------------

REQUESTS_FILE="$WORK_DIR/requests.tsv"

SORTED_FILE="$WORK_DIR/sorted_requests.tsv"

UNIQUE_FILE="$WORK_DIR/unique_requests.tsv"

FRAME_FILE="$WORK_DIR/frame_numbers.txt"

FINAL_OUTPUT="$OUTPUT_BASE/${INPUT_NAME}_filtered.pcap"


# ============================================================
# EXTRACT HTTP + HTTPS
# ============================================================

echo
echo "------------------------------------------------------------"
echo "EXTRACTING HTTP / HTTPS REQUEST INFORMATION"
echo "------------------------------------------------------------"
echo

echo "Processing PCAP..."
echo "For large PCAP files this may take some time."
echo


# ------------------------------------------------------------
# HTTP
#
# Output:
#
# frame number
# HTTP URL
#
# ------------------------------------------------------------

tshark \
    -n \
    -r "$INPUT_PCAP" \
    -Y 'http.request' \
    -T fields \
    -E separator=$'\t' \
    -e frame.number \
    -e http.request.full_uri \
    -e http.host \
    -e http.request.uri \
    2>/dev/null |
awk -F '\t' '

{
    frame=$1
    full_uri=$2
    host=$3
    uri=$4

    if (full_uri != "")
    {
        url=full_uri
    }
    else if (host != "" && uri != "")
    {
        url="http://" host uri
    }
    else
    {
        next
    }

    # --------------------------------------------------------
    # Normalize URL
    # --------------------------------------------------------

    # Convert hostname/URL to lowercase.
    url=tolower(url)

    # Remove trailing spaces.
    gsub(/[[:space:]]+$/, "", url)

    # Remove leading spaces.
    gsub(/^[[:space:]]+/, "", url)

    # Remove trailing slash.
    if (url ~ /^https?:\/\/[^\/]+\/$/)
    {
        sub(/\/$/, "", url)
    }

    print frame "\t" url
}

' > "$REQUESTS_FILE"


# ============================================================
# EXTRACT HTTPS SNI
# ============================================================

echo "Extracting HTTPS hostnames/SNI..."
echo


tshark \
    -n \
    -r "$INPUT_PCAP" \
    -Y 'tls.handshake.extensions_server_name' \
    -T fields \
    -E separator=$'\t' \
    -e frame.number \
    -e tls.handshake.extensions_server_name \
    2>/dev/null |
awk -F '\t' '

{
    frame=$1
    host=$2

    if (host == "")
    {
        next
    }

    # --------------------------------------------------------
    # Normalize hostname
    # --------------------------------------------------------

    host=tolower(host)

    gsub(/[[:space:]]+$/, "", host)
    gsub(/^[[:space:]]+/, "", host)

    # Remove trailing dot.
    sub(/\.$/, "", host)

    # Represent HTTPS hostname as URL.
    url="https://" host

    print frame "\t" url
}

' >> "$REQUESTS_FILE"


# ============================================================
# CHECK EXTRACTION
# ============================================================

if [ ! -s "$REQUESTS_FILE" ]
then
    echo
    echo "ERROR: No HTTP requests or HTTPS SNI were found."
    echo
    echo "Possible reasons:"
    echo
    echo "  1. The PCAP contains no HTTP traffic."
    echo "  2. The PCAP contains no TLS SNI."
    echo "  3. Traffic is encrypted/obfuscated."
    echo "  4. The capture is incomplete."
    echo
    exit 1
fi


TOTAL_REQUESTS=$(wc -l < "$REQUESTS_FILE")


echo
echo "Total HTTP/HTTPS request records:"
echo "    $TOTAL_REQUESTS"
echo


# ============================================================
# SORT
# ============================================================

echo
echo "------------------------------------------------------------"
echo "SORTING REQUESTS"
echo "------------------------------------------------------------"
echo


sort -t $'\t' -k2,2 -k1,1n \
    "$REQUESTS_FILE" \
    > "$SORTED_FILE"


# ============================================================
# REMOVE DUPLICATES
# ============================================================

echo "Removing duplicate URLs..."
echo


awk -F '\t' '
BEGIN {
    previous=""
}

{
    frame=$1
    url=$2

    if (url != previous)
    {
        print frame "\t" url
        previous=url
    }
}

' "$SORTED_FILE" > "$UNIQUE_FILE"


# ============================================================
# Extract frame numbers
# ============================================================

cut -f1 "$UNIQUE_FILE" > "$FRAME_FILE"


UNIQUE_COUNT=$(wc -l < "$FRAME_FILE")


echo
echo "------------------------------------------------------------"
echo "DEDUPLICATION RESULT"
echo "------------------------------------------------------------"
echo
echo "Original request records:"
echo "    $TOTAL_REQUESTS"
echo
echo "Unique URLs/hosts:"
echo "    $UNIQUE_COUNT"
echo


if [ "$UNIQUE_COUNT" -eq 0 ]
then
    echo "ERROR: No unique requests found."
    exit 1
fi


# ============================================================
# Show sample
# ============================================================

echo
echo "First 20 unique URLs/hosts:"
echo

head -20 "$UNIQUE_FILE" |
while IFS=$'\t' read -r FRAME URL
do
    echo "  $URL"
done

echo


# ============================================================
# CREATE FILTERED PCAP
# ============================================================

echo
echo "------------------------------------------------------------"
echo "CREATING FILTERED PCAP"
echo "------------------------------------------------------------"
echo


# ------------------------------------------------------------
# IMPORTANT:
#
# We cannot safely put millions of frame numbers into one
# shell command because of the Linux ARG_MAX limit.
#
# Therefore we process the frame numbers in batches.
# ------------------------------------------------------------

BATCH_DIR="$WORK_DIR/batches"

mkdir -p "$BATCH_DIR"


# Number of packets processed per editcap operation.
BATCH_SIZE=5000


split \
    -l "$BATCH_SIZE" \
    -d \
    -a 5 \
    "$FRAME_FILE" \
    "$BATCH_DIR/batch_"


BATCH_COUNT=$(find "$BATCH_DIR" \
    -type f \
    -name "batch_*" |
    wc -l)


echo "Unique packets to extract:"
echo "    $UNIQUE_COUNT"
echo

echo "Processing in batches:"
echo "    $BATCH_COUNT"
echo


BATCH_OUTPUT_DIR="$WORK_DIR/batch_pcaps"

mkdir -p "$BATCH_OUTPUT_DIR"


BATCH_NUMBER=0


for BATCH_FILE in "$BATCH_DIR"/batch_*
do

    [ -f "$BATCH_FILE" ] || continue

    BATCH_NUMBER=$((BATCH_NUMBER + 1))

    BATCH_OUTPUT="$BATCH_OUTPUT_DIR/batch_${BATCH_NUMBER}.pcap"


    echo -ne "\rProcessing batch $BATCH_NUMBER / $BATCH_COUNT..."


    # --------------------------------------------------------
    # Read frame numbers.
    #
    # editcap -r keeps only selected packets.
    # --------------------------------------------------------

    mapfile -t FRAMES < "$BATCH_FILE"


    editcap \
        -r \
        "$INPUT_PCAP" \
        "$BATCH_OUTPUT" \
        "${FRAMES[@]}" \
        2>/dev/null


    if [ "$?" -ne 0 ]
    then
        echo
        echo
        echo "ERROR: editcap failed on batch:"
        echo "    $BATCH_FILE"
        echo
        exit 1
    fi

done


echo
echo


# ============================================================
# MERGE BATCH PCAPS
# ============================================================

echo
echo "------------------------------------------------------------"
echo "MERGING FILTERED PACKETS"
echo "------------------------------------------------------------"
echo


mapfile -t BATCH_FILES < <(
    find "$BATCH_OUTPUT_DIR" \
        -type f \
        -name "*.pcap" \
        -printf "%f\n" |
    sort -V
)


if [ "${#BATCH_FILES[@]}" -eq 0 ]
then
    echo "ERROR: No filtered PCAP batches were created."
    exit 1
fi


MERGE_INPUTS=()


for FILE in "${BATCH_FILES[@]}"
do
    MERGE_INPUTS+=("$BATCH_OUTPUT_DIR/$FILE")
done


echo "Merging ${#MERGE_INPUTS[@]} filtered PCAP files..."
echo


mergecap \
    -w "$FINAL_OUTPUT" \
    "${MERGE_INPUTS[@]}"


if [ "$?" -ne 0 ]
then
    echo
    echo "ERROR: mergecap failed."
    exit 1
fi


# ============================================================
# FINAL PCAP CHECK
# ============================================================

if [ ! -f "$FINAL_OUTPUT" ]
then
    echo
    echo "ERROR: Final PCAP was not created."
    exit 1
fi


FINAL_SIZE=$(stat -c%s "$FINAL_OUTPUT")


# ============================================================
# FINAL SIZE COMPARISON
# ============================================================

echo
echo "------------------------------------------------------------"
echo "FINAL PCAP SIZE CHECK"
echo "------------------------------------------------------------"
echo

echo "Original PCAP:"
echo "    $(format_size "$ORIGINAL_SIZE")"
echo

echo "Filtered PCAP:"
echo "    $(format_size "$FINAL_SIZE")"
echo


# ------------------------------------------------------------
# Calculate percentage reduction
# ------------------------------------------------------------

REDUCTION=$(awk \
    -v original="$ORIGINAL_SIZE" \
    -v final="$FINAL_SIZE" \
    'BEGIN {
        if (original > 0)
            printf "%.2f", ((original-final)/original)*100
        else
            print "0.00"
    }'
)


echo "Size reduction:"
echo "    ${REDUCTION}%"
echo


# ============================================================
# FINAL RESULT
# ============================================================

echo
echo "============================================================"
echo "                    PROCESS COMPLETED"
echo "============================================================"
echo

echo "Input PCAP:"
echo "    $INPUT_PCAP"
echo

echo "Original size:"
echo "    $(format_size "$ORIGINAL_SIZE")"
echo

echo "Total HTTP/HTTPS records:"
echo "    $TOTAL_REQUESTS"
echo

echo "Unique URLs/HTTPS hosts:"
echo "    $UNIQUE_COUNT"
echo

echo "Final PCAP:"
echo "    $FINAL_OUTPUT"
echo

echo "Final size:"
echo "    $(format_size "$FINAL_SIZE")"
echo

echo "Size reduction:"
echo "    ${REDUCTION}%"
echo

echo "The original PCAP was NOT modified."
echo

echo "============================================================"
