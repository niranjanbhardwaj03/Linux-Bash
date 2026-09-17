#!/bin/bash

# ============================================================
# PCAP PROCESSOR
#
# Purpose:
#   1. Ask user for a .pcap file
#   2. Check its size
#   3. If > 100 MB, ask whether to split it
#   4. Split into files <= 100 MB
#   5. Store split files under /home/
#   6. Verify every part
#   7. Merge parts back together
#   8. Save final PCAP under /tmp/
#
# Requirements:
#   editcap
#   mergecap
#
# Install on Ubuntu/Debian:
#   sudo apt update
#   sudo apt install wireshark-common
# ============================================================

set -u

MAX_SIZE_MB=100
MAX_SIZE_BYTES=$((100 * 1024 * 1024))

HOME_BASE="/home"
TMP_BASE="/tmp"


# ============================================================
# FUNCTIONS
# ============================================================

format_size()
{
    local SIZE="$1"

    if [ "$SIZE" -ge 1073741824 ]; then
        awk -v s="$SIZE" 'BEGIN {
            printf "%.2f GB", s/1073741824
        }'

    elif [ "$SIZE" -ge 1048576 ]; then
        awk -v s="$SIZE" 'BEGIN {
            printf "%.2f MB", s/1048576
        }'

    elif [ "$SIZE" -ge 1024 ]; then
        awk -v s="$SIZE" 'BEGIN {
            printf "%.2f KB", s/1024
        }'

    else
        echo "${SIZE} B"
    fi
}


ask_yes_no()
{
    local QUESTION="$1"

    while true
    do
        read -r -p "$QUESTION [y/n]: " ANSWER

        case "$ANSWER" in
            y|Y|yes|Yes|YES)
                return 0
                ;;

            n|N|no|No|NO)
                return 1
                ;;

            *)
                echo "Please enter y or n."
                ;;
        esac
    done
}


check_dependencies()
{
    echo
    echo "Checking dependencies..."
    echo

    if ! command -v editcap >/dev/null 2>&1
    then
        echo "ERROR: editcap is not installed."
        echo
        echo "Install with:"
        echo "    sudo apt install wireshark-common"
        exit 1
    fi

    if ! command -v mergecap >/dev/null 2>&1
    then
        echo "ERROR: mergecap is not installed."
        echo
        echo "Install with:"
        echo "    sudo apt install wireshark-common"
        exit 1
    fi

    echo "editcap : $(command -v editcap)"
    echo "mergecap: $(command -v mergecap)"
    echo
}


# ============================================================
# MAIN
# ============================================================

echo
echo "============================================================"
echo "                 PCAP 100 MB PROCESSOR"
echo "============================================================"
echo


# ============================================================
# Check dependencies
# ============================================================

check_dependencies


# ============================================================
# Ask for input PCAP
# ============================================================

read -r -p "Enter full path to .pcap file: " INPUT_FILE

# Remove surrounding spaces
INPUT_FILE="$(echo "$INPUT_FILE" | sed 's/^ *//;s/ *$//')"

# Expand ~
INPUT_FILE="${INPUT_FILE/#\~/$HOME}"

echo


# ============================================================
# Validate input
# ============================================================

if [ ! -f "$INPUT_FILE" ]
then
    echo "ERROR: PCAP file does not exist:"
    echo
    echo "    $INPUT_FILE"
    echo
    exit 1
fi


if [ ! -r "$INPUT_FILE" ]
then
    echo "ERROR: Cannot read PCAP file:"
    echo
    echo "    $INPUT_FILE"
    echo
    exit 1
fi


if [[ "${INPUT_FILE,,}" != *.pcap ]]
then
    echo "ERROR: File must have .pcap extension."
    echo
    exit 1
fi


# ============================================================
# Get file information
# ============================================================

ORIGINAL_SIZE=$(stat -c%s "$INPUT_FILE")

FILE_NAME=$(basename "$INPUT_FILE")
FILE_NAME_NO_EXT="${FILE_NAME%.pcap}"

echo "------------------------------------------------------------"
echo "FILE INFORMATION"
echo "------------------------------------------------------------"
echo
echo "Input file:"
echo "    $INPUT_FILE"
echo
echo "File size:"
echo "    $(format_size "$ORIGINAL_SIZE")"
echo


# ============================================================
# If PCAP is already <= 100 MB
# ============================================================

if [ "$ORIGINAL_SIZE" -le "$MAX_SIZE_BYTES" ]
then

    echo "PCAP file is already <= 100 MB."
    echo "No splitting is required."
    echo

    FINAL_OUTPUT="$TMP_BASE/$FILE_NAME"

    if [ -e "$FINAL_OUTPUT" ]
    then
        echo "File already exists:"
        echo "    $FINAL_OUTPUT"
        echo

        if ! ask_yes_no "Overwrite it?"
        then
            echo
            echo "Operation cancelled."
            exit 0
        fi
    fi

    cp -f "$INPUT_FILE" "$FINAL_OUTPUT"

    if [ "$?" -ne 0 ]
    then
        echo
        echo "ERROR: Could not copy PCAP to /tmp."
        exit 1
    fi

    echo
    echo "============================================================"
    echo "PROCESS COMPLETED"
    echo "============================================================"
    echo
    echo "Final PCAP:"
    echo "    $FINAL_OUTPUT"
    echo

    exit 0
fi


# ============================================================
# PCAP > 100 MB
# ============================================================

echo "============================================================"
echo "                         ALERT"
echo "============================================================"
echo
echo "PCAP file is bigger than 100 MB!"
echo
echo "Current size:"
echo "    $(format_size "$ORIGINAL_SIZE")"
echo


# ============================================================
# Ask user
# ============================================================

if ! ask_yes_no "Do you want to break this PCAP into subfiles?"
then
    echo
    echo "Operation cancelled."
    exit 0
fi


# ============================================================
# Create split directory
# ============================================================

SPLIT_DIR="$HOME_BASE/${FILE_NAME_NO_EXT}_parts"

echo
echo "Creating split directory:"
echo
echo "    $SPLIT_DIR"
echo

mkdir -p "$SPLIT_DIR"

if [ ! -d "$SPLIT_DIR" ]
then
    echo "ERROR: Could not create:"
    echo "    $SPLIT_DIR"
    echo
    exit 1
fi


# ============================================================
# Remove old split files
# ============================================================

find "$SPLIT_DIR" \
    -maxdepth 1 \
    -type f \
    -name "*.pcap" \
    -delete


# ============================================================
# Split PCAP
# ============================================================

echo "------------------------------------------------------------"
echo "SPLITTING PCAP"
echo "------------------------------------------------------------"
echo
echo "Maximum part size: 100 MB"
echo
echo "Please wait..."
echo


# IMPORTANT:
#
# editcap -C SIZE
#
# splits the capture based on file size.
#
# We use slightly below 100 MB to account for PCAP headers
# and ensure the generated parts remain below 100 MB.
#

SPLIT_SIZE=$((99 * 1024 * 1024))

TEMP_PREFIX="$SPLIT_DIR/part"

editcap \
    -C "$SPLIT_SIZE" \
    "$INPUT_FILE" \
    "$TEMP_PREFIX"


EDITCAP_STATUS=$?


if [ "$EDITCAP_STATUS" -ne 0 ]
then
    echo
    echo "ERROR: editcap failed."
    echo
    echo "Exit code: $EDITCAP_STATUS"
    echo
    exit 1
fi


# ============================================================
# Rename editcap output
# ============================================================

echo
echo "------------------------------------------------------------"
echo "PROCESSING SPLIT FILES"
echo "------------------------------------------------------------"
echo


COUNT=0

for FILE in "$SPLIT_DIR"/part*
do
    [ -f "$FILE" ] || continue

    COUNT=$((COUNT + 1))

    NEW_FILE="$SPLIT_DIR/part_$(printf "%03d" "$COUNT").pcap"

    mv "$FILE" "$NEW_FILE"
done


# ============================================================
# Check whether parts were actually created
# ============================================================

if [ "$COUNT" -eq 0 ]
then
    echo
    echo "ERROR: No PCAP parts were created."
    echo
    echo "The split directory is:"
    echo "    $SPLIT_DIR"
    echo
    exit 1
fi


# ============================================================
# Verify every part
# ============================================================

echo
echo "------------------------------------------------------------"
echo "VERIFYING PCAP PARTS"
echo "------------------------------------------------------------"
echo

OVERSIZED=0
PART_COUNT=0

for FILE in "$SPLIT_DIR"/*.pcap
do
    [ -f "$FILE" ] || continue

    PART_COUNT=$((PART_COUNT + 1))

    SIZE=$(stat -c%s "$FILE")

    echo "$(basename "$FILE")"
    echo "    Size: $(format_size "$SIZE")"

    if [ "$SIZE" -gt "$MAX_SIZE_BYTES" ]
    then

        echo "    STATUS: ERROR - larger than 100 MB"

        OVERSIZED=1

    else

        echo "    STATUS: OK"

    fi

    echo
done


# ============================================================
# Verify split result
# ============================================================

if [ "$PART_COUNT" -eq 0 ]
then
    echo "ERROR: Total parts = 0"
    exit 1
fi


if [ "$OVERSIZED" -eq 1 ]
then
    echo
    echo "ERROR: One or more parts are larger than 100 MB."
    echo
    exit 1
fi


echo "------------------------------------------------------------"
echo "SPLIT SUCCESSFUL"
echo "------------------------------------------------------------"
echo
echo "Total parts: $PART_COUNT"
echo
echo "Parts stored in:"
echo "    $SPLIT_DIR"
echo


# ============================================================
# Prepare final output
# ============================================================

FINAL_OUTPUT="$TMP_BASE/$FILE_NAME"


if [ -e "$FINAL_OUTPUT" ]
then

    echo "Final output already exists:"
    echo
    echo "    $FINAL_OUTPUT"
    echo

    if ! ask_yes_no "Overwrite existing final PCAP?"
    then
        echo
        echo "Operation cancelled."
        exit 0
    fi

    rm -f "$FINAL_OUTPUT"
fi


# ============================================================
# Merge PCAP files
# ============================================================

echo
echo "------------------------------------------------------------"
echo "MERGING PCAP PARTS"
echo "------------------------------------------------------------"
echo

echo "Input directory:"
echo "    $SPLIT_DIR"
echo

echo "Output:"
echo "    $FINAL_OUTPUT"
echo


# ------------------------------------------------------------
# Build sorted list
# ------------------------------------------------------------

mapfile -t PCAP_FILES < <(
    find "$SPLIT_DIR" \
        -maxdepth 1 \
        -type f \
        -name "*.pcap" \
        -printf "%f\n" |
    sort -V
)


if [ "${#PCAP_FILES[@]}" -eq 0 ]
then
    echo "ERROR: No PCAP files found."
    echo
    echo "Directory:"
    echo "    $SPLIT_DIR"
    echo
    exit 1
fi


echo "Files to merge:"
echo

MERGE_FILES=()

for FILE in "${PCAP_FILES[@]}"
do
    FULL_PATH="$SPLIT_DIR/$FILE"

    echo "    $FILE"

    MERGE_FILES+=("$FULL_PATH")
done


echo
echo "Starting merge..."
echo


# ============================================================
# Merge
# ============================================================

mergecap \
    -w "$FINAL_OUTPUT" \
    "${MERGE_FILES[@]}"


MERGE_STATUS=$?


if [ "$MERGE_STATUS" -ne 0 ]
then
    echo
    echo "ERROR: mergecap failed."
    echo
    echo "Exit code: $MERGE_STATUS"
    echo
    exit 1
fi


# ============================================================
# Verify final output
# ============================================================

if [ ! -f "$FINAL_OUTPUT" ]
then
    echo
    echo "ERROR: Final PCAP was not created."
    echo
    exit 1
fi


FINAL_SIZE=$(stat -c%s "$FINAL_OUTPUT")


# ============================================================
# FINAL RESULT
# ============================================================

echo
echo "============================================================"
echo "                    PROCESS COMPLETED"
echo "============================================================"
echo
echo "Original PCAP:"
echo "    $INPUT_FILE"
echo
echo "Original size:"
echo "    $(format_size "$ORIGINAL_SIZE")"
echo
echo "Number of parts:"
echo "    $PART_COUNT"
echo
echo "Sub-PCAP files:"
echo "    $SPLIT_DIR"
echo
echo "Final merged PCAP:"
echo "    $FINAL_OUTPUT"
echo
echo "Final size:"
echo "    $(format_size "$FINAL_SIZE")"
echo
echo "Original PCAP was NOT modified."
echo
echo "============================================================"
