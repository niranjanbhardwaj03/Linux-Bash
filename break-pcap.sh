#!/bin/bash

# ============================================================
# PCAP 100 MB PROCESSOR
#
# Requirements:
#   - bash
#   - editcap
#   - mergecap
#
# Ubuntu/Debian:
#   sudo apt install wireshark-common
#
# Usage:
#   chmod +x pcap_processor.sh
#   ./pcap_processor.sh
# ============================================================

set -u

# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------

MAX_SIZE_MB=100
MAX_SIZE_BYTES=$((MAX_SIZE_MB * 1024 * 1024))

HOME_DIR="/home"
TMP_DIR="/tmp"


# ------------------------------------------------------------
# Functions
# ------------------------------------------------------------

format_size()
{
    local SIZE=$1

    if [ "$SIZE" -lt 1024 ]; then
        echo "${SIZE} B"

    elif [ "$SIZE" -lt $((1024 * 1024)) ]; then
        awk "BEGIN {printf \"%.2f KB\", $SIZE/1024}"

    elif [ "$SIZE" -lt $((1024 * 1024 * 1024)) ]; then
        awk "BEGIN {printf \"%.2f MB\", $SIZE/(1024*1024)}"

    else
        awk "BEGIN {printf \"%.2f GB\", $SIZE/(1024*1024*1024)}"
    fi
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
                ;;
        esac
    done
}


check_requirements()
{
    echo
    echo "Checking required commands..."
    echo

    if ! command -v editcap >/dev/null 2>&1
    then
        echo "ERROR: editcap was not found."
        echo
        echo "Install it with:"
        echo
        echo "    sudo apt install wireshark-common"
        echo
        exit 1
    fi

    if ! command -v mergecap >/dev/null 2>&1
    then
        echo "ERROR: mergecap was not found."
        echo
        echo "Install it with:"
        echo
        echo "    sudo apt install wireshark-common"
        echo
        exit 1
    fi

    echo "editcap : $(command -v editcap)"
    echo "mergecap: $(command -v mergecap)"
    echo
}


# ------------------------------------------------------------
# Split PCAP
# ------------------------------------------------------------

split_pcap()
{
    local INPUT_FILE="$1"
    local OUTPUT_DIR="$2"

    local FILE_SIZE
    local NUMBER_OF_PARTS
    local TARGET_SIZE
    local PART_PREFIX

    FILE_SIZE=$(stat -c%s "$INPUT_FILE")

    # Number of parts required.
    NUMBER_OF_PARTS=$(
        awk -v size="$FILE_SIZE" -v max="$MAX_SIZE_BYTES" \
        'BEGIN {
            print int((size + max - 1) / max)
        }'
    )

    if [ "$NUMBER_OF_PARTS" -lt 2 ]
    then
        NUMBER_OF_PARTS=2
    fi

    # Approximate target size.
    TARGET_SIZE=$(
        awk -v size="$FILE_SIZE" -v parts="$NUMBER_OF_PARTS" \
        'BEGIN {
            print int((size + parts - 1) / parts)
        }'
    )

    PART_PREFIX="$OUTPUT_DIR/pcap_part"

    echo
    echo "------------------------------------------------"
    echo "PCAP SPLITTING"
    echo "------------------------------------------------"
    echo
    echo "Original size : $(format_size "$FILE_SIZE")"
    echo "Parts required: $NUMBER_OF_PARTS"
    echo "Target size   : $(format_size "$TARGET_SIZE")"
    echo

    mkdir -p "$OUTPUT_DIR"

    # --------------------------------------------------------
    # editcap -c splits by packet count, not exact size.
    #
    # Therefore we first determine approximately how many
    # packets should go into each part.
    # --------------------------------------------------------

    echo "Counting packets..."
    echo

    local PACKET_COUNT

    PACKET_COUNT=$(capinfos -c "$INPUT_FILE" 2>/dev/null | \
        awk -F: '/Number of packets/ {
            gsub(/^[ \t]+/, "", $2);
            print $2
        }')

    # If capinfos isn't available or packet count cannot be
    # determined, use editcap's size splitting option.
    if [ -z "$PACKET_COUNT" ]
    then
        echo "Could not determine packet count."
        echo "Using editcap size-based splitting."

        editcap \
            -C "$MAX_SIZE_BYTES" \
            "$INPUT_FILE" \
            "$PART_PREFIX"

    else

        echo "Packets      : $PACKET_COUNT"
        echo

        local PACKETS_PER_PART

        PACKETS_PER_PART=$(
            awk -v packets="$PACKET_COUNT" \
                -v parts="$NUMBER_OF_PARTS" \
                'BEGIN {
                    print int((packets + parts - 1) / parts)
                }'
        )

        if [ "$PACKETS_PER_PART" -lt 1 ]
        then
            PACKETS_PER_PART=1
        fi

        echo "Packets/part : $PACKETS_PER_PART"
        echo

        editcap \
            -c "$PACKETS_PER_PART" \
            "$INPUT_FILE" \
            "$PART_PREFIX"
    fi

    echo
    echo "Initial splitting completed."
    echo

    # --------------------------------------------------------
    # Rename generated files to .pcap
    # --------------------------------------------------------

    local FILE
    local COUNT=1

    for FILE in "$OUTPUT_DIR"/pcap_part*
    do
        [ -e "$FILE" ] || continue

        local NEW_NAME

        NEW_NAME="$OUTPUT_DIR/part_$(printf "%03d" "$COUNT").pcap"

        mv "$FILE" "$NEW_NAME"

        COUNT=$((COUNT + 1))
    done

    # --------------------------------------------------------
    # Verify parts
    # --------------------------------------------------------

    verify_and_resplit "$OUTPUT_DIR"
}


# ------------------------------------------------------------
# Verify parts and recursively split oversized parts
# ------------------------------------------------------------

verify_and_resplit()
{
    local DIRECTORY="$1"

    local NEED_SPLIT=0
    local FILE
    local TEMP_DIR

    echo
    echo "------------------------------------------------"
    echo "SIZE VERIFICATION"
    echo "------------------------------------------------"
    echo

    for FILE in "$DIRECTORY"/*.pcap
    do
        [ -e "$FILE" ] || continue

        local SIZE

        SIZE=$(stat -c%s "$FILE")

        echo "$(basename "$FILE"): $(format_size "$SIZE")"

        if [ "$SIZE" -gt "$MAX_SIZE_BYTES" ]
        then
            NEED_SPLIT=1

            echo "  -> Larger than ${MAX_SIZE_MB} MB"
        fi
    done

    # --------------------------------------------------------
    # If every file is <= 100 MB, we're finished.
    # --------------------------------------------------------

    if [ "$NEED_SPLIT" -eq 0 ]
    then
        echo
        echo "SUCCESS: All PCAP parts are <= ${MAX_SIZE_MB} MB."
        echo
        return 0
    fi

    echo
    echo "Some files are still larger than ${MAX_SIZE_MB} MB."
    echo "Splitting them again..."
    echo

    TEMP_DIR="$DIRECTORY/.resplit"

    mkdir -p "$TEMP_DIR"

    for FILE in "$DIRECTORY"/*.pcap
    do
        [ -e "$FILE" ] || continue

        local SIZE

        SIZE=$(stat -c%s "$FILE")

        if [ "$SIZE" -le "$MAX_SIZE_BYTES" ]
        then
            continue
        fi

        echo "Re-splitting:"
        echo "    $FILE"
        echo "    Size: $(format_size "$SIZE")"
        echo

        local PARTS

        PARTS=$(
            awk -v size="$SIZE" -v max="$MAX_SIZE_BYTES" \
            'BEGIN {
                print int((size + max - 1) / max)
            }'
        )

        if [ "$PARTS" -lt 2 ]
        then
            PARTS=2
        fi

        local PACKET_COUNT

        PACKET_COUNT=$(capinfos -c "$FILE" 2>/dev/null | \
            awk -F: '/Number of packets/ {
                gsub(/^[ \t]+/, "", $2);
                print $2
            }')

        local PREFIX

        PREFIX="$TEMP_DIR/$(basename "${FILE%.pcap}")_sub"

        if [ -n "$PACKET_COUNT" ]
        then

            local PACKETS_PER_PART

            PACKETS_PER_PART=$(
                awk -v packets="$PACKET_COUNT" \
                    -v parts="$PARTS" \
                    'BEGIN {
                        print int((packets + parts - 1) / parts)
                    }'
            )

            if [ "$PACKETS_PER_PART" -lt 1 ]
            then
                PACKETS_PER_PART=1
            fi

            editcap \
                -c "$PACKETS_PER_PART" \
                "$FILE" \
                "$PREFIX"

        else

            editcap \
                -C "$MAX_SIZE_BYTES" \
                "$FILE" \
                "$PREFIX"

        fi

        # Remove original oversized part.
        rm -f "$FILE"

        # Move new parts into main directory.
        local SUBFILE
        local SUBCOUNT=1

        for SUBFILE in "$TEMP_DIR"/*
        do
            [ -e "$SUBFILE" ] || continue

            local DEST

            DEST="$DIRECTORY/part_${RANDOM}_$(printf "%03d" "$SUBCOUNT").pcap"

            mv "$SUBFILE" "$DEST"

            SUBCOUNT=$((SUBCOUNT + 1))
        done
    done

    rmdir "$TEMP_DIR" 2>/dev/null || true

    # --------------------------------------------------------
    # Run verification again.
    # --------------------------------------------------------

    verify_and_resplit "$DIRECTORY"
}


# ------------------------------------------------------------
# Merge PCAP files
# ------------------------------------------------------------

merge_pcaps()
{
    local INPUT_DIR="$1"
    local OUTPUT_FILE="$2"

    echo
    echo "------------------------------------------------"
    echo "MERGING PCAP PARTS"
    echo "------------------------------------------------"
    echo

    echo "Input directory:"
    echo "    $INPUT_DIR"
    echo

    echo "Output:"
    echo "    $OUTPUT_FILE"
    echo

    # --------------------------------------------------------
    # Build sorted list of PCAP files.
    # --------------------------------------------------------

    mapfile -t PCAP_FILES < <(
        find "$INPUT_DIR" \
            -maxdepth 1 \
            -type f \
            -name "*.pcap" \
            -printf "%f\n" |
        sort -V
    )

    if [ "${#PCAP_FILES[@]}" -eq 0 ]
    then
        echo "ERROR: No PCAP files found."
        return 1
    fi

    echo "Parts to merge: ${#PCAP_FILES[@]}"
    echo

    local FILE
    local FULL_PATH

    local MERGE_ARGS=()

    for FILE in "${PCAP_FILES[@]}"
    do
        FULL_PATH="$INPUT_DIR/$FILE"

        echo "  + $FILE"

        MERGE_ARGS+=("$FULL_PATH")
    done

    echo

    # --------------------------------------------------------
    # Merge.
    # --------------------------------------------------------

    mergecap \
        -w "$OUTPUT_FILE" \
        "${MERGE_ARGS[@]}"

    if [ "$?" -ne 0 ]
    then
        echo
        echo "ERROR: mergecap failed."
        return 1
    fi

    echo
    echo "Merge completed."

    return 0
}


# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

clear

echo "================================================"
echo "       PCAP 100 MB PROCESSOR"
echo "================================================"
echo

# ------------------------------------------------------------
# Check dependencies
# ------------------------------------------------------------

check_requirements


# ------------------------------------------------------------
# Ask for PCAP
# ------------------------------------------------------------

read -r -p "Enter path to .pcap file: " INPUT_FILE

INPUT_FILE="${INPUT_FILE/#\~/$HOME}"

echo


# ------------------------------------------------------------
# Validate file
# ------------------------------------------------------------

if [ ! -f "$INPUT_FILE" ]
then
    echo "ERROR: File does not exist:"
    echo "    $INPUT_FILE"
    exit 1
fi


# ------------------------------------------------------------
# Check extension
# ------------------------------------------------------------

if [[ "${INPUT_FILE,,}" != *.pcap ]]
then
    echo "ERROR: File must have a .pcap extension."
    exit 1
fi


# ------------------------------------------------------------
# Get original size
# ------------------------------------------------------------

ORIGINAL_SIZE=$(stat -c%s "$INPUT_FILE")

echo "------------------------------------------------"
echo "FILE INFORMATION"
echo "------------------------------------------------"
echo
echo "File:"
echo "    $INPUT_FILE"
echo
echo "Size:"
echo "    $(format_size "$ORIGINAL_SIZE")"
echo


# ------------------------------------------------------------
# If <= 100 MB
# ------------------------------------------------------------

if [ "$ORIGINAL_SIZE" -le "$MAX_SIZE_BYTES" ]
then

    echo "PCAP file is <= ${MAX_SIZE_MB} MB."
    echo "No splitting is required."
    echo

    OUTPUT_FILE="$TMP_DIR/$(basename "$INPUT_FILE")"

    if [ -e "$OUTPUT_FILE" ]
    then
        echo "WARNING:"
        echo "$OUTPUT_FILE already exists."
        echo

        if ! ask_yes_no "Overwrite existing file?"
        then
            echo
            echo "Operation cancelled."
            exit 0
        fi

        rm -f "$OUTPUT_FILE"
    fi

    cp -p "$INPUT_FILE" "$OUTPUT_FILE"

    echo
    echo "Final PCAP:"
    echo "    $OUTPUT_FILE"
    echo

    exit 0
fi


# ------------------------------------------------------------
# File is > 100 MB
# ------------------------------------------------------------

echo "================================================"
echo "                    ALERT"
echo "================================================"
echo
echo "PCAP file is bigger than ${MAX_SIZE_MB} MB!"
echo
echo "Current size:"
echo "    $(format_size "$ORIGINAL_SIZE")"
echo


# ------------------------------------------------------------
# Ask user whether to split
# ------------------------------------------------------------

if ! ask_yes_no \
    "Do you want to break the PCAP into subfiles?"
then

    echo
    echo "Operation cancelled."
    exit 0
fi


# ------------------------------------------------------------
# Create split directory
# ------------------------------------------------------------

BASE_NAME=$(basename "$INPUT_FILE" .pcap)

SPLIT_DIR="$HOME_DIR/${BASE_NAME}_parts"

mkdir -p "$SPLIT_DIR"

echo
echo "Sub-PCAP files will be stored in:"
echo
echo "    $SPLIT_DIR"
echo


# ------------------------------------------------------------
# Remove old parts if present
# ------------------------------------------------------------

if compgen -G "$SPLIT_DIR/*.pcap" > /dev/null
then
    echo "WARNING: Existing PCAP parts were found."
    echo

    if ask_yes_no "Delete existing parts?"
    then
        rm -f "$SPLIT_DIR"/*.pcap
        echo "Existing parts deleted."
        echo
    else
        echo
        echo "Operation cancelled."
        exit 0
    fi
fi


# ------------------------------------------------------------
# Split PCAP
# ------------------------------------------------------------

echo "Starting PCAP processing..."
echo

split_pcap "$INPUT_FILE" "$SPLIT_DIR"

if [ "$?" -ne 0 ]
then
    echo
    echo "ERROR: PCAP splitting failed."
    exit 1
fi


# ------------------------------------------------------------
# Final verification
# ------------------------------------------------------------

echo
echo "------------------------------------------------"
echo "FINAL PARTS"
echo "------------------------------------------------"
echo

PART_COUNT=0

for FILE in "$SPLIT_DIR"/*.pcap
do
    [ -e "$FILE" ] || continue

    SIZE=$(stat -c%s "$FILE")

    echo "$(basename "$FILE")"
    echo "    Size: $(format_size "$SIZE")"

    if [ "$SIZE" -gt "$MAX_SIZE_BYTES" ]
    then
        echo "    ERROR: Still larger than ${MAX_SIZE_MB} MB!"
        exit 1
    fi

    PART_COUNT=$((PART_COUNT + 1))
done

echo
echo "Total parts: $PART_COUNT"
echo


# ------------------------------------------------------------
# Merge output
# ------------------------------------------------------------

FINAL_OUTPUT="$TMP_DIR/$(basename "$INPUT_FILE")"

if [ -e "$FINAL_OUTPUT" ]
then
    echo "WARNING:"
    echo "$FINAL_OUTPUT already exists."
    echo

    if ask_yes_no "Overwrite existing final PCAP?"
    then
        rm -f "$FINAL_OUTPUT"
    else
        echo
        echo "Operation cancelled."
        exit 0
    fi
fi


# ------------------------------------------------------------
# Merge
# ------------------------------------------------------------

merge_pcaps "$SPLIT_DIR" "$FINAL_OUTPUT"

if [ "$?" -ne 0 ]
then
    echo
    echo "ERROR: Failed to create final PCAP."
    exit 1
fi


# ------------------------------------------------------------
# Final result
# ------------------------------------------------------------

if [ ! -f "$FINAL_OUTPUT" ]
then
    echo
    echo "ERROR: Final PCAP was not created."
    exit 1
fi

FINAL_SIZE=$(stat -c%s "$FINAL_OUTPUT")


echo
echo "================================================"
echo "             PROCESS COMPLETED"
echo "================================================"
echo
echo "Original PCAP:"
echo "    $INPUT_FILE"
echo
echo "Original size:"
echo "    $(format_size "$ORIGINAL_SIZE")"
echo
echo "Sub-PCAP location:"
echo "    $SPLIT_DIR"
echo
echo "Number of parts:"
echo "    $PART_COUNT"
echo
echo "Final PCAP:"
echo "    $FINAL_OUTPUT"
echo
echo "Final size:"
echo "    $(format_size "$FINAL_SIZE")"
echo
echo "The original PCAP was NOT modified."
echo
echo "================================================"
