#!/usr/bin/env python3

import os
import math
import shutil
import subprocess
import sys
from pathlib import Path

from scapy.utils import PcapReader, PcapWriter


# ---------------------------------------------------------
# Configuration
# ---------------------------------------------------------

MAX_SIZE_MB = 100
MAX_SIZE_BYTES = MAX_SIZE_MB * 1024 * 1024

HOME_SPLIT_DIR = Path("/home")
TMP_OUTPUT_DIR = Path("/tmp")


# ---------------------------------------------------------
# Utility functions
# ---------------------------------------------------------

def get_file_size(file_path):
    """Return file size in bytes."""
    return os.path.getsize(file_path)


def format_size(size_bytes):
    """Convert bytes to a human-readable size."""
    if size_bytes < 1024:
        return f"{size_bytes} B"

    if size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.2f} KB"

    if size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.2f} MB"

    return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"


def ask_yes_no(question):
    """Ask user for yes/no input."""
    while True:
        answer = input(f"{question} [y/n]: ").strip().lower()

        if answer in ("y", "yes"):
            return True

        if answer in ("n", "no"):
            return False

        print("Please enter y or n.")


# ---------------------------------------------------------
# PCAP splitting
# ---------------------------------------------------------

def split_pcap(input_file, output_directory):
    """
    Split a PCAP into approximately equal-sized parts.

    The number of parts is initially calculated from the
    original file size. Each part is then checked. If a part
    is still larger than 100 MB, it is split again.
    """

    input_file = Path(input_file)
    output_directory = Path(output_directory)

    output_directory.mkdir(parents=True, exist_ok=True)

    original_size = get_file_size(input_file)

    # Calculate initial number of parts.
    number_of_parts = math.ceil(original_size / MAX_SIZE_BYTES)

    # If file is 500 MB:
    # number_of_parts = ceil(500 / 100) = 5
    #
    # Target size is approximately:
    # 500 / 5 = 100 MB

    target_size = math.ceil(original_size / number_of_parts)

    print()
    print("------------------------------------------------")
    print("PCAP SPLITTING")
    print("------------------------------------------------")
    print(f"Original size : {format_size(original_size)}")
    print(f"Number parts  : {number_of_parts}")
    print(f"Target size   : {format_size(target_size)}")
    print()

    first_level_parts = []

    # -----------------------------------------------------
    # First split
    # -----------------------------------------------------

    reader = PcapReader(str(input_file))

    part_number = 1
    current_file = None
    current_path = None

    try:
        for packet in reader:

            if current_file is None:
                current_path = (
                    output_directory /
                    f"{input_file.stem}_part_{part_number:03d}.pcap"
                )

                current_file = PcapWriter(
                    str(current_path),
                    append=False,
                    sync=True
                )

                print(f"Creating: {current_path}")

            current_file.write(packet)

            # Check actual file size.
            current_file.flush()

            current_size = current_path.stat().st_size

            # Once target size has been reached, start
            # another part.
            if current_size >= target_size and part_number < number_of_parts:
                current_file.close()
                first_level_parts.append(current_path)

                part_number += 1
                current_file = None

    finally:
        if current_file is not None:
            current_file.close()

        reader.close()

    # Add final part.
    if current_path is not None and current_path not in first_level_parts:
        first_level_parts.append(current_path)

    print()
    print("Initial split completed.")
    print()

    # -----------------------------------------------------
    # Check whether any part is > 100 MB
    # -----------------------------------------------------

    final_parts = []

    for part in first_level_parts:

        part_size = get_file_size(part)

        print(
            f"{part.name}: "
            f"{format_size(part_size)}"
        )

        if part_size <= MAX_SIZE_BYTES:
            final_parts.append(part)
        else:
            print(
                f"  -> {part.name} is still larger than "
                f"{MAX_SIZE_MB} MB."
            )

            smaller_parts = split_large_part(
                part,
                output_directory
            )

            final_parts.extend(smaller_parts)

            # Remove the intermediate oversized file.
            try:
                part.unlink()
            except OSError:
                pass

    # Sort according to filename so packet order is preserved.
    final_parts.sort()

    print()
    print("------------------------------------------------")
    print("FINAL PARTS")
    print("------------------------------------------------")

    for part in final_parts:
        print(
            f"{part.name:<50} "
            f"{format_size(get_file_size(part))}"
        )

    return final_parts


def split_large_part(input_file, output_directory):
    """
    Split an oversized PCAP recursively until all generated
    files are <= 100 MB.
    """

    input_file = Path(input_file)

    size = get_file_size(input_file)

    number_of_parts = math.ceil(size / MAX_SIZE_BYTES)

    target_size = math.ceil(size / number_of_parts)

    print()
    print(
        f"Splitting {input_file.name} "
        f"into {number_of_parts} smaller parts..."
    )

    reader = PcapReader(str(input_file))

    generated_parts = []

    current_file = None
    current_path = None

    part_number = 1

    try:
        for packet in reader:

            if current_file is None:

                current_path = (
                    output_directory /
                    f"{input_file.stem}_sub_{part_number:03d}.pcap"
                )

                current_file = PcapWriter(
                    str(current_path),
                    append=False,
                    sync=True
                )

            current_file.write(packet)
            current_file.flush()

            current_size = current_path.stat().st_size

            if (
                current_size >= target_size
                and part_number < number_of_parts
            ):
                current_file.close()

                generated_parts.append(current_path)

                part_number += 1
                current_file = None

    finally:
        if current_file is not None:
            current_file.close()

        reader.close()

    if (
        current_path is not None
        and current_path not in generated_parts
    ):
        generated_parts.append(current_path)

    # -----------------------------------------------------
    # Recursively verify the generated files.
    # -----------------------------------------------------

    final_parts = []

    for part in generated_parts:

        part_size = get_file_size(part)

        if part_size <= MAX_SIZE_BYTES:
            final_parts.append(part)

        else:
            # Still too large -> split again.
            smaller_parts = split_large_part(
                part,
                output_directory
            )

            final_parts.extend(smaller_parts)

            try:
                part.unlink()
            except OSError:
                pass

    final_parts.sort()

    return final_parts


# ---------------------------------------------------------
# PCAP merging
# ---------------------------------------------------------

def merge_pcaps(pcap_parts, output_file):
    """
    Merge PCAP parts back into a single PCAP.

    Uses mergecap because it is designed specifically for
    merging capture files.
    """

    output_file = Path(output_file)

    print()
    print("------------------------------------------------")
    print("MERGING PCAP PARTS")
    print("------------------------------------------------")

    print(f"Output: {output_file}")
    print()

    # Check that mergecap exists.
    mergecap_path = shutil.which("mergecap")

    if mergecap_path is None:
        print(
            "ERROR: 'mergecap' was not found."
        )
        print()
        print(
            "Please install Wireshark/tshark tools."
        )
        print()
        print(
            "On Ubuntu/Debian:"
        )
        print(
            "    sudo apt install wireshark-common"
        )
        print()

        return False

    command = [
        mergecap_path,
        "-w",
        str(output_file)
    ]

    command.extend(str(part) for part in pcap_parts)

    print("Running mergecap...")

    try:
        subprocess.run(
            command,
            check=True
        )

    except subprocess.CalledProcessError as error:
        print()
        print("ERROR: Failed to merge PCAP files.")
        print(f"mergecap exit code: {error.returncode}")
        return False

    print()
    print("PCAP merge completed.")

    return True


# ---------------------------------------------------------
# Main program
# ---------------------------------------------------------

def main():

    print()
    print("================================================")
    print("       PCAP 100 MB PROCESSOR")
    print("================================================")
    print()

    # -----------------------------------------------------
    # Get input PCAP
    # -----------------------------------------------------

    input_path = input(
        "Enter path to .pcap file: "
    ).strip()

    input_file = Path(input_path).expanduser()

    # -----------------------------------------------------
    # Validate input
    # -----------------------------------------------------

    if not input_file.exists():
        print()
        print("ERROR: File does not exist.")
        sys.exit(1)

    if not input_file.is_file():
        print()
        print("ERROR: Path is not a file.")
        sys.exit(1)

    if input_file.suffix.lower() != ".pcap":
        print()
        print("ERROR: Input file must have .pcap extension.")
        sys.exit(1)

    # -----------------------------------------------------
    # Check size
    # -----------------------------------------------------

    original_size = get_file_size(input_file)

    print()
    print("------------------------------------------------")
    print("FILE INFORMATION")
    print("------------------------------------------------")
    print(f"File : {input_file}")
    print(f"Size : {format_size(original_size)}")
    print()

    # -----------------------------------------------------
    # File <= 100 MB
    # -----------------------------------------------------

    if original_size <= MAX_SIZE_BYTES:

        print(
            f"PCAP file is <= {MAX_SIZE_MB} MB."
        )

        output_file = (
            TMP_OUTPUT_DIR /
            input_file.name
        )

        shutil.copy2(
            input_file,
            output_file
        )

        print()
        print("No splitting required.")
        print(f"Final PCAP: {output_file}")
        print()

        return

    # -----------------------------------------------------
    # File > 100 MB
    # -----------------------------------------------------

    print(
        f"ALERT: PCAP file is bigger than "
        f"{MAX_SIZE_MB} MB!"
    )

    print(
        f"Current size: {format_size(original_size)}"
    )

    print()

    # Ask user.
    should_split = ask_yes_no(
        "Do you want to break the PCAP into subfiles?"
    )

    if not should_split:

        print()
        print("Operation cancelled.")
        return

    # -----------------------------------------------------
    # Create split directory
    # -----------------------------------------------------

    split_directory = (
        HOME_SPLIT_DIR /
        f"{input_file.stem}_parts"
    )

    split_directory.mkdir(
        parents=True,
        exist_ok=True
    )

    print()
    print(
        f"Sub-PCAP files will be saved in:"
    )
    print(
        f"    {split_directory}"
    )

    # -----------------------------------------------------
    # Split
    # -----------------------------------------------------

    try:
        pcap_parts = split_pcap(
            input_file,
            split_directory
        )

    except Exception as error:
        print()
        print("ERROR while splitting PCAP:")
        print(error)
        sys.exit(1)

    if not pcap_parts:
        print()
        print("ERROR: No PCAP parts were created.")
        sys.exit(1)

    # -----------------------------------------------------
    # Verify every part <= 100 MB
    # -----------------------------------------------------

    print()
    print("------------------------------------------------")
    print("SIZE VERIFICATION")
    print("------------------------------------------------")

    oversized_parts = []

    for part in pcap_parts:

        size = get_file_size(part)

        print(
            f"{part.name}: {format_size(size)}"
        )

        if size > MAX_SIZE_BYTES:
            oversized_parts.append(part)

    if oversized_parts:

        print()
        print(
            "ERROR: Some parts are still larger than "
            f"{MAX_SIZE_MB} MB."
        )

        for part in oversized_parts:
            print(f"  {part}")

        sys.exit(1)

    print()
    print(
        f"SUCCESS: All PCAP parts are <= "
        f"{MAX_SIZE_MB} MB."
    )

    # -----------------------------------------------------
    # Merge parts back together
    # -----------------------------------------------------

    final_output = (
        TMP_OUTPUT_DIR /
        input_file.name
    )

    # Remove existing output if necessary.
    if final_output.exists():

        print()
        print(
            f"WARNING: {final_output} already exists."
        )

        overwrite = ask_yes_no(
            "Do you want to overwrite it?"
        )

        if not overwrite:
            print()
            print("Operation cancelled.")
            return

        final_output.unlink()

    # Merge.
    success = merge_pcaps(
        pcap_parts,
        final_output
    )

    if not success:
        sys.exit(1)

    # -----------------------------------------------------
    # Final verification
    # -----------------------------------------------------

    if final_output.exists():

        final_size = get_file_size(final_output)

        print()
        print("================================================")
        print("              PROCESS COMPLETED")
        print("================================================")
        print()
        print(f"Original PCAP : {input_file}")
        print(
            f"Original size : "
            f"{format_size(original_size)}"
        )
        print()
        print(f"Parts location: {split_directory}")
        print(f"Number parts  : {len(pcap_parts)}")
        print()
        print(f"Final PCAP    : {final_output}")
        print(
            f"Final size    : "
            f"{format_size(final_size)}"
        )
        print()
        print(
            "The original PCAP has NOT been modified."
        )
        print()

    else:

        print()
        print(
            "ERROR: Final PCAP was not created."
        )
        sys.exit(1)


# ---------------------------------------------------------
# Program entry point
# ---------------------------------------------------------

if __name__ == "__main__":
    main()
