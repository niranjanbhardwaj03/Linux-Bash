#!/usr/bin/env python3

import hashlib
import os
import time
import dpkt

def packet_hash(packet_data):
    """Create a fingerprint for the complete packet."""
    return hashlib.sha256(packet_data).digest()

def deduplicate_pcap(input_file, output_file):
    seen = set()
    total_packets = 0
    unique_packets = 0
    duplicate_packets = 0
    input_size = os.path.getsize(input_file)
    start_time = time.time()

    print()
    print("=" * 65)
    print("              PCAP DUPLICATE REMOVER")
    print("=" * 65)
    print(f"Input file : {input_file}")
    print(f"Output file: {output_file}")
    print(f"Input size : {input_size / (1024 ** 3):.2f} GB")
    print()
    print("Processing...")
    print("-" * 65)

    with open(input_file, "rb") as f_in:
        # Check for PCAP-NG
        magic = f_in.read(4)
        f_in.seek(0)
        if magic == b"\x0a\x0d\x0d\x0a":
            raise ValueError(
                "PCAP-NG is not supported by this script. "
                "Please convert it to classic .pcap first."
            )
        reader = dpkt.pcap.Reader(f_in)
        with open(output_file, "wb") as f_out:
            writer = dpkt.pcap.Writer(
             f_out,
                linktype=reader.datalink()
            )
            for timestamp, packet_data in reader:
                total_packets += 1
                # Create fingerprint of packet
                packet_id = packet_hash(packet_data)
                # Duplicate packet
                if packet_id in seen:
                    duplicate_packets += 1
                    continue
                # New/unique packet
                seen.add(packet_id)
                writer.writepkt(
                    packet_data,
                    ts=timestamp
                )

                unique_packets += 1
                # Display progress every 100,000 packets
                if total_packets % 100000 == 0:
                    elapsed = time.time() - start_time
                    if input_size:
                        progress = (
                            f_in.tell() / input_size
                        ) * 100
                    else:
                        progress = 0

                    print(
                        f"\rPackets: {total_packets:,} | "
                        f"Unique: {unique_packets:,} | "
                        f"Duplicates: {duplicate_packets:,} | "
                        f"Progress: {progress:.1f}%",
                        end="",
                        flush=True
                    )

    elapsed = time.time() - start_time
    print()
    print()
    print("=" * 65)
    print("                         DONE")
    print("=" * 65)
    print(f"Total packets     : {total_packets:,}")
    print(f"Unique packets    : {unique_packets:,}")
    print(f"Duplicate packets : {duplicate_packets:,}")

    if total_packets > 0:
        removed = (
            duplicate_packets / total_packets
        ) * 100
        print(f"Duplicates removed: {removed:.2f}%")
    print(f"Processing time   : {elapsed:.2f} seconds")
    if os.path.exists(output_file):
        output_size = os.path.getsize(output_file)
        print(
            f"Output size       : "
            f"{output_size / (1024 ** 3):.2f} GB"
        )
    print(f"\nSaved to: {output_file}")
    print("=" * 65)


def main():
    print()
    print("=" * 65)
    print("              PCAP DEDUPLICATION TOOL")
    print("=" * 65)
    print()
    # Ask user for input PCAP
    input_file = input(
        "Enter path to input .pcap file: "
    ).strip().strip('"')
    if not input_file:
        print("ERROR: No input file specified.")
        return
    # Check input file
    if not os.path.isfile(input_file):
        print()
        print(f"ERROR: File does not exist:")
        print(input_file)
        return
    # Make sure it is a PCAP
    if not input_file.lower().endswith(".pcap"):
        print()
        print("WARNING: The input file does not have a .pcap extension.")
        answer = input(
            "Continue anyway? [y/N]: "
        ).strip().lower()
        if answer != "y":
            return

    # Ask user for output file
    print()
    output_file = input(
        "Enter path for output .pcap file "
        "(press Enter for automatic name): "
    ).strip().strip('"')

    # Automatic output filename
    if not output_file:
        directory = os.path.dirname(input_file)
        filename = os.path.basename(input_file)
        name, ext = os.path.splitext(filename)
        output_file = os.path.join(
            directory,
            f"{name}_deduplicated.pcap"
        )

    # Make sure output has .pcap extension
    if not output_file.lower().endswith(".pcap"):
        output_file += ".pcap"
    # Don't overwrite input
    if os.path.abspath(input_file) == os.path.abspath(output_file):
        print()
        print("ERROR:")
        print("Input and output files must be different.")
        return

    # Check if output already exists
    if os.path.exists(output_file):
        print()
        print(f"WARNING: Output file already exists:")
        print(output_file)
        answer = input(
            "Overwrite it? [y/N]: "
        ).strip().lower()
        if answer != "y":
            print("Operation cancelled.")
            return

    print()
    try:
        deduplicate_pcap(
            input_file,
            output_file
        )

    except dpkt.dpkt.NeedData:
        print()
        print("ERROR: The PCAP file appears to be incomplete or corrupted.")
    except ValueError as e:
        print()
        print(f"ERROR: {e}")
    except PermissionError:
        print()
        print(
            "ERROR: Permission denied. "
            "Check that you have permission to read/write the files."
        )

    except Exception as e:
        print()
        print(f"ERROR: {type(e).__name__}: {e}")


if __name__ == "__main__":
    main()
