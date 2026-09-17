#!/usr/bin/env python3

import os
import sys
import hashlib
import time

from scapy.all import PcapReader, PcapWriter


def get_packet_hash(packet):
    """
    Generate a SHA-256 hash from the complete packet bytes.

    Two packets with exactly the same packet data
    will have the same hash.
    """
    return hashlib.sha256(bytes(packet)).digest()


def deduplicate_pcap(input_file, output_file):

    total_packets = 0
    unique_packets = 0
    duplicate_packets = 0

    # Store fingerprints of packets already seen.
    seen_packets = set()

    input_size = os.path.getsize(input_file)
    start_time = time.time()

    print()
    print("=" * 70)
    print("                    PCAP DEDUPLICATION")
    print("=" * 70)
    print(f"Input file :  {input_file}")
    print(f"Output file:  {output_file}")
    print(f"Input size :  {input_size / (1024 ** 3):.2f} GB")
    print("=" * 70)
    print()
    print("Reading packets...")
    print()

    try:

        # PcapReader reads packets one at a time.
        # This is much better for large PCAP files.
        reader = PcapReader(input_file)

        # Write packets to the new PCAP.
        writer = PcapWriter(
            output_file,
            append=False,
            sync=False
        )

        for packet in reader:

            total_packets += 1

            # Generate unique fingerprint
            packet_hash = get_packet_hash(packet)

            # Check if this exact packet already exists
            if packet_hash in seen_packets:

                duplicate_packets += 1

            else:

                # First occurrence of this packet
                seen_packets.add(packet_hash)

                writer.write(packet)

                unique_packets += 1

            # Progress display
            if total_packets % 100000 == 0:

                elapsed = time.time() - start_time

                try:
                    current_position = reader.f.tell()

                    progress = (
                        current_position / input_size
                    ) * 100

                    if progress > 100:
                        progress = 100

                except Exception:
                    progress = 0

                print(
                    f"\r"
                    f"Packets: {total_packets:,} | "
                    f"Unique: {unique_packets:,} | "
                    f"Duplicates: {duplicate_packets:,} | "
                    f"Progress: {progress:.1f}% | "
                    f"Time: {elapsed:.0f}s",
                    end="",
                    flush=True
                )

        reader.close()
        writer.close()

    except Exception:

        # Make sure files are closed if something goes wrong.
        try:
            reader.close()
        except Exception:
            pass

        try:
            writer.close()
        except Exception:
            pass

        raise

    elapsed = time.time() - start_time

    print()
    print()
    print("=" * 70)
    print("                         COMPLETE")
    print("=" * 70)

    print(f"Total packets     : {total_packets:,}")
    print(f"Unique packets    : {unique_packets:,}")
    print(f"Duplicate packets : {duplicate_packets:,}")

    if total_packets > 0:

        duplicate_percentage = (
            duplicate_packets / total_packets
        ) * 100

        print(
            f"Duplicates removed: "
            f"{duplicate_percentage:.2f}%"
        )

    print(f"Processing time   : {elapsed:.2f} seconds")

    if os.path.exists(output_file):

        output_size = os.path.getsize(output_file)

        print(
            f"Output size       : "
            f"{output_size / (1024 ** 3):.2f} GB"
        )

    print()
    print(f"Output saved to:")
    print(output_file)
    print("=" * 70)


def main():

    print()
    print("=" * 70)
    print("                  PCAP DEDUPLICATION TOOL")
    print("=" * 70)
    print()

    # ---------------------------------------------------------
    # Ask for input PCAP
    # ---------------------------------------------------------

    input_file = input(
        "Enter path to input PCAP file: "
    ).strip().strip('"').strip("'")

    if not input_file:

        print("ERROR: No input file specified.")
        sys.exit(1)

    # Expand ~ in paths such as ~/Downloads/file.pcap
    input_file = os.path.expanduser(input_file)

    # Convert to absolute path
    input_file = os.path.abspath(input_file)

    if not os.path.isfile(input_file):

        print()
        print("ERROR: Input file does not exist:")
        print(input_file)

        sys.exit(1)

    # ---------------------------------------------------------
    # Automatic output filename
    # ---------------------------------------------------------

    directory = os.path.dirname(input_file)
    filename = os.path.basename(input_file)

    name, extension = os.path.splitext(filename)

    default_output = os.path.join(
        directory,
        name + "_deduplicated.pcap"
    )

    print()
    print(
        "Output file path "
        "(press ENTER for automatic name):"
    )

    print(f"Default: {default_output}")

    output_file = input(
        "Output: "
    ).strip().strip('"').strip("'")

    if not output_file:

        output_file = default_output

    else:

        output_file = os.path.expanduser(output_file)
        output_file = os.path.abspath(output_file)

    # ---------------------------------------------------------
    # Make sure output has .pcap extension
    # ---------------------------------------------------------

    if not output_file.lower().endswith(".pcap"):

        output_file += ".pcap"

    # ---------------------------------------------------------
    # Prevent overwriting input
    # ---------------------------------------------------------

    if os.path.abspath(input_file) == os.path.abspath(output_file):

        print()
        print("ERROR:")
        print("Input and output files must be different.")

        sys.exit(1)

    # ---------------------------------------------------------
    # Check existing output
    # ---------------------------------------------------------

    if os.path.exists(output_file):

        print()
        print("WARNING: Output file already exists:")
        print(output_file)

        answer = input(
            "Overwrite it? [y/N]: "
        ).strip().lower()

        if answer != "y":

            print("Cancelled.")
            sys.exit(0)

    # ---------------------------------------------------------
    # Run
    # ---------------------------------------------------------

    try:

        deduplicate_pcap(
            input_file,
            output_file
        )

    except KeyboardInterrupt:

        print()
        print()
        print("Operation cancelled by user.")

        sys.exit(1)

    except Exception as error:

        print()
        print()
        print("=" * 70)
        print("ERROR")
        print("=" * 70)
        print(type(error).__name__)
        print(error)
        print("=" * 70)

        sys.exit(1)


if __name__ == "__main__":
    main()
