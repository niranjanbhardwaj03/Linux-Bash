import os
import zipfile
import subprocess
import shutil
import ipaddress
from collections import Counter
from datetime import datetime


# ============================================================
# CONFIGURATION
# ============================================================

SIZE_LIMIT_MB = 100
SIZE_LIMIT_BYTES = SIZE_LIMIT_MB * 1024 * 1024

# Maximum packets in each split PCAP.
# Example: 500000 = up to 500,000 packets per part.
PACKETS_PER_PART = 500000


# ============================================================
# GENERAL FUNCTIONS
# ============================================================

def clean_path(path):
    """Remove quotes/spaces from a pasted path."""
    return path.strip().strip('"').strip("'")


def get_size_mb(file_path):
    """Get file size in MB."""
    return os.path.getsize(file_path) / (1024 * 1024)


def find_pcap_files(folder):
    """
    Recursively find .pcap and .pcapng files.
    """
    pcap_files = []

    for root, dirs, files in os.walk(folder):
        for file in files:
            if file.lower().endswith((".pcap", ".pcapng")):
                pcap_files.append(
                    os.path.join(root, file)
                )

    return sorted(pcap_files)


def is_internal_ip(ip):
    """Check whether an IP is private/internal."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


# ============================================================
# CHECK EXTERNAL PROGRAMS
# ============================================================

def tshark_available():
    return shutil.which("tshark") is not None


def editcap_available():
    return shutil.which("editcap") is not None


# ============================================================
# RUN TSHARK
# ============================================================

def run_tshark(pcap_file, fields, display_filter=None):
    """
    Extract fields from a PCAP using TShark.
    """

    command = [
        "tshark",
        "-r",
        pcap_file,
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-E",
        "occurrence=f",
        "-E",
        "aggregator=,"
    ]

    for field in fields:
        command.extend(["-e", field])

    if display_filter:
        command.extend(["-Y", display_filter])

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace"
        )

        if result.returncode != 0:
            return []

        rows = []

        for line in result.stdout.splitlines():
            values = line.split("\t")

            if any(value.strip() for value in values):
                rows.append(values)

        return rows

    except FileNotFoundError:
        return []


# ============================================================
# IP ANALYSIS
# ============================================================

def get_ip_statistics(pcap_file):

    rows = run_tshark(
        pcap_file,
        [
            "ip.src",
            "ip.dst",
            "ipv6.src",
            "ipv6.dst"
        ]
    )

    all_ips = Counter()

    for row in rows:

        for value in row:

            # TShark may return multiple values separated by comma.
            for ip in value.split(","):

                ip = ip.strip()

                if ip:
                    all_ips[ip] += 1

    internal = Counter()
    external = Counter()

    for ip, count in all_ips.items():

        if is_internal_ip(ip):
            internal[ip] = count
        else:
            external[ip] = count

    return internal, external


# ============================================================
# PORT ANALYSIS
# ============================================================

def get_port_statistics(pcap_file):

    rows = run_tshark(
        pcap_file,
        [
            "tcp.srcport",
            "tcp.dstport",
            "udp.srcport",
            "udp.dstport"
        ]
    )

    ports = Counter()

    for row in rows:

        for value in row:

            for port in value.split(","):

                port = port.strip()

                if port:
                    ports[port] += 1

    return ports


# ============================================================
# DNS ANALYSIS
# ============================================================

def get_dns_statistics(pcap_file):

    rows = run_tshark(
        pcap_file,
        [
            "dns.qry.name",
            "dns.qry.type"
        ],
        "dns.qry.name"
    )

    domains = Counter()

    for row in rows:

        if not row:
            continue

        domain = row[0].strip()

        if domain:
            domains[domain] += 1

    return domains


# ============================================================
# HTTP ANALYSIS
# ============================================================

def get_http_statistics(pcap_file):

    rows = run_tshark(
        pcap_file,
        [
            "ip.src",
            "ip.dst",
            "tcp.srcport",
            "tcp.dstport",
            "http.host",
            "http.request.method",
            "http.request.uri"
        ],
        "http"
    )

    hosts = Counter()
    methods = Counter()
    connections = Counter()
    requests = Counter()

    for row in rows:

        if len(row) < 7:
            continue

        src_ip = row[0].strip()
        dst_ip = row[1].strip()
        src_port = row[2].strip()
        dst_port = row[3].strip()
        host = row[4].strip()
        method = row[5].strip()
        uri = row[6].strip()

        if host:
            hosts[host] += 1

        if method:
            methods[method] += 1

        if uri:
            requests[uri] += 1

        if src_ip and dst_ip and src_port and dst_port:

            connection = (
                f"{src_ip}:{src_port} -> "
                f"{dst_ip}:{dst_port}"
            )

            connections[connection] += 1

    return hosts, methods, requests, connections


# ============================================================
# HTTPS / TLS ANALYSIS
# ============================================================

def get_https_statistics(pcap_file):

    rows = run_tshark(
        pcap_file,
        [
            "ip.src",
            "ip.dst",
            "tcp.srcport",
            "tcp.dstport",
            "tls.handshake.extensions_server_name"
        ],
        "tls.handshake.extensions_server_name"
    )

    domains = Counter()
    connections = Counter()

    for row in rows:

        if len(row) < 5:
            continue

        src_ip = row[0].strip()
        dst_ip = row[1].strip()
        src_port = row[2].strip()
        dst_port = row[3].strip()
        domain = row[4].strip()

        if domain:
            domains[domain] += 1

        if src_ip and dst_ip and src_port and dst_port:

            connection = (
                f"{src_ip}:{src_port} -> "
                f"{dst_ip}:{dst_port}"
            )

            connections[connection] += 1

    return domains, connections


# ============================================================
# PROTOCOL ANALYSIS
# ============================================================

def get_protocol_statistics(pcap_file):

    rows = run_tshark(
        pcap_file,
        ["_ws.col.Protocol"]
    )

    protocols = Counter()

    for row in rows:

        if row:

            protocol = row[0].strip()

            if protocol:
                protocols[protocol] += 1

    return protocols


# ============================================================
# REPORT FUNCTIONS
# ============================================================

def write_counter(report, title, counter, maximum=50):

    report.write("\n")
    report.write("-" * 70 + "\n")
    report.write(title + "\n")
    report.write("-" * 70 + "\n")

    if not counter:

        report.write("No repeated data found.\n")
        return

    for value, count in counter.most_common(maximum):

        report.write(
            f"{value}  -->  {count} occurrences\n"
        )


def analyze_big_pcap(pcap_file, report):

    filename = os.path.basename(pcap_file)
    size_mb = get_size_mb(pcap_file)

    report.write("\n")
    report.write("=" * 80 + "\n")
    report.write(f"TRAFFIC ANALYSIS: {filename}\n")
    report.write("=" * 80 + "\n")

    report.write(
        f"PCAP Path : {pcap_file}\n"
    )

    report.write(
        f"PCAP Size : {size_mb:.2f} MB\n"
    )

    # --------------------------------------------------------
    # INTERNAL / EXTERNAL IPs
    # --------------------------------------------------------

    internal_ips, external_ips = get_ip_statistics(
        pcap_file
    )

    write_counter(
        report,
        "REPEATED INTERNAL IPs",
        internal_ips
    )

    write_counter(
        report,
        "REPEATED EXTERNAL IPs",
        external_ips
    )

    # --------------------------------------------------------
    # PORTS
    # --------------------------------------------------------

    ports = get_port_statistics(
        pcap_file
    )

    write_counter(
        report,
        "REPEATED PORTS",
        ports
    )

    # --------------------------------------------------------
    # DNS
    # --------------------------------------------------------

    dns_domains = get_dns_statistics(
        pcap_file
    )

    write_counter(
        report,
        "REPEATED DNS QUERIES / DOMAINS",
        dns_domains
    )

    # --------------------------------------------------------
    # HTTP
    # --------------------------------------------------------

    http_hosts, http_methods, http_requests, http_connections = (
        get_http_statistics(pcap_file)
    )

    write_counter(
        report,
        "REPEATED HTTP HOSTS / DOMAINS",
        http_hosts
    )

    write_counter(
        report,
        "REPEATED HTTP METHODS / ACTIONS",
        http_methods
    )

    write_counter(
        report,
        "REPEATED HTTP REQUEST URIs",
        http_requests
    )

    write_counter(
        report,
        "REPEATED HTTP CONNECTIONS",
        http_connections
    )

    # --------------------------------------------------------
    # HTTPS / TLS
    # --------------------------------------------------------

    https_domains, https_connections = (
        get_https_statistics(pcap_file)
    )

    write_counter(
        report,
        "REPEATED HTTPS / TLS SNI DOMAINS",
        https_domains
    )

    write_counter(
        report,
        "REPEATED HTTPS / TLS CONNECTIONS",
        https_connections
    )

    # --------------------------------------------------------
    # PROTOCOLS
    # --------------------------------------------------------

    protocols = get_protocol_statistics(
        pcap_file
    )

    write_counter(
        report,
        "REPEATED PROTOCOLS / TRAFFIC ACTIONS",
        protocols
    )


# ============================================================
# SPLIT PCAP
# ============================================================

def split_pcap(pcap_file):

    if not editcap_available():

        print(
            "\nAlert: editcap was not found."
        )

        print(
            "Install Wireshark/Editcap and make sure "
            "editcap is available in PATH."
        )

        return None

    filename = os.path.basename(
        pcap_file
    )

    name = os.path.splitext(
        filename
    )[0]

    parent = os.path.dirname(
        pcap_file
    )

    output_directory = os.path.join(
        parent,
        name + "_parts"
    )

    os.makedirs(
        output_directory,
        exist_ok=True
    )

    output_prefix = os.path.join(
        output_directory,
        name
    )

    print(
        f"\nSplitting {filename}..."
    )

    command = [
        "editcap",
        "-c",
        str(PACKETS_PER_PART),
        pcap_file,
        output_prefix + ".pcap"
    ]

    try:

        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace"
        )

        if result.returncode != 0:

            print(
                "\nAlert: PCAP splitting failed."
            )

            print(result.stderr)

            return None

    except Exception as error:

        print(
            f"\nAlert: Error while splitting: {error}"
        )

        return None

    parts = find_pcap_files(
        output_directory
    )

    if not parts:

        print(
            "\nAlert: No split files were created."
        )

        return None

    return output_directory, parts


# ============================================================
# CREATE ZIP
# ============================================================

def create_zip(parts_directory, original_pcap):

    filename = os.path.basename(
        original_pcap
    )

    name = os.path.splitext(
        filename
    )[0]

    parent = os.path.dirname(
        original_pcap
    )

    zip_path = os.path.join(
        parent,
        name + "_parts.zip"
    )

    print(
        "\nCreating ZIP archive..."
    )

    with zipfile.ZipFile(
        zip_path,
        "w",
        compression=zipfile.ZIP_DEFLATED
    ) as zip_file:

        for root, dirs, files in os.walk(
            parts_directory
        ):

            for file in files:

                if file.lower().endswith(
                    (".pcap", ".pcapng")
                ):

                    full_path = os.path.join(
                        root,
                        file
                    )

                    zip_file.write(
                        full_path,
                        arcname=file
                    )

    return zip_path


# ============================================================
# MAIN PROGRAM
# ============================================================

def main():

    print("=" * 80)
    print("          PCAP ZIP TRAFFIC ANALYZER")
    print("=" * 80)

    # --------------------------------------------------------
    # Check TShark
    # --------------------------------------------------------

    if not tshark_available():

        print(
            "\nAlert: TShark is not installed "
            "or is not available in PATH."
        )

        print(
            "Install Wireshark and make sure "
            "'tshark' works from the command line."
        )

        return

    # --------------------------------------------------------
    # ASK FOR FILE PATH
    # --------------------------------------------------------

    input_file = input(
        "\nEnter .pcap file path: "
    )

    input_file = clean_path(
        input_file
    )

    # --------------------------------------------------------
    # FILE EXISTS?
    # --------------------------------------------------------

    if not os.path.isfile(input_file):

        print(
            "\nAlert: File does not exist."
        )

        return

    # --------------------------------------------------------
    # CHECK ZIP
    # --------------------------------------------------------

    if not zipfile.is_zipfile(input_file):

        print(
            "\nAlert: File is not in ZIP format..."
        )

        return

    print(
        "\nZIP format detected."
    )

    # --------------------------------------------------------
    # EXTRACT ZIP
    # --------------------------------------------------------

    original_directory = os.path.dirname(
        input_file
    )

    zip_name = os.path.splitext(
        os.path.basename(input_file)
    )[0]

    extract_directory = os.path.join(
        original_directory,
        zip_name + "_extracted"
    )

    os.makedirs(
        extract_directory,
        exist_ok=True
    )

    print(
        f"Extracting files to:\n"
        f"{extract_directory}"
    )

    try:

        with zipfile.ZipFile(
            input_file,
            "r"
        ) as zip_ref:

            zip_ref.extractall(
                extract_directory
            )

    except zipfile.BadZipFile:

        print(
            "\nAlert: ZIP file is corrupted."
        )

        return

    print(
        "Extraction completed."
    )

    # --------------------------------------------------------
    # FIND PCAP FILES
    # --------------------------------------------------------

    pcap_files = find_pcap_files(
        extract_directory
    )

    if not pcap_files:

        print(
            "\nAlert: No .pcap/.pcapng files "
            "found inside the ZIP."
        )

        return

    print(
        f"\nFound {len(pcap_files)} PCAP file(s)."
    )

    # --------------------------------------------------------
    # REPORT FILE
    # --------------------------------------------------------

    report_path = os.path.join(
        original_directory,
        zip_name + "_analysis.txt"
    )

    big_files = []

    # --------------------------------------------------------
    # CREATE REPORT
    # --------------------------------------------------------

    with open(
        report_path,
        "w",
        encoding="utf-8"
    ) as report:

        report.write(
            "PCAP TRAFFIC ANALYSIS REPORT\n"
        )

        report.write(
            "=" * 80 + "\n"
        )

        report.write(
            f"Generated: "
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        )

        report.write(
            f"Input ZIP: {input_file}\n"
        )

        report.write(
            f"Large file limit: "
            f"{SIZE_LIMIT_MB} MB\n"
        )

        report.write(
            "=" * 80 + "\n\n"
        )

        # ----------------------------------------------------
        # CHECK SIZE OF ALL PCAP FILES
        # ----------------------------------------------------

        report.write(
            "PCAP FILE SIZE SUMMARY\n"
        )

        report.write(
            "=" * 80 + "\n"
        )

        for pcap_file in pcap_files:

            filename = os.path.basename(
                pcap_file
            )

            size_mb = get_size_mb(
                pcap_file
            )

            # Required highlighted output
            print(
                f"\n*** {filename} Size is "
                f"{size_mb:.2f} MB ***"
            )

            report.write(
                f"{filename} Size is "
                f"{size_mb:.2f} MB\n"
            )

            if size_mb > SIZE_LIMIT_MB:

                print(
                    f"Alert: {filename} "
                    f"file is bigger than 100mb"
                )

                report.write(
                    f"Alert: {filename} "
                    f"file is bigger than 100mb\n"
                )

                big_files.append(
                    pcap_file
                )

            else:

                report.write(
                    "Status: File is within "
                    "100 MB limit.\n"
                )

        # ----------------------------------------------------
        # ANALYZE ONLY BIG FILES
        # ----------------------------------------------------

        if big_files:

            report.write(
                "\n\n"
                + "#" * 80
                + "\n"
            )

            report.write(
                "BIG PCAP TRAFFIC ANALYSIS"
            )

            report.write(
                "\n"
                + "#" * 80
                + "\n"
            )

            for pcap_file in big_files:

                print(
                    "\nAnalyzing:"
                    f" {os.path.basename(pcap_file)}"
                )

                print(
                    "Checking repeated internal/external "
                    "IPs, ports, DNS, HTTP, HTTPS, "
                    "domains and protocols..."
                )

                analyze_big_pcap(
                    pcap_file,
                    report
                )

        else:

            report.write(
                "\nNo PCAP files are bigger than "
                f"{SIZE_LIMIT_MB} MB.\n"
            )

    # --------------------------------------------------------
    # REPORT SAVED
    # --------------------------------------------------------

    print("\n" + "=" * 80)

    print(
        "Analysis output saved to:"
    )

    print(
        report_path
    )

    print("=" * 80)

    # --------------------------------------------------------
    # ASK WHETHER TO SPLIT BIG FILES
    # --------------------------------------------------------

    for pcap_file in big_files:

        filename = os.path.basename(
            pcap_file
        )

        answer = input(
            f"\nDo you want to break this big file "
            f"{filename} into equal parts? yes/no: "
        ).strip().lower()

        # ----------------------------------------------------
        # YES
        # ----------------------------------------------------

        if answer in ("yes", "y"):

            result = split_pcap(
                pcap_file
            )

            if result:

                parts_directory, parts = result

                zip_path = create_zip(
                    parts_directory,
                    pcap_file
                )

                print(
                    f"\nCreated {len(parts)} PCAP part(s):"
                )

                for part in parts:

                    print(
                        "  "
                        + os.path.basename(part)
                    )

                print(
                    "\nZIP file created:"
                )

                print(
                    zip_path
                )

        # ----------------------------------------------------
        # NO
        # ----------------------------------------------------

        elif answer in ("no", "n"):

            print(
                f"\nSkipping {filename}."
            )

        # ----------------------------------------------------
        # INVALID INPUT
        # ----------------------------------------------------

        else:

            print(
                "\nInvalid input. "
                f"Skipping {filename}."
            )

    print(
        "\nAll processing completed."
    )


# ============================================================
# START
# ============================================================

if __name__ == "__main__":
    main()
