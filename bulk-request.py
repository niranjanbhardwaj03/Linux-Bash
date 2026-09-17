#!/usr/bin/env python3

import platform
import subprocess
import time
import requests


def get_target():
    target = input(
        "\nEnter target IP/Domain to send requests to: "
    ).strip()

    if not target:
        print("Target cannot be empty.")
        return None

    return target


def get_test_settings():
    try:
        count = int(input("Enter number of requests: "))
        delay = float(input("Enter delay between requests (seconds): "))

        if count < 1 or count > 100:
            print("Request count must be between 1 and 100.")
            return None

        if delay < 0.1:
            print("Delay must be at least 0.1 seconds.")
            return None

        return count, delay

    except ValueError:
        print("Invalid number.")
        return None


def http_test(target):
    # Add http:// if the user entered only a hostname/IP.
    if not target.startswith(("http://", "https://")):
        target = "http://" + target

    settings = get_test_settings()
    if not settings:
        return

    count, delay = settings

    print(f"\nTarget: {target}")
    print(f"Requests: {count}")
    print(f"Delay: {delay}s")
    print("-" * 50)

    for i in range(count):
        start = time.perf_counter()

        try:
            response = requests.get(target, timeout=5)

            elapsed = (time.perf_counter() - start) * 1000

            print(
                f"[{i + 1}/{count}] "
                f"HTTP {response.status_code} "
                f"- {elapsed:.1f} ms"
            )

        except requests.RequestException as e:
            print(f"[{i + 1}/{count}] ERROR: {e}")

        time.sleep(delay)


def icmp_test(target):
    settings = get_test_settings()
    if not settings:
        return

    count, delay = settings

    print(f"\nTarget: {target}")
    print(f"Requests: {count}")
    print(f"Delay: {delay}s")
    print("-" * 50)

    for i in range(count):

        if platform.system().lower() == "windows":
            command = ["ping", "-n", "1", target]
        else:
            command = ["ping", "-c", "1", "-W", "2", target]

        start = time.perf_counter()

        try:
            result = subprocess.run(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
            )

            elapsed = (time.perf_counter() - start) * 1000

            if result.returncode == 0:
                print(
                    f"[{i + 1}/{count}] "
                    f"ICMP OK - {elapsed:.1f} ms"
                )
            else:
                print(f"[{i + 1}/{count}] ICMP FAILED")

        except subprocess.TimeoutExpired:
            print(f"[{i + 1}/{count}] ICMP TIMEOUT")

        time.sleep(delay)


def arp_test(target):
    print(f"\nTarget: {target}")
    print("ARP/neighbour-table lookup")
    print("-" * 50)

    if platform.system().lower() == "windows":
        command = ["arp", "-a"]
    else:
        command = ["ip", "neigh"]

    try:
        subprocess.run(command)
    except Exception as e:
        print(f"ARP error: {e}")


def main():
    print("=" * 55)
    print("              NETWORK TEST TOOL")
    print("=" * 55)

    while True:

        print("\nWhich type of request do you want to send?")
        print()
        print("1. HTTP")
        print("2. ICMP")
        print("3. ARP")
        print("4. HTTP + ICMP")
        print("5. Exit")

        choice = input("\nEnter choice [1-5]: ").strip()

        if choice == "5":
            print("\nExiting...")
            break

        if choice not in {"1", "2", "3", "4"}:
            print("\nInvalid choice.")
            continue

        # Ask for target after selecting request type.
        target = get_target()

        if not target:
            continue

        if choice == "1":
            http_test(target)

        elif choice == "2":
            icmp_test(target)

        elif choice == "3":
            arp_test(target)

        elif choice == "4":
            print("\n--- HTTP TEST ---")
            http_test(target)

            print("\n--- ICMP TEST ---")
            icmp_test(target)

        print("\nTest completed.")


if __name__ == "__main__":
    main()
