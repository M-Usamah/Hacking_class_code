"""
ARP snooping / Dynamic ARP Inspection — classroom lab.

Discovery is not rewritten here. This lab imports scan() and show_result()
from network/02_network_discovery/network_scanner.py, then the student
picks one IP from that table and we watch ARP for it.

This does not forge ARP replies or change anyone's cache. Lab network only.
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone
from typing import Dict, Optional

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_DISCOVERY_DIR = os.path.abspath(os.path.join(_THIS_DIR, "..", "02_network_discovery"))
if _DISCOVERY_DIR not in sys.path:
    # 02_network_discovery is not a valid Python package name (starts with a digit),
    # so we add that folder to sys.path and import network_scanner as a module.
    sys.path.insert(0, _DISCOVERY_DIR)

try:
    from network_scanner import scan, show_result
except ImportError as err:
    print("Could not import network_scanner.py from network/02_network_discovery/")
    print(err)
    print("If Scapy is missing, from the repo root run:  pip install -r requirements.txt")
    sys.exit(1)

try:
    import scapy.all as scapy
except ImportError:
    print("Scapy is required. From the repo root run:  pip install -r requirements.txt")
    sys.exit(1)


ARP_OP = {1: "REQUEST", 2: "REPLY"}


def ask_for_target(hosts):
    """Student types a table number (1, 2, ...) or the IP itself."""
    while True:
        choice = input("\nEnter the number or IP to watch (or q to quit): ").strip()
        if choice.lower() in {"q", "quit", "exit"}:
            return None

        if choice.isdigit():
            index = int(choice)
            if 1 <= index <= len(hosts):
                return hosts[index - 1]
            print(f"Pick a number between 1 and {len(hosts)}.")
            continue

        for host in hosts:
            if host["ip"] == choice:
                return host
        print("That IP is not in the discovery table. Choose a listed host.")


class Binding:
    def __init__(self, ip, mac, source):
        now = datetime.now(timezone.utc)
        self.ip = ip
        self.mac = mac.lower()
        self.source = source
        self.first_seen = now
        self.last_seen = now
        self.seen = 1

    def touch(self):
        self.last_seen = datetime.now(timezone.utc)
        self.seen += 1


class ArpInspector:
    def __init__(self, watch_ip):
        self.watch_ip = watch_ip
        self.bindings: Dict[str, Binding] = {}
        self.alerts = 0
        self.packets = 0

    def seed(self, ip, mac, source="discovered"):
        self.bindings[ip] = Binding(ip, mac, source)

    def inspect_sender(self, ip, mac, op_name):
        mac = mac.lower()
        existing = self.bindings.get(ip)

        if existing is None:
            if ip == self.watch_ip:
                self.bindings[ip] = Binding(ip, mac, source="learned")
                return "LEARNED"
            return "OTHER"

        if existing.mac == mac:
            existing.touch()
            return "OK"

        self.alerts += 1
        print(
            "\n[ALERT] Binding conflict for the selected IP\n"
            f"        IP {ip} was {existing.mac} ({existing.source})\n"
            f"        this {op_name} claims sender MAC {mac}\n"
            "        In a switch DAI would drop this ARP and log it.\n"
        )
        return "CONFLICT"

    def table_text(self):
        if not self.bindings:
            return "(binding table is empty)"
        print_ip_mac = ["ip \t\t\t\t\t mac"]
        for ip in sorted(self.bindings):
            b = self.bindings[ip]
            print_ip_mac.append(f"{b.ip}\t\t\t\t{b.mac}")
        return "\n".join(print_ip_mac)


def handle_packet(pkt, inspector, verbose):
    if not pkt.haslayer(scapy.ARP):
        return

    arp = pkt[scapy.ARP]
    if inspector.watch_ip not in {arp.psrc, arp.pdst}:
        return

    inspector.packets += 1
    op_name = ARP_OP.get(int(arp.op), str(arp.op))
    status = inspector.inspect_sender(arp.psrc, arp.hwsrc, op_name)

    if verbose or status in {"CONFLICT", "LEARNED"}:
        ts = datetime.now().strftime("%H:%M:%S")
        print(
            f"[{ts}] ARP {op_name:<7} "
            f"sender {arp.psrc} ({arp.hwsrc}) -> target {arp.pdst} ({arp.hwdst})  [{status}]"
        )


def list_interfaces():
    print("Available interfaces (pass one to -i / --iface):\n")
    print(f"  default: {scapy.conf.iface}")
    for name in scapy.get_if_list():
        marker = "  (default)" if str(name) == str(scapy.conf.iface) else ""
        print(f"  {name}{marker}")


def parse_args(argv: Optional[list] = None):
    parser = argparse.ArgumentParser(
        description="Import network_scanner, pick an IP, then watch that IP's ARP binding (lab only)."
    )
    parser.add_argument(
        "-t",
        "--target",
        default="192.168.18.1/24",
        help="Subnet to discover (same default as network_scanner.py)",
    )
    parser.add_argument("-i", "--iface", help="Network interface")
    parser.add_argument(
        "--ip",
        dest="selected_ip",
        help="Skip the prompt and watch this IP (must answer the scan)",
    )
    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=0,
        help="Stop after N matching ARP packets (0 = until Ctrl+C)",
    )
    parser.add_argument("--list-ifaces", action="store_true", help="Print interface names and exit")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print every watched ARP packet")
    return parser.parse_args(argv)


def main(argv: Optional[list] = None) -> int:
    args = parse_args(argv)

    if args.list_ifaces:
        list_interfaces()
        return 0

    # Discovery uses the previous lab as a module (scan + show_result).
    if args.iface:
        scapy.conf.iface = args.iface

    print(f"Discovering hosts on {args.target} ...")
    hosts = scan(args.target)
    show_result(hosts, numbered=True)

    if not hosts:
        print("No replies. Check the subnet, interface, and that you may scan this lab network.")
        return 1

    if args.selected_ip:
        chosen = next((h for h in hosts if h["ip"] == args.selected_ip), None)
        if chosen is None:
            print(f"{args.selected_ip} did not answer the discovery scan.")
            return 1
    else:
        chosen = ask_for_target(hosts)
        if chosen is None:
            print("No host selected.")
            return 0

    print("\nip \t\t\t\t\t mac")
    print(f"{chosen['ip']}\t\t\t\t{chosen['mac']}")
    print(f"\nWatching ARP for {chosen['ip']} (expected MAC {chosen['mac']}).")
    print("Ctrl+C to stop.\n")

    inspector = ArpInspector(watch_ip=chosen["ip"])
    inspector.seed(chosen["ip"], chosen["mac"], source="discovered")

    sniff_kwargs = {
        "filter": f"arp and host {chosen['ip']}",
        "store": False,
        "prn": lambda pkt: handle_packet(pkt, inspector, args.verbose),
    }
    if args.iface:
        sniff_kwargs["iface"] = args.iface
    if args.count > 0:
        sniff_kwargs["count"] = args.count

    try:
        scapy.sniff(**sniff_kwargs)
    except PermissionError:
        print("Need administrator/root privileges to sniff ARP on this interface.")
        return 1
    except KeyboardInterrupt:
        print("\nStopped by user.")
    finally:
        print("\n=== Binding table ===")
        print(inspector.table_text())
        print(f"\nARP packets seen: {inspector.packets}")
        print(f"Conflicts flagged: {inspector.alerts}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
