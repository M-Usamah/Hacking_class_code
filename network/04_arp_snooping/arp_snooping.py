"""
ARP snooping lab — classroom interactive shell.

If the student forgets -i, ifconfig is used to list adapters:

  1) eth0 lan (default)
  2) wlan0 wifi

After an adapter is chosen it is put in monitor mode (wifi only).
Then the student types net.show to list hosts (02_network_discovery),
then a number or IP to start ARP inspection.

This does not forge ARP replies. Lab network only.
"""

from __future__ import annotations

import argparse
import atexit
import os
import sys
from datetime import datetime, timezone
from typing import Dict, Optional

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_NETWORK_DIR = os.path.abspath(os.path.join(_THIS_DIR, ".."))
for _lab in ("02_network_discovery", "03_convert_to_monitor_mode"):
    _path = os.path.join(_NETWORK_DIR, _lab)
    if _path not in sys.path:
        sys.path.insert(0, _path)

try:
    from network_scanner import local_cidr, scan, show_result
except ImportError as err:
    print("Could not import network_scanner.py from network/02_network_discovery/")
    print(err)
    print("If Scapy is missing, from the repo root run:  pip install -r requirements.txt")
    sys.exit(1)

try:
    from monitor_mode import (
        current_mode,
        is_wireless,
        pick_interface,
        set_managed,
        set_monitor,
    )
except ImportError as err:
    print("Could not import monitor_mode.py from network/03_convert_to_monitor_mode/")
    print(err)
    sys.exit(1)

try:
    import scapy.all as scapy
except ImportError:
    print("Scapy is required. From the repo root run:  pip install -r requirements.txt")
    sys.exit(1)


ARP_OP = {1: "REQUEST", 2: "REPLY"}


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


class AdapterSession:
    """Put a wireless NIC in monitor mode, always try to restore managed on exit."""

    def __init__(self, iface):
        self.iface = iface
        self.wireless = is_wireless(iface)
        self.original_mode = current_mode(iface) if self.wireless else "managed"
        self.changed = False

    def restore(self):
        if not self.changed:
            return
        print(f"\nRestoring {self.iface} to managed mode ...")
        set_managed(self.iface)
        self.changed = False

    def enable_monitor(self):
        if not self.wireless:
            print(
                f"{self.iface} is not wireless; skipping monitor mode "
                "(typical for VMware/VirtualBox Ethernet)."
            )
            return False
        print(f"Switching {self.iface} to monitor mode (was {self.original_mode}) ...")
        ok = set_monitor(self.iface)
        self.changed = True
        if not ok:
            print("Monitor mode failed; continuing in the current mode.")
        return ok

    def ensure_managed_for_scan(self):
        if not self.wireless:
            return
        mode = current_mode(self.iface)
        if mode == "monitor":
            print("Temporarily switching to managed so net.show / ARP discovery can work ...")
            set_managed(self.iface)
            self.changed = True


def print_help():
    print(
        "\nCommands:\n"
        "  net.show     list devices on the network (uses network discovery)\n"
        "  <number>     start ARP snooping on that row from net.show\n"
        "  <ip>         start ARP snooping on that IP from net.show\n"
        "  help         show this list\n"
        "  exit         restore managed mode and quit\n"
    )


def resolve_host(hosts, choice):
    if choice.isdigit():
        index = int(choice)
        if 1 <= index <= len(hosts):
            return hosts[index - 1]
        print(f"Pick a number between 1 and {len(hosts)} (run net.show first).")
        return False
    for host in hosts:
        if host["ip"] == choice:
            return host
    print("That IP is not in the last net.show table. Run net.show again.")
    return False


def interactive_shell(session, iface, target, verbose, lesson):
    hosts = []
    print_help()
    print(f"Adapter {iface} is ready. Type net.show then pick an IP.")

    while True:
        try:
            raw = input("arp> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return None

        if not raw:
            continue

        cmd = raw.lower()
        if cmd in {"exit", "quit", "q"}:
            return None
        if cmd in {"help", "?"}:
            print_help()
            continue
        if cmd in {"net.show", "net show", "netshow"}:
            session.ensure_managed_for_scan()
            scapy.conf.iface = iface
            cidr = target or local_cidr(iface) or "192.168.18.0/24"
            print(f"\nnet.show  ({cidr} on {iface})")
            hosts = scan(cidr, iface=iface, verbose=lesson)
            show_result(hosts, numbered=True)
            if not hosts:
                print("No replies. Pick the adapter that has the lab IP, then run net.show again.")
            session.enable_monitor()
            continue

        if not hosts:
            print("Run net.show first so you have a device list.")
            continue

        chosen = resolve_host(hosts, raw)
        if chosen:
            return chosen


def watch_host(session, iface, chosen, verbose, packet_count):
    print("\nip \t\t\t\t\t mac")
    print(f"{chosen['ip']}\t\t\t\t{chosen['mac']}")
    session.enable_monitor()
    print(f"\nARP snooping on {chosen['ip']} (expected MAC {chosen['mac']}).")
    print("Ctrl+C to stop (adapter returns to managed mode).\n")

    inspector = ArpInspector(watch_ip=chosen["ip"])
    inspector.seed(chosen["ip"], chosen["mac"], source="discovered")

    sniff_kwargs = {
        "filter": "arp",
        "store": False,
        "prn": lambda pkt: handle_packet(pkt, inspector, verbose),
        "iface": iface,
    }
    if packet_count > 0:
        sniff_kwargs["count"] = packet_count

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


def parse_args(argv: Optional[list] = None):
    parser = argparse.ArgumentParser(
        description="ifconfig adapter menu, net.show, then ARP snooping on the selected IP."
    )
    parser.add_argument(
        "-i",
        "--iface",
        "--interface",
        dest="iface",
        help="Adapter name from ifconfig (if omitted, the script asks)",
    )
    parser.add_argument("-t", "--target", help="Subnet for net.show, e.g. 192.168.18.0/24")
    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=0,
        help="Stop snooping after N ARP packets (0 = until Ctrl+C)",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Print every watched ARP packet")
    parser.add_argument("--lesson", action="store_true", help="Extra Scapy dumps during net.show")
    return parser.parse_args(argv)


def main(argv: Optional[list] = None) -> int:
    args = parse_args(argv)

    iface = pick_interface(args.iface)
    if not iface:
        print("No adapter selected.")
        return 0

    session = AdapterSession(iface)
    atexit.register(session.restore)

    try:
        session.enable_monitor()
        chosen = interactive_shell(session, iface, args.target, args.verbose, args.lesson)
        if chosen is None:
            print("No host selected.")
            return 0
        return watch_host(session, iface, chosen, args.verbose, args.count)
    finally:
        session.restore()


if __name__ == "__main__":
    sys.exit(main())
