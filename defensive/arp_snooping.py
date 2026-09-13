"""
ARP snooping / Dynamic ARP Inspection (DAI) — defensive classroom lab.

What this program does
----------------------
Switches that support ARP snooping (often paired with DHCP snooping) watch
ARP traffic and keep an IP-to-MAC binding table. Dynamic ARP Inspection then
compares each ARP packet to that table. A mismatch is treated as suspicious
because it may be an ARP cache-poisoning attempt.

This script is a software version of that idea for teaching:

1. Optionally load a trusted binding file (the lab stand-in for DHCP snooping).
2. Passively sniff ARP packets on one interface (it does not inject frames).
3. Record sender IP/MAC pairs in a binding table.
4. Raise an alert when an IP is claimed by a MAC that is not the trusted one.

What this program does not do
-----------------------------
It does not forge ARP replies, change anyone's ARP cache, intercept traffic,
or poison DNS. Those are attacks. This lab only inspects and reports.

Classroom setup
---------------
- Run only on a network you are authorized to monitor (your VM lab is ideal).
- Windows: install Npcap, then run the terminal as Administrator.
- Linux/macOS: run with sufficient privileges to sniff (often sudo).
- Install:  pip install -r requirements.txt
- List NICs: python defensive/arp_snooping.py --list-ifaces
- Example:  python defensive/arp_snooping.py -i eth0 --trusted defensive/trusted_bindings.txt --learn

Related lab in this repo
------------------------
network/network_scanner.py *sends* ARP requests to discover hosts.
This file *listens* to ARP and validates bindings. Same protocol, opposite role.
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone
from typing import Dict, Optional

try:
    from scapy.all import ARP, conf, get_if_list, sniff
except ImportError:
    print("Scapy is required. From the repo root run:  pip install -r requirements.txt")
    sys.exit(1)


ARP_OP = {1: "REQUEST", 2: "REPLY"}


class Binding:
    """One IP -> MAC mapping learned from a trusted file or from live ARP."""

    def __init__(self, ip: str, mac: str, source: str) -> None:
        now = datetime.now(timezone.utc)
        self.ip = ip
        self.mac = mac.lower()
        self.source = source  # "trusted" or "learned"
        self.first_seen = now
        self.last_seen = now
        self.seen = 1

    def touch(self) -> None:
        self.last_seen = datetime.now(timezone.utc)
        self.seen += 1


class ArpInspector:
    """Maintains the binding table and checks each ARP sender claim."""

    def __init__(self, learn: bool) -> None:
        self.learn = learn
        self.bindings: Dict[str, Binding] = {}
        self.alerts = 0
        self.packets = 0

    def load_trusted_file(self, path: str) -> int:
        loaded = 0
        with open(path, encoding="utf-8") as handle:
            for line_no, raw in enumerate(handle, start=1):
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) != 2:
                    print(f"[warn] skip trusted_bindings line {line_no}: expected 'IP MAC'")
                    continue
                ip, mac = parts
                self.bindings[ip] = Binding(ip, mac, source="trusted")
                loaded += 1
        return loaded

    def inspect_sender(self, ip: str, mac: str, op_name: str) -> str:
        """
        Compare the ARP sender (psrc, hwsrc) with the table.

        Returns a short status used in the log line.
        """
        mac = mac.lower()
        existing = self.bindings.get(ip)

        if existing is None:
            if self.learn:
                self.bindings[ip] = Binding(ip, mac, source="learned")
                return "LEARNED"
            return "UNBOUND"

        if existing.mac == mac:
            existing.touch()
            return "OK"

        self.alerts += 1
        print(
            "\n[ALERT] Possible ARP spoofing / poisoning\n"
            f"        IP {ip} is bound to {existing.mac} ({existing.source})\n"
            f"        but this {op_name} claims sender MAC {mac}\n"
            "        Action in a real switch: drop the ARP packet, log, optionally shut the port.\n"
        )
        return "CONFLICT"

    def table_text(self) -> str:
        if not self.bindings:
            return "(binding table is empty)"
        header = f"{'IP':<16} {'MAC':<18} {'SOURCE':<8} {'SEEN':<6} LAST_SEEN_UTC"
        lines = [header, "-" * len(header)]
        for ip in sorted(self.bindings):
            b = self.bindings[ip]
            last = b.last_seen.strftime("%Y-%m-%d %H:%M:%S")
            lines.append(f"{b.ip:<16} {b.mac:<18} {b.source:<8} {b.seen:<6} {last}")
        return "\n".join(lines)


def handle_packet(pkt, inspector: ArpInspector, verbose: bool) -> None:
    if not pkt.haslayer(ARP):
        return

    arp = pkt[ARP]
    inspector.packets += 1
    op_name = ARP_OP.get(int(arp.op), str(arp.op))

    # Sender protocol/hardware addresses: "I am IP psrc at MAC hwsrc".
    # DAI cares most about this claim, because that is what other hosts cache.
    status = inspector.inspect_sender(arp.psrc, arp.hwsrc, op_name)

    if verbose or status in {"CONFLICT", "LEARNED", "UNBOUND"}:
        ts = datetime.now().strftime("%H:%M:%S")
        print(
            f"[{ts}] ARP {op_name:<7} "
            f"sender {arp.psrc} ({arp.hwsrc}) -> target {arp.pdst} ({arp.hwdst})  [{status}]"
        )


def list_interfaces() -> None:
    print("Available interfaces (pass one to -i / --iface):\n")
    print(f"  default: {conf.iface}")
    for name in get_if_list():
        marker = "  (default)" if str(name) == str(conf.iface) else ""
        print(f"  {name}{marker}")


def parse_args(argv: Optional[list] = None) -> argparse.Namespace:
    here = os.path.dirname(os.path.abspath(__file__))
    default_trusted = os.path.join(here, "trusted_bindings.txt")

    parser = argparse.ArgumentParser(
        description="Defensive ARP snooping / Dynamic ARP Inspection lab (passive monitor only)."
    )
    parser.add_argument("-i", "--iface", help="Network interface to sniff")
    parser.add_argument(
        "--trusted",
        default=default_trusted,
        help="File of trusted IP MAC pairs (default: defensive/trusted_bindings.txt)",
    )
    parser.add_argument(
        "--learn",
        action="store_true",
        help="Sticky-learn: the first MAC seen for an unbound IP becomes the binding",
    )
    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=0,
        help="Stop after N ARP packets (0 = until Ctrl+C)",
    )
    parser.add_argument(
        "--list-ifaces",
        action="store_true",
        help="Print interface names and exit",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Print every ARP packet, not only new/unbound/conflict events",
    )
    return parser.parse_args(argv)


def main(argv: Optional[list] = None) -> int:
    args = parse_args(argv)

    if args.list_ifaces:
        list_interfaces()
        return 0

    inspector = ArpInspector(learn=args.learn)

    if os.path.isfile(args.trusted):
        n = inspector.load_trusted_file(args.trusted)
        print(f"Loaded {n} trusted binding(s) from {args.trusted}")
    else:
        print(f"No trusted file at {args.trusted} (continuing with an empty table)")

    if not inspector.bindings and not args.learn:
        print("Hint: add IP/MAC rows to the trusted file, or pass --learn for sticky lab mode.")

    print("Listening for ARP (passive). Ctrl+C to stop and print the binding table.\n")
    print("Seed table:")
    print(inspector.table_text())
    print()

    sniff_kwargs = {
        "filter": "arp",
        "store": False,
        "prn": lambda pkt: handle_packet(pkt, inspector, args.verbose),
    }
    if args.iface:
        sniff_kwargs["iface"] = args.iface
    if args.count > 0:
        sniff_kwargs["count"] = args.count

    try:
        sniff(**sniff_kwargs)
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
