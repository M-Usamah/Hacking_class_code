# Scapy is a Python library used to create, send, capture, and inspect
# network packets (Ethernet, IP, ARP, TCP, and more).
import argparse
import scapy.all as scapy


def list_interfaces():
    # Each item is {"name": iface, "ip": ipv4 or "-"}
    rows = []
    for name in scapy.get_if_list():
        try:
            addr = scapy.get_if_addr(name)
        except Exception:
            addr = "-"
        if not addr:
            addr = "-"
        rows.append({"name": str(name), "ip": addr})
    return rows


def show_interfaces(rows=None):
    if rows is None:
        rows = list_interfaces()
    print("No\tiface\t\t\t ip")
    for index, row in enumerate(rows, start=1):
        marker = "  (scapy default)" if str(row["name"]) == str(scapy.conf.iface) else ""
        print(f"{index}\t{row['name']}\t\t{row['ip']}{marker}")
    return rows


def local_cidr(iface):
    """Build a /24 from the adapter's IPv4, e.g. 192.168.18.44 -> 192.168.18.0/24."""
    try:
        addr = scapy.get_if_addr(iface)
    except Exception:
        return None
    if not addr or addr in {"0.0.0.0", "-"}:
        return None
    parts = addr.split(".")
    if len(parts) != 4:
        return None
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"


def scan(ip, iface=None, verbose=False, timeout=3):
    # scapy.arping(ip)  # ready-made ARP ping; below we build the packet ourselves

    if iface:
        scapy.conf.iface = iface

    # --- ARP layer ---
    # ARP asks: "who has this IP? tell me your MAC".
    if verbose:
        print("ARP")
        scapy.ls(scapy.ARP())

    # pdst = protocol destination = the IP / subnet we want to discover
    arp_request = scapy.ARP(pdst=ip)
    if verbose:
        print(arp_request.summary())

    # --- Ethernet layer ---
    # Ethernet is the Layer-2 frame that carries ARP on a LAN.
    if verbose:
        print("Ether")
        scapy.ls(scapy.Ether())

    # ff:ff:ff:ff:ff:ff is the broadcast MAC: every host on the LAN receives it
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    if verbose:
        print(broadcast.summary())

    # / stacks two layers: Ethernet on the outside, ARP on the inside
    arp_request_broadcast = broadcast / arp_request
    if verbose:
        print("arp_request_broadcast")
        print(arp_request_broadcast.summary())
        print("Results")

    # srp() = send and receive at Layer 2.
    # timeout must be long enough for a /24 (256 probes). timeout=1 is too short.
    srp_kwargs = {"timeout": timeout, "retry": 1, "verbose": False}
    if iface:
        srp_kwargs["iface"] = iface
    answered, unanswered = scapy.srp(arp_request_broadcast, **srp_kwargs)

    if verbose:
        print("Answered Result")
        answered.summary()
        print(f"Unanswered: {len(unanswered)} (not listing every probe)")

    # LIST: an ordered collection, written with square brackets [].
    # Example: ["a", "b"] or [{"ip": "...", "mac": "..."}, ...]
    ls = []

    # Each item in answered is a pair:
    #   elements[0] = the packet we sent
    #   elements[1] = the reply we got back
    for elements in answered:
        if verbose:
            print("-----------------------------------------")
            print(elements)
            print("##########################################")
            elements[1].show()
            print("*****************************************")
            print(elements[1].psrc)   # psrc  = IP of the device that answered
            print(elements[1].hwsrc)  # hwsrc = MAC of that device

        answered_dic = {"ip": elements[1].psrc, "mac": elements[1].hwsrc}
        ls.append(answered_dic)

    if verbose:
        print("________________________")
        print(ls)
    return ls  # send the list back to the caller


def show_result(ls_of_results, numbered=False):
    # ls_of_results is the list of dictionaries returned by scan()
    if numbered:
        print("No\tip \t\t\t\t\t mac")
        if not ls_of_results:
            print("(no hosts answered)")
            return
        for index, ls in enumerate(ls_of_results, start=1):
            print(f"{index}\t{ls['ip']}\t\t\t\t{ls['mac']}")
        return

    print("ip \t\t\t\t\t mac")
    for ls in ls_of_results:  # loop over each dictionary in the list
        print(f"{ls['ip']}\t\t\t\t{ls['mac']}")


# What this script does, step by step:
# 1. Pick the NIC that actually has the lab IP (not VPN / another adapter)
# 2. Scan that NIC's /24 with a longer timeout
# 3. Print a simple IP / MAC table
#
# The if __name__ == "__main__" guard means:
#   python network_scanner.py  -> runs the scan below
#   import network_scanner     -> only loads the functions, no auto-scan
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ARP network discovery lab.")
    parser.add_argument("-i", "--iface", help="Interface to send ARP on")
    parser.add_argument("-t", "--target", help="CIDR to scan, e.g. 192.168.18.0/24")
    parser.add_argument(
        "--lesson",
        action="store_true",
        help="Print extra Scapy field dumps (the original teaching output)",
    )
    args = parser.parse_args()

    print("Interfaces:")
    show_interfaces()

    iface = args.iface or str(scapy.conf.iface)
    target = args.target or local_cidr(iface) or "192.168.18.0/24"
    print(f"\nScanning {target} on {iface} ...")
    scan_net = scan(target, iface=iface, verbose=args.lesson)
    show_result(scan_net, numbered=True)
