# Convert YOUR wireless adapter between managed and monitor mode.
#
# Managed  = normal Wi-Fi (connected to an AP, has an IP, ARP works).
# Monitor  = radio listen mode (the card is no longer a normal LAN client).
#
# This only changes the local adapter. It does not attack anyone.
# Wired / VMware virtual NICs usually cannot enter monitor mode.
#
# Run as root, for example:
#   sudo python network/03_convert_to_monitor_mode/monitor_mode.py -i wlan0 --monitor
#   sudo python network/03_convert_to_monitor_mode/monitor_mode.py -i wlan0 --managed

import argparse
import os
import re
import shutil
import subprocess
import sys

# Modern ifconfig: "eth0: flags=..."
# Older ifconfig:  "eth0      Link encap:Ethernet"
_IFACE_LINE = re.compile(r"^(\S+?)(?:\s*:|\s+Link\s)", re.IGNORECASE)


def run(cmd):
    # Same idea as mac_changer.py: call system tools with a list (not a shell string).
    print(" ".join(cmd))
    result = subprocess.run(cmd, check=False, capture_output=True, text=True)
    if result.stdout.strip():
        print(result.stdout.strip())
    if result.returncode != 0 and result.stderr.strip():
        print(result.stderr.strip())
    return result.returncode == 0


def is_wireless(iface):
    return os.path.isdir(os.path.join("/sys/class/net", iface, "wireless"))


def adapter_kind(iface):
    if is_wireless(iface):
        return "wifi"
    name = iface.lower()
    if name.startswith(("wlan", "wlp", "wifi")):
        return "wifi"
    return "lan"


def list_ifconfig_adapters():
    """
    Read local adapter names from ifconfig (same tool as mac_changer.py).
    Returns a list of {"name", "kind", "ip"} skipping loopback.
    """
    ifconfig = shutil.which("ifconfig")
    if not ifconfig:
        print("ifconfig not found. Install net-tools or pass -i <adapter>.")
        return []

    result = subprocess.run(
        [ifconfig, "-a"],
        check=False,
        capture_output=True,
        text=True,
    )
    text = result.stdout or result.stderr
    adapters = []
    current = None
    for raw in text.splitlines():
        match = _IFACE_LINE.match(raw)
        if match and not raw.startswith(" "):
            name = match.group(1).strip(":")
            if name == "lo" or name.startswith("lo:"):
                current = None
                continue
            current = {"name": name, "kind": adapter_kind(name), "ip": "-"}
            adapters.append(current)
            continue
        if current is None:
            continue
        inet = re.search(r"inet(?:\s+addr:)?\s+(\d+\.\d+\.\d+\.\d+)", raw)
        if inet and not inet.group(1).startswith("127."):
            current["ip"] = inet.group(1)
    return adapters


def show_adapter_menu(adapters, default_name=None):
    """Print:  1) eth0 lan (default)   2) wlan0 wifi"""
    if default_name is None:
        default_name = next(
            (a["name"] for a in adapters if a["kind"] == "lan" and a["ip"] != "-"),
            None,
        )
        if default_name is None and adapters:
            default_name = adapters[0]["name"]

    print("Adapters from ifconfig:\n")
    for index, adapter in enumerate(adapters, start=1):
        extra = " (default)" if adapter["name"] == default_name else ""
        ip = f"  {adapter['ip']}" if adapter["ip"] != "-" else ""
        print(f"{index}) {adapter['name']} {adapter['kind']}{extra}{ip}")
    return default_name


def current_mode(iface):
    iw = shutil.which("iw")
    if iw:
        result = subprocess.run(
            [iw, "dev", iface, "info"],
            check=False,
            capture_output=True,
            text=True,
        )
        for line in result.stdout.splitlines():
            if "type" in line.lower():
                return line.split()[-1].lower()
    iwconfig = shutil.which("iwconfig")
    if iwconfig:
        result = subprocess.run(
            [iwconfig, iface],
            check=False,
            capture_output=True,
            text=True,
        )
        text = (result.stdout + result.stderr).lower()
        if "mode:monitor" in text.replace(" ", ""):
            return "monitor"
        if "mode:managed" in text.replace(" ", "") or "mode:auto" in text.replace(" ", ""):
            return "managed"
    return "unknown"


def _set_type_iw(iface, mode):
    iw = shutil.which("iw")
    ip = shutil.which("ip")
    if not iw or not ip:
        return False
    ok = run([ip, "link", "set", iface, "down"])
    ok = run([iw, "dev", iface, "set", "type", mode]) and ok
    ok = run([ip, "link", "set", iface, "up"]) and ok
    return ok


def _set_type_iwconfig(iface, mode):
    iwconfig = shutil.which("iwconfig")
    ifconfig = shutil.which("ifconfig")
    if not iwconfig or not ifconfig:
        return False
    ok = run([ifconfig, iface, "down"])
    ok = run([iwconfig, iface, "mode", mode]) and ok
    ok = run([ifconfig, iface, "up"]) and ok
    return ok


def set_mode(iface, mode):
    """mode is 'monitor' or 'managed'. Returns True on success."""
    if mode not in {"monitor", "managed"}:
        print("mode must be monitor or managed")
        return False
    if not is_wireless(iface):
        print(
            f"{iface} is not a wireless adapter (no monitor mode). "
            "VMware/VirtualBox Ethernet NICs stay in normal/managed operation."
        )
        return False

    before = current_mode(iface)
    print(f"{iface} current mode: {before}")

    if _set_type_iw(iface, mode) or _set_type_iwconfig(iface, mode):
        after = current_mode(iface)
        print(f"{iface} new mode: {after}")
        return after == mode or after == "unknown"

    print("Could not change mode. Need root plus iw/ip or iwconfig/ifconfig.")
    return False


def set_monitor(iface):
    return set_mode(iface, "monitor")


def set_managed(iface):
    return set_mode(iface, "managed")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Put a local wireless adapter in monitor or managed mode (lab only)."
    )
    parser.add_argument("-i", "--interface", help="Wireless adapter, e.g. wlan0")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--monitor", action="store_true", help="Switch to monitor mode")
    group.add_argument("--managed", action="store_true", help="Switch back to managed mode")
    group.add_argument("--status", action="store_true", help="Print the current mode and exit")
    return parser.parse_args()


def pick_interface(preselected=None):
    adapters = list_ifconfig_adapters()
    if not adapters:
        return preselected

    default_name = show_adapter_menu(adapters)
    if preselected:
        names = {a["name"] for a in adapters}
        if preselected in names:
            print(f"Using adapter from -i: {preselected}")
            return preselected
        print(f"{preselected} was not in ifconfig; using it anyway.")
        return preselected

    raw = input("\nSelect adapter number or name (Enter = default, q = quit): ").strip()
    if raw.lower() in {"q", "quit", "exit"}:
        return None
    if not raw:
        return default_name
    if raw.isdigit():
        index = int(raw)
        if 1 <= index <= len(adapters):
            return adapters[index - 1]["name"]
        print(f"Pick a number between 1 and {len(adapters)}.")
        return pick_interface()
    return raw


def main():
    args = parse_args()
    iface = pick_interface(args.interface)
    if not iface:
        print("No adapter selected.")
        return 1

    if args.status or (not args.monitor and not args.managed):
        print(f"{iface} wireless={is_wireless(iface)} mode={current_mode(iface)}")
        if not args.monitor and not args.managed and not args.status:
            print("Pass --monitor or --managed to change mode.")
        return 0

    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("Run this script with sudo/root so the adapter mode can change.")
        return 1

    ok = set_monitor(iface) if args.monitor else set_managed(iface)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
