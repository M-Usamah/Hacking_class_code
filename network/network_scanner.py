# Scapy is a Python library used to create, send, capture, and inspect
# network packets (Ethernet, IP, ARP, TCP, and more).
import scapy.all as scapy


def scan(ip):
    # scapy.arping(ip)  # ready-made ARP ping; below we build the packet ourselves

    # --- ARP layer ---
    # ARP asks: "who has this IP? tell me your MAC".
    # ls() prints every field this packet type has, so you can see names like pdst.
    print("ARP")
    scapy.ls(scapy.ARP())

    # pdst = protocol destination = the IP / subnet we want to discover
    arp_request = scapy.ARP(pdst=ip)
    print(arp_request.summary())

    # --- Ethernet layer ---
    # Ethernet is the Layer-2 frame that carries ARP on a LAN.
    print("Ether")
    scapy.ls(scapy.Ether())

    # ff:ff:ff:ff:ff:ff is the broadcast MAC: every host on the LAN receives it
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    print(broadcast.summary())

    # / stacks two layers: Ethernet on the outside, ARP on the inside
    print("arp_request_broadcast")
    arp_request_broadcast = broadcast / arp_request
    print(arp_request_broadcast.summary())

    # srp() = send and receive at Layer 2.
    # It returns TWO lists (like two boxes of packets):
    #   answered   -> hosts that replied
    #   unanswered -> hosts that stayed silent
    # timeout=1 means wait 1 second for replies.
    print("Results")
    answered, unanswered = scapy.srp(arp_request_broadcast, timeout=1)

    # .summary() already prints; do not wrap it in print() or you will also see None
    print("Answered Result")
    answered.summary()
    print("Unanswered Result")
    unanswered.summary()
# "_______________________________________________________"
    # LIST: an ordered collection, written with square brackets [].
    # Example: ["a", "b"] or [{"ip": "...", "mac": "..."}, ...]
    # We start with an empty list and add one host at a time.
    ls = []

    # LOOP: "for item in collection" repeats the body once per item.
    # Each item in answered is a pair:
    #   elements[0] = the packet we sent
    #   elements[1] = the reply we got back
    for elements in answered:
        print("-----------------------------------------")
        print(elements)
        print("##########################################")
        # .show() prints the full packet; it returns None, so we call it without print()
        elements[1].show()
        print("*****************************************")
        print(elements[1].psrc)   # psrc  = IP of the device that answered
        print(elements[1].hwsrc)  # hwsrc = MAC of that device (hwdst would be OUR MAC)

        # DICTIONARY: a set of key → value pairs, written with curly braces {}.
        # Example: {"ip": "192.168.18.1", "mac": "aa:bb:cc:dd:ee:ff"}
        # Keys ("ip", "mac") let us look up values by name later.
        answered_dic = {"ip": elements[1].psrc, "mac": elements[1].hwsrc}

        # append() puts that dictionary at the end of the list
        ls.append(answered_dic)

    print("________________________")
    print(ls)
    return ls  # send the list back to the caller


def show_result(ls_of_results):
    # ls_of_results is the list of dictionaries returned by scan()
    print("ip \t\t\t\t\t mac")
    for ls in ls_of_results:  # loop over each dictionary in the list
        # ls['ip'] and ls['mac'] read values from the dictionary by key
        print(f"{ls['ip']}\t\t\t\t{ls['mac']}")


# What this script does, step by step:
# 1. Build a broadcast ARP request for every host in 192.168.18.1/24
# 2. Send it with srp() and collect replies
# 3. Store each live host as a dictionary {"ip": ..., "mac": ...} inside a list
# 4. Print that list as a simple IP / MAC table
scan_net = scan("192.168.18.1/24")
show_result(scan_net)