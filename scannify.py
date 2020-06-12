

import scapy.all as scapy
from termcolor import colored, cprint
import optparse

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", dest="target", help="usage: python scanner.py -t `IP`")
    options, arguments = parser.parse_args()
    return options


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    return(clients_list)

def print_result(results_list):
    print colored("\n[!]", 'yellow'), colored("For Help use -h")
    print colored("[!]", 'yellow'), colored("For OS detection use 'nmap -O 'target_ip'")
    cprint("\nIP\t\t\t\tMAC Adress\n-------------------------------------------------", "blue")
    for client in results_list:
        print colored("[+]", 'blue'), colored(client["ip"] + "\t\t" + client["mac"])


options = get_arguments()
scan_result = scan(options.target)
print_result(scan_result)
