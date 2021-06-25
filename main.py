#!/usr/bin/env python

import scapy.all as scapy

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    boradcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_braodcast = boradcast/arp_request
    answered_list = scapy.srp(arp_request_braodcast, timeout=1, verbose=False)[0]
    client_list = []
    for element in answered_list:
        client_dist = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        client_list.append(client_dist)
        # print(element[1].psrc+ "\t\t" + element[1].hwsrc)
        # print("---------------------------------------------------")
    return client_list

def print_result(result_list):
    print("IP\t\t\tMAC Address\n---------------------------------------------------")

    for client in result_list:
        print(client["ip"] + "\t\t"+ client["mac"])



scan_result = scan("192.168.0.1/24")
print_result(scan_result)