#! /usr/bin/env python
import scapy.all as scapy
import optparse
def making_interace():
    parser = optparse.OptionParser()
    parser.add_option("--t","--target", dest="ip_address", help="Interface to get TARGET ip address")
    (options,arguments)=parser.parse_args()
    if not options.ip_address:
        parser.error("[-] Please enter the ip address or take the help of --help")
    return options.ip_address



def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list= scapy.srp(arp_request_broadcast,timeout=1,verbose=False)[0]
    target_list=[]
    for element in answered_list:
        ip_mac_info={"mac":"","ip":""}
        ip_mac_info["mac"]=element[1].hwsrc
        ip_mac_info["ip"]=element[1].psrc
        target_list.append(ip_mac_info)
    return target_list

def printing_scanned_result(target_list):
    print("IP\t\t\tMAC Adress\n---------------------------------")
    for each_ele in target_list:
        print(each_ele["ip"] + "\t\t" + each_ele["mac"])


scanning_ip=making_interace()
target_list=scan(scanning_ip)

printing_scanned_result(target_list)

