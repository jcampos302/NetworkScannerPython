# Jorge Campos
# Network Scanner
# Scanner File
# 7/12/2022

# Credit for Starting Build to thePacketGeek
# https://thepacketgeek.com/scapy/building-network-tools/part-10/#sweep-and-scan

import random
from ipaddress import IPv4Network
# from typing import List
from scapy.sendrecv import sr
from scapy.all import ICMP, IP, sr1, TCP

# Define IP range to scan


def port_scan(host: str, port_range: str):

    ports = []
    if '-' in port_range:
        start_port, fin_port = port_range.split('-')
        for x in range(int(start_port), int(fin_port) + 1):
            ports.append(x)
    else:
        ports.append(port_range)

    # Send SYN with random Src Port for each Dst port
    for dst_port in ports:
        src_port = random.randint(1025, 65534)
        resp = sr1(
            IP(dst=host) / TCP(sport=src_port, dport=dst_port, flags="S"), timeout=1,
            verbose=0,
        )
        if resp is None:
            print(f"{host}:{dst_port} is filtered (silently dropped).")

        elif resp.haslayer(TCP):
            if resp.getlayer(TCP).flags == 0x12:
                send_rst = sr(
                    IP(dst=host) / TCP(sport=src_port, dport=dst_port, flags='R'),
                    timeout=1,
                    verbose=0,
                )
                print(f"{host}:{dst_port} is open.")

            elif resp.getlayer(TCP).flags == 0x14:
                print(f"{host}:{dst_port} is closed.")

        elif resp.haslayer(ICMP):
            if (
                    int(resp.getlayer(ICMP).type) == 3 and
                    int(resp.getlayer(ICMP).code) in (1, 2, 3, 9, 10, 13)
            ):
                print(f"{host}:{dst_port} is filtered (silently dropped).")


def scan(network:  str, ports: str):
    live_count = 0
    addresses = IPv4Network(network)
    port_range = ports

    # Send ICMP ping request, wait for answer
    for host in addresses:
#        if host in (addresses.network_address, addresses.broadcast_address):
            # Skip network and broadcast addresses
#            continue

        resp = sr1(IP(dst=str(host)) / ICMP(), timeout=2, verbose=0)

        if resp is None:
            print(f"{host} is down or not responding.")
        elif (
                int(resp.getlayer(ICMP).type) == 3 and
                int(resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]
        ):
            print(f"{host} is blocking ICMP.")
        else:
            port_scan(str(host), port_range)
            live_count += 1

    print(f"{live_count}/{addresses.num_addresses} hosts are online.")
