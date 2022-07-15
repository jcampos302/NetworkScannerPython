# Jorge Campos
# Network Scanner
# 7/12/2022

# Credit for Starting Build to thePacketGeek
# https://thepacketgeek.com/scapy/building-network-tools/part-10/#sweep-and-scan
# Credit to Tutorials Point
# https://www.tutorialspoint.com/python_penetration_testing/python_penetration_testing_network_scanner.htm#:~:text=Port%20scanning%20may%20be%20defined,hacker%20can%20use%20this%20technique.

# Imports
import random
from ipaddress import IPv4Network
import threading
from scapy.sendrecv import sr
from scapy.all import ICMP, IP, sr1, TCP
from queue import Queue


# Functions
def threader():
    while True:
        # Collect variables from
        worker = q.get()
        host, dst_port = worker.split(',')
        # Calls Port Scanning Function
        port_scan(host, int(dst_port))
        q.task_done()


def icmp_scan(network: str, ports: str):
    live_count = 0
    addresses = IPv4Network(network)

    # Gets IP address
    for host in addresses:
        if host in (addresses.network_address, addresses.broadcast_address):
            # Skip network and broadcast addresses
            continue

        # Sends ICMP packet and collects response
        resp = sr1(IP(dst=str(host)) / ICMP(), timeout=2, verbose=0)

        if resp is None:
            print(f"{host} is down or not responding.")
        elif (
                int(resp.getlayer(ICMP).type) == 3 and
                int(resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]
        ):
            print(f"{host} is blocking ICMP.")
        else:
            print(f"{host} is UP.")
            # Get ports to send to worker
            get_ports(str(host), ports)
            # Starts the threading
            for x in range(100):
                t = threading.Thread(target=threader)
                t.daemon = True
                t.start()
            live_count += 1

    print(f"{live_count}/{addresses.num_addresses} hosts are online.")


def port_scan(host, dst_port):
    # Randomize Source Port
    src_port = random.randint(1025, 65534)
    # Sends and receives TCP Packet for Port
    resp = sr1(
        IP(dst=host) / TCP(sport=src_port, dport=dst_port, flags="S"), timeout=1,
        verbose=0,
    )

    if resp is None:
        with print_lock:
            print(f"{host}:{dst_port} is filtered (silently dropped).")

    elif resp.haslayer(TCP):
        if resp.getlayer(TCP).flags == 0x12:
            send_rst = sr(
                IP(dst=host) / TCP(sport=src_port, dport=dst_port, flags='R'),
                timeout=1,
                verbose=0,
            )
            with print_lock:
                print(f"{host}:{dst_port} is open.")

        elif resp.getlayer(TCP).flags == 0x14:
            with print_lock:
                print(f"{host}:{dst_port} is closed.")

    elif resp.haslayer(ICMP):
        if (
                int(resp.getlayer(ICMP).type) == 3 and
                int(resp.getlayer(ICMP).code) in (1, 2, 3, 9, 10, 13)
        ):
            with print_lock:
                print(f"{host}:{dst_port} is filtered (silently dropped).")


def get_ports(host: str, port_range: str):
    # Create list of ports
    # Work in Progress Still
    ports = []
    if '-' in port_range:
        start_port, fin_port = port_range.split('-')
        for i in range(int(start_port), int(fin_port) + 1):
            ports.append(i)
    else:
        ports.append(port_range)

    # Send SYN with random Src Port for each Dst port
    for dst_port in ports:
        worker = str(host) + ',' + str(dst_port)
        q.put(worker)


def scan(network: str, ports: str):
    # Starts Program
    icmp_scan(network, ports)


# Main
print_lock = threading.Lock()
q = Queue()
