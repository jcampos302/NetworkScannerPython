from scapy.all import Ether, ICMP, IP, sr1, TCP, UDP, ARP
from scapy.volatile import RandShort


def arp_packet():
    resp = sr1(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="192.168.1.0/24"), timeout=2)
    return resp


def icmp_packet(host):
    resp = sr1(IP(dst=str(host)) / ICMP(), timeout=2, verbose=0)
    return resp


def tcp_packet(host, dst_port):
    resp = sr1(
        IP(dst=host) / TCP(sport=RandShort(), dport=dst_port, flags="S"), timeout=1,
        verbose=0,
    )
    return resp


def udp_packet(host, dst_port):
    resp = sr1(IP(dst=host) / UDP(sport=RandShort(), dport=dst_port))
    return resp
