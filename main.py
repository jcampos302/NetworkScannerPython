# Jorge Campos
# Network Scanner
# Main File
# 7/12/2022

# Imports
import argparse
import time

from scapy.layers.inet import ICMP

import scanner
import packet

# Constants
VERSION = 3.0


# Functions
def print_menu():
    print("===========================================")
    print("\t\t\tNetwork Scanner")
    print(f'\t\t\tVersion: {VERSION}')
    print("===========================================\n")


def start_program():
    print_menu()

    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', dest='target', help='Target IP Address(es)')
    parser.add_argument('-p', '--port', dest='port', default='1-1000', help='Specify Target Port(s)')
    options = parser.parse_args()

    if not options.target:
        options.target = input("Enter Network Address(es): ")
        options.port = input("Enter Target Port(s): ")
        if options.port == "":
            options.port = '1-1000'
        options.target = "10.120.20.0/24"
        options.port = '1-1000'
    return options


# Main
if __name__ == '__main__':
    start_time = time.time()
    # option = start_program()
    # scanner.scan(option.target, option.port)

    # resp = packet.icmp_packet("localhost")
    # print(resp)
    # resp = packet.arp_packet()
    # print(resp)
    resp = packet.tcp_packet("localhost", 445)
    print(resp)
    resp = packet.udp_packet("localhost", 53)
    print(resp)
    end_time = time.time()
    print(f'Total time is = {end_time-start_time}')
