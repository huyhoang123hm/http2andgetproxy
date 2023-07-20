#!/usr/bin/env python3

import socket
import psutil
import time
import subprocess
import re

def get_network_stats():
    # Get the network stats for the specified interface (e.g., eth0)
    net_interface = "eth0"  # Replace with your network interface
    net_stats = psutil.net_io_counters(pernic=True).get(net_interface)
    return net_stats

def get_mbps(stats):
    if stats is not None:
        # Calculate the network traffic in Mbps
        return (stats.bytes_sent + stats.bytes_recv) * 8 / 1000000
    return 0

def get_pps(stats):
    if stats is not None:
        # Calculate the packets per second
        return stats.packets_sent + stats.packets_recv
    return 0

def block_ip(ip):
    # Add an 'iptables' rule to block incoming traffic from the specified IP
    subprocess.run(f"sudo iptables -A INPUT -s {ip} -j DROP", shell=True)
    print(f"Blocked {ip} for suspicious traffic.")

def extract_ips_from_log(log_file_path):
    with open(log_file_path, "r") as log_file:
