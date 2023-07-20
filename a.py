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
    # Calculate the network traffic in Mbps
    return (stats.bytes_sent + stats.bytes_recv) * 8 / 1000000

def get_pps(stats):
    # Calculate the packets per second
    return stats.packets_sent + stats.packets_recv

def block_ip(ip):
    # Add an 'iptables' rule to block incoming traffic from the specified IP
    subprocess.run(f"sudo iptables -A INPUT -s {ip} -j DROP", shell=True)
    print(f"Blocked {ip} for suspicious traffic.")

def extract_ips_from_log(log_file_path):
    ips = set()

    with open(log_file_path, "r") as log_file:
        for line in log_file:
            line_ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
            ips.update(line_ips)

    return ips

def detect_ddos(mbps_threshold, pps_threshold):
    log_file_path = "/var/log/auth.log"  # Replace with the path to your log file
    while True:
        net_stats = get_network_stats()
        mbps = get_mbps(net_stats)
        pps = get_pps(net_stats)

        print(f"Mbps: {mbps:.2f} | PPS: {pps}")

        if mbps > mbps_threshold or pps > pps_threshold:
            print("DDoS detected!")
            ips = extract_ips_from_log(log_file_path)

            # Block all suspicious IPs
            for ip in ips:
                block_ip(ip)

        time.sleep(1)  # Wait for 1 second before checking again

if __name__ == "__main__":
    mbps_threshold = 100  # Set the Mbps threshold for DDoS detection
    pps_threshold = 1000  # Set the pps threshold for DDoS detection

    detect_ddos(mbps_threshold, pps_threshold)
