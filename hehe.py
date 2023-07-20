#!/usr/bin/env python3

import subprocess
import time

block_threshold_connections = 50    # Set the threshold for blocking an IP based on connections (adjust as needed)
block_threshold_packets = 500       # Set the threshold for blocking an IP based on packets (adjust as needed)
block_duration = 3600               # Set the duration (in seconds) to block an IP (1 hour in this example)
blocked_ips_connections = {}        # Dictionary to store blocked IP addresses based on connections and timestamps
blocked_ips_packets = {}            # Dictionary to store blocked IP addresses based on packets and timestamps

def get_ssh_connections_count():
    # Get the number of SSH connections per IP address
    ssh_connections = subprocess.run("sudo netstat -tnp | grep ':22' | awk '{print $5}' | cut -d: -f1 | sort | uniq -c", shell=True, capture_output=True, text=True)
    ssh_connections = ssh_connections.stdout.strip().splitlines()
    connections = {}
    for conn in ssh_connections:
        count, ip = conn.split()
        connections[ip] = int(count)
    return connections

def get_ssh_packet_count():
    # Get the number of SSH packets per IP address
    ssh_packets = subprocess.run("sudo tcpdump -n -i eth0 -s 0 -c 1000 port 22 2>/dev/null | awk '{print $3}' | cut -d. -f1-4 | sort | uniq -c", shell=True, capture_output=True, text=True)
    ssh_packets = ssh_packets.stdout.strip().splitlines()
    packets = {}
    for pkt in ssh_packets:
        count, ip = pkt.split()
        packets[ip] = int(count)
    return packets

def block_ip(ip):
    # Add an 'iptables' rule to block incoming traffic from the specified IP
    subprocess.run(f"sudo iptables -A INPUT -s {ip} -j DROP", shell=True)
    print(f"Blocked {ip} for excessive SSH connections and/or packets.")

def unblock_ip(ip):
    # Remove the 'iptables' rule to unblock the IP
    subprocess.run(f"sudo iptables -D INPUT -s {ip} -j DROP", shell=True)
    print(f"Unblocked {ip} after {block_duration} seconds.")

def detect_excessive_ssh_connections_and_packets():
    while True:
        connections = get_ssh_connections_count()
        for ip, count in connections.items():
            if count > block_threshold_connections and ip not in blocked_ips_connections:
                block_ip(ip)
                blocked_ips_connections[ip] = time.time()

        packets = get_ssh_packet_count()
        for ip, count in packets.items():
            if count > block_threshold_packets and ip not in blocked_ips_packets:
                block_ip(ip)
                blocked_ips_packets[ip] = time.time()

        # Check if it's time to unblock IPs based on connections
        current_time = time.time()
        for ip, timestamp in list(blocked_ips_connections.items()):
            if current_time - timestamp >= block_duration:
                unblock_ip(ip)
                del blocked_ips_connections[ip]

        # Check if it's time to unblock IPs based on packets
        for ip, timestamp in list(blocked_ips_packets.items()):
            if current_time - timestamp >= block_duration:
                unblock_ip(ip)
                del blocked_ips_packets[ip]

        time.sleep(1)  # Wait for 1 second before checking again

if __name__ == "__main__":
    detect_excessive_ssh_connections_and_packets()
