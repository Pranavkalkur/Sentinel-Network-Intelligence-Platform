#!/usr/bin/env python3
"""
Visual Packet Explorer - Phase 1
================================
A beginner-friendly packet sniffer using Scapy.
This script captures live IP network packets on your machine and extracts:
- Source IP Address
- Destination IP Address
- Protocol (TCP, UDP, ICMP)
- Source & Destination Ports (for TCP/UDP)

How it works:
1. It listens to your network interface.
2. For each packet received, it checks if there is an Internet Protocol (IP) layer.
3. If an IP layer is present, it extracts the source/destination IPs and the sub-protocol.
4. If the packet is TCP/UDP, it extracts the source and destination ports.
5. It prints this information clearly to the console.
"""

import sys
import socket
import json
from datetime import datetime
import database

packets_buffer = []
total_packets_count = 0
total_bytes_count = 0
protocol_count = {
    "TCP": 0,
    "UDP": 0,
    "ICMP": 0
}
ip_count = {}
destination_count = {}
conversation_count = {}
connections_table = {}

# Try to import Scapy's sniffing function and IP, TCP, and UDP layer classes.
# If Scapy is not installed, print a friendly error message and exit.
try:
    from scapy.all import sniff, IP, TCP, UDP
except ImportError:
    print("Error: Scapy is not installed. Please install it using 'pip install scapy'.")
    sys.exit(1)

# Protocol mapping dictionary.
# Under the hood, the IP header defines the next-layer protocol using numbers:
# - Protocol 1 is ICMP (Internet Control Message Protocol) - used by 'ping'
# - Protocol 6 is TCP (Transmission Control Protocol) - used by web browsers (HTTP/HTTPS)
# - Protocol 17 is UDP (User Datagram Protocol) - used by DNS, streaming, gaming
# This dictionary helps map those numbers to human-readable text.
PROTOCOL_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP"
}
COMMON_PORTS = {
    80: "HTTP",
    443: "HTTPS",
    53: "DNS",
    22: "SSH",
    25: "SMTP",
    110: "POP3",
    143: "IMAP"
}

def process_packet(packet):
    """
    Callback function that is executed automatically for every packet captured.
    
    Parameters:
        packet (scapy.packet.Packet): The captured packet object.
    """
    # 1. Check if the packet has an IP layer (Layer 3).
    # Since we are interested in IP addresses, we only process packets that contain IP data.
    if packet.haslayer(IP):
        # 2. Extract the IP layer object from the packet.
        ip_layer = packet[IP]
        
        # 3. Extract the Source IP address.
        # This is the address of the device that sent the packet.
        src_ip = ip_layer.src
        
        # 4. Extract the Destination IP address.
        # This is the address of the device receiving the packet.
        dst_ip = ip_layer.dst
        
        # 5. Extract the protocol number (e.g., 6 for TCP, 17 for UDP, 1 for ICMP).
        proto_num = ip_layer.proto
        
        # 6. Translate the protocol number to a user-friendly name.
        # If it is not in our dictionary (like protocol 2 or 50), we show "Other" with the number.
        protocol_name = PROTOCOL_MAP.get(proto_num, f"Other ({proto_num})")
        
        # 7. Extract Source and Destination Port information for Layer 4 protocols (TCP/UDP)
        src_port = None
        dst_port = None
        
        if packet.haslayer(TCP):
            # TCP has source and destination ports
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            # UDP has source and destination ports
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        
        # 8. Store packet information
        packet_info = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "src": src_ip,
            "dst": dst_ip,
            "protocol": protocol_name,
            "length": len(packet),
            "sport": src_port,
            "dport": dst_port,
            "hostname": dst_ip
        }
        
        global total_packets_count, total_bytes_count
        total_packets_count += 1
        total_bytes_count += len(packet)
        packets_buffer.append(packet_info)
        
        # 9. Count Protocols
        if protocol_name in protocol_count:
            protocol_count[protocol_name] += 1
        else:
            protocol_count[protocol_name] = protocol_count.get(protocol_name, 0) + 1
            
        # 10. Detect Most Active IP
        ip_count[src_ip] = ip_count.get(src_ip, 0) + 1
        
        # 11. Track Destinations
        destination_count[dst_ip] = destination_count.get(dst_ip, 0) + 1
        
        # 12. Track Conversations
        conversation = tuple(sorted([src_ip, dst_ip]))
        conversation_count[conversation] = conversation_count.get(conversation, 0) + 1
        
        # 13. Service Detection
        service = "Unknown"
        if dst_port in COMMON_PORTS:
            service = COMMON_PORTS[dst_port]
        elif src_port in COMMON_PORTS:
            service = COMMON_PORTS[src_port]
        
        # 14. Group Connections
        ip1, ip2 = sorted([src_ip, dst_ip])
        conn_key = (ip1, ip2, protocol_name, service)
        
        if conn_key not in connections_table:
            connections_table[conn_key] = {"packets": 0, "bytes": 0}
            
        connections_table[conn_key]["packets"] += 1
        connections_table[conn_key]["bytes"] += len(packet)
        
        # 15. Show live progress
        sys.stdout.write(f"\r[INFO] Captured {total_packets_count} packets...")
        sys.stdout.flush()
        
        # 16. Periodically flush to SQLite for real-time dashboard
        if len(packets_buffer) >= 25:
            try:
                database.insert_packets(packets_buffer)
                database.upsert_connections(connections_table)
                packets_buffer.clear()
            except Exception as e:
                pass

def print_report():
    print() # Move to a clean line
    print("\n" + "="*50)
    print("                 FINAL REPORT                 ")
    print("="*50)
    
    print("\n[INFO] Resolving hostnames, please wait...")
    unique_ips = set()
    for ip1, ip2, _, _ in connections_table.keys():
        unique_ips.add(ip1)
        unique_ips.add(ip2)
        
    resolved_hostnames = {}
    for ip in unique_ips:
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror):
            hostname = ip
        resolved_hostnames[ip] = hostname
        
    # Add hostnames to packet storage for Phase 3 (if any are left in buffer)
    for p in packets_buffer:
        p['hostname'] = resolved_hostnames.get(p['dst'], p['dst'])
    
    # Flush remaining buffer
    if packets_buffer:
        try:
            database.insert_packets(packets_buffer)
            database.upsert_connections(connections_table)
            packets_buffer.clear()
        except Exception as e:
            print(f"Warning: Could not flush final packets: {e}")
        
    print(f"\nTotal Packets: {total_packets_count}")
    
    if total_packets_count > 0:
        avg_size = total_bytes_count / total_packets_count
        
        print(f"Total Bytes  : {total_bytes_count}")
        print(f"Average Size : {avg_size:.2f} bytes")
        
        print("\nProtocol Counts:")
        print("TCP :", protocol_count.get("TCP", 0))
        print("UDP :", protocol_count.get("UDP", 0))
        print("ICMP:", protocol_count.get("ICMP", 0))
        
        print("\nConnection Summary")
        print("==================")
        sorted_connections = sorted(
            connections_table.items(), 
            key=lambda item: item[1]["packets"], 
            reverse=True
        )
        
        for (ip1, ip2, proto, svc), stats in sorted_connections[:10]:
            host1 = resolved_hostnames.get(ip1, ip1)
            host2 = resolved_hostnames.get(ip2, ip2)
            
            print(f"\n{host1} ↔ {host2}")
            print(f"Protocol: {proto}")
            print(f"Service: {svc}")
            print(f"Packets: {stats['packets']}")
            print(f"Bytes: {stats['bytes']} bytes")
            
    print("\n[INFO] Saving final connections to database...")
    try:
        database.upsert_connections(connections_table)
    except Exception as e:
        print(f"Warning: Could not save final connections: {e}")
            
    print("\n[INFO] Stopping packet capture. Goodbye!")

def main():
    print("=" * 50)
    print("            VISUAL PACKET EXPLORER - PHASE 1            ")
    print("=" * 50)
    print("Starting continuous live packet sniffing...")
    print("Capturing indefinitely. Press Ctrl+C to stop.")
    print("Make sure you are running this with sudo / root privileges.")
    print("-" * 50)
    
    try:
        # Start sniffing packets!
        # - store: Set to 0 (False) so Scapy doesn't keep massive packet objects in memory.
        database.init_db()
        sniff(prn=process_packet, store=0, filter="ip", count=0)
        print_report()
    except PermissionError:
        print("\n[ERROR] Permission Denied!")
        print("Packet sniffing requires root/administrative privileges.")
        print("Please run the script using sudo:")
        print("  sudo python3 packet_sniffer.py")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nCtrl+C detected")
        print_report()
        sys.exit(0)

if __name__ == "__main__":
    main()
