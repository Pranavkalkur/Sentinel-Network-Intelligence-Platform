#!/usr/bin/env python3
import json
import os
import collections
from pyvis.network import Network

COMPANY_MAP = {
    "google": "Google",
    "1e100.net": "Google",
    "github": "GitHub",
    "cloudflare": "Cloudflare",
    "fastly": "Fastly",
    "amazon": "Amazon",
    "aws": "Amazon",
    "apple": "Apple",
    "microsoft": "Microsoft",
    "reddit": "Reddit",
    "gateway": "Local Router",
}

def detect_company(hostname):
    hostname_lower = hostname.lower()
    for key, company in COMPANY_MAP.items():
        if key in hostname_lower:
            return company
    return hostname

def generate_graph(json_file="connections.json", output_html="network_graph.html"):
    if not os.path.exists(json_file):
        print(f"Error: {json_file} not found. Please run packet_sniffer.py first.")
        return

    with open(json_file, 'r') as f:
        connections = json.load(f)

    if not connections:
        print("No connections found in JSON.")
        return

    # Identify the local machine IP by finding the most frequently occurring IP
    ip_counts = {}
    for conn in connections:
        ip_counts[conn['ip1']] = ip_counts.get(conn['ip1'], 0) + 1
        ip_counts[conn['ip2']] = ip_counts.get(conn['ip2'], 0) + 1

    local_ip = max(ip_counts, key=ip_counts.get)
    
    # Find local hostname from connections
    local_hostname = local_ip
    for conn in connections:
        if conn['ip1'] == local_ip:
            local_hostname = conn['host1']
            break
        elif conn['ip2'] == local_ip:
            local_hostname = conn['host2']
            break

    node_packets = collections.defaultdict(int)
    edges = collections.defaultdict(int)

    for conn in connections:
        if conn['ip1'] == local_ip:
            remote_host = conn['host2']
        else:
            remote_host = conn['host1']
            
        if local_hostname == remote_host:
            continue
            
        company = detect_company(remote_host)
        service = conn['service']
        protocol = conn['protocol']
        packets = conn['packets']
        
        comp_node = f"Company:{company}"
        svc_node = f"Service:{service}"
        proto_node = f"Protocol:{protocol}"
        
        node_packets[local_hostname] += packets
        node_packets[comp_node] += packets
        node_packets[svc_node] += packets
        node_packets[proto_node] += packets
        
        edges[(local_hostname, comp_node)] += packets
        edges[(comp_node, svc_node)] += packets
        edges[(svc_node, proto_node)] += packets

    # Initialize pyvis network
    net = Network(height="750px", width="100%", bgcolor="#222222", font_color="white", directed=True)
    
    # Add LOCAL node (Blue)
    net.add_node(local_hostname, label="Laptop\n" + local_hostname, color="#1e90ff", value=node_packets[local_hostname], title=f"LOCAL_MACHINE\nPackets: {node_packets[local_hostname]}")

    # Add other nodes (Company, Service, Protocol)
    for node, pkts in node_packets.items():
        if node == local_hostname:
            continue
        
        if node.startswith("Company:"):
            label = node.split(":", 1)[1]
            net.add_node(node, label=label, color="#32cd32", value=pkts, title=f"Company: {label}\nPackets: {pkts}")
        elif node.startswith("Service:"):
            label = node.split(":", 1)[1]
            net.add_node(node, label=label, color="#ffa500", value=pkts, title=f"Service: {label}\nPackets: {pkts}")
        elif node.startswith("Protocol:"):
            label = node.split(":", 1)[1]
            net.add_node(node, label=label, color="#ff4500", value=pkts, title=f"Protocol: {label}\nPackets: {pkts}")

    # Add Edges
    for (src, dst), pkts in edges.items():
        net.add_edge(src, dst, value=pkts, title=f"{pkts} packets")

    # Generate HTML
    net.show(output_html, notebook=False)
    print(f"[INFO] Advanced interactive network graph generated at: {output_html}")

if __name__ == "__main__":
    generate_graph()
