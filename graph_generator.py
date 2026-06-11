import json
import os
import collections
from pyvis.network import Network
import sqlite3

def detect_company(hostname):
    """Simple heuristic to detect the actual company from CDN/cloud URLs"""
    if not hostname or hostname == "Unknown": return "Unknown"
    
    known_domains = {
        'google': 'Google',
        'googleapis': 'Google',
        '1e100': 'Google',
        'amazonaws': 'Amazon AWS',
        'apple': 'Apple',
        'icloud': 'Apple',
        'microsoft': 'Microsoft',
        'windowsupdate': 'Microsoft',
        'fastly': 'Fastly CDN',
        'cloudflare': 'Cloudflare',
        'akamai': 'Akamai CDN',
        'facebook': 'Meta/Facebook',
        'netflix': 'Netflix'
    }
    
    host_lower = hostname.lower()
    for key, company in known_domains.items():
        if key in host_lower:
            return company
    return hostname

def generate_graph(db_path="sentinel.db", output_html="network_graph.html"):
    if not os.path.exists(db_path):
        print(f"Error: {db_path} not found. Please run packet_sniffer.py first.")
        return

    try:
        db_uri = f"file:{os.path.abspath(db_path)}?mode=ro"
        conn = sqlite3.connect(db_uri, uri=True, timeout=10)
        c = conn.cursor()
        c.execute("SELECT ip1, ip2, host1, host2, protocol, service, packets FROM connections")
        rows = c.fetchall()
        conn.close()
    except Exception as e:
        print(f"Database error: {e}")
        return

    if not rows:
        print("No connections found in database.")
        return

    # Map rows to dictionary
    connections = []
    for row in rows:
        connections.append({
            'ip1': row[0],
            'ip2': row[1],
            'host1': row[2],
            'host2': row[3],
            'protocol': row[4],
            'service': row[5],
            'packets': row[6]
        })

    # Identify the local machine IP
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

    # Load Threat Intel Cache
    intel_cache = {}
    if os.path.exists("intel.db"):
        try:
            intel_conn = sqlite3.connect("file:intel.db?mode=ro", uri=True)
            ic = intel_conn.cursor()
            ic.execute("SELECT ip, classification FROM threat_cache")
            for row in ic.fetchall():
                intel_cache[row[0]] = row[1]
            intel_conn.close()
        except Exception:
            pass

    # Node coloring logic
    def get_node_color(ip):
        classification = intel_cache.get(ip, "UNKNOWN")
        if classification == "CRITICAL": return "#FF0000" # Red
        elif classification == "HIGH": return "#FFA500" # Orange
        elif classification == "SUSPICIOUS": return "#FFFF00" # Yellow
        elif classification == "SAFE": return "#00FF00" # Green
        return "#97C2FC" # Default Blue

    node_packets = collections.defaultdict(int)
    edges = collections.defaultdict(int)

    for conn in connections:
        if conn['ip1'] == local_ip:
            remote_host = conn['host2']
            remote_ip = conn['ip2']
        else:
            remote_host = conn['host1']
            remote_ip = conn['ip1']
            
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
        
        # Save the remote IP so we can color the company node later if we want
        # For simplicity, we just color the target nodes based on Intel Cache
        
        edges[(local_hostname, comp_node)] += packets
        edges[(comp_node, svc_node)] += packets
        edges[(svc_node, proto_node)] += packets

    # Build the PyVis Network
    net = Network(height="800px", width="100%", bgcolor="#0e1117", font_color="white", directed=True)

    # Add Nodes
    for node, pkts in node_packets.items():
        # Size logic
        size = 10 + (pkts / 50)
        size = min(max(size, 10), 50)
        
        title = f"{node}\\nTotal Packets: {pkts}"
        
        if node == local_hostname:
            net.add_node(node, label="Local Machine", title=title, color="#FFD700", size=40)
        elif node.startswith("Company:"):
            # Try to find a matching IP for this company from connections to get intel color
            comp_name = node.split(":")[1]
            intel_color = "#97C2FC" # Default Blue
            for conn in connections:
                if detect_company(conn['host2']) == comp_name:
                    intel_color = get_node_color(conn['ip2'])
                    if intel_color != "#97C2FC": break # Prioritize critical colors
            
            net.add_node(node, label=comp_name, title=title, color=intel_color, size=size)
        elif node.startswith("Service:"):
            net.add_node(node, label=node.split(":")[1], title=title, color="#FFA07A", size=size, shape="diamond")
        elif node.startswith("Protocol:"):
            net.add_node(node, label=node.split(":")[1], title=title, color="#98FB98", size=size, shape="square")

    # Add Edges
    for (src, dst), weight in edges.items():
        net.add_edge(src, dst, value=weight, title=f"Packets: {weight}")

    # Physics options for better clustering
    net.set_options("""
    var options = {
      "physics": {
        "forceAtlas2Based": {
          "gravitationalConstant": -50,
          "centralGravity": 0.01,
          "springLength": 100,
          "springConstant": 0.08
        },
        "minVelocity": 0.75,
        "solver": "forceAtlas2Based"
      }
    }
    """)

    net.save_graph(output_html)

if __name__ == "__main__":
    generate_graph()
