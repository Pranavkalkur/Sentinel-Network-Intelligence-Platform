import streamlit as st
import pandas as pd
import json
import os
import altair as alt
import requests
import pydeck as pdk
from streamlit_autorefresh import st_autorefresh

# Auto-refresh every 2 seconds
st_autorefresh(interval=2000, limit=None, key="data_refresh")

st.set_page_config(page_title="AI-Powered Network Intelligence", layout="wide")

# Sidebar
st.sidebar.title("📡 Visual Packet Explorer")
st.sidebar.markdown("AI-Powered Network Traffic Intelligence Platform")
st.sidebar.info("Continuous live monitoring with active threat scoring and Host Reputation analysis.")

KNOWN_SERVICES = {
    "googleusercontent.com": "Google",
    "1e100.net": "Google",
    "github.com": "GitHub",
    "cloudflare.com": "Cloudflare",
    "cloudflare.net": "Cloudflare",
    "fastly.net": "Fastly",
    "amazon.com": "Amazon",
    "aws.amazon.com": "Amazon",
    "apple.com": "Apple",
    "microsoft.com": "Microsoft",
}

def get_reputation(hostname):
    if not hostname or pd.isna(hostname):
        return "Unknown"
    hostname = str(hostname).lower()
    for suffix, name in KNOWN_SERVICES.items():
        if suffix in hostname:
            return name
    return "Unknown"

GEOIP_CACHE_FILE = "geoip_cache.json"

def load_geoip_cache():
    if os.path.exists(GEOIP_CACHE_FILE):
        try:
            with open(GEOIP_CACHE_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def save_geoip_cache(cache):
    try:
        with open(GEOIP_CACHE_FILE, "w") as f:
            json.dump(cache, f)
    except Exception:
        pass

def get_geoip_data(ips):
    cache = load_geoip_cache()
    
    external_ips = [ip for ip in ips if not (ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.") or ip.startswith("224.") or ip.startswith("127.") or ip.startswith("255."))]
    external_ips = list(set(external_ips))
    
    new_ips = [ip for ip in external_ips if ip not in cache]
    
    if new_ips:
        for i in range(0, len(new_ips), 100):
            batch = new_ips[i:i+100]
            try:
                # ip-api.com batch endpoint limit is 15 requests per minute
                response = requests.post("http://ip-api.com/batch", json=batch, timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    for item in data:
                        if item.get('status') == 'success':
                            cache[item['query']] = item
                        else:
                            cache[item['query']] = {} # Prevent constant retries for invalid IPs
                else:
                    # Rate limited or error, stop querying for now
                    break
            except Exception as e:
                break
        save_geoip_cache(cache)
        
    return cache

def analyze_threats(df_pkts):
    alerts = []
    score = 100
    
    if df_pkts.empty:
        return score, alerts

    df = df_pkts.copy()
    df['datetime'] = pd.to_datetime(df['time'], format='%H:%M:%S', errors='coerce')
    
    ip_counts = df['src'].value_counts()
    local_ip = ip_counts.idxmax() if not ip_counts.empty else None

    # 1. Port Scan Detection (>10 ports in 3s)
    for src, group in df.groupby('src'):
        group = group.sort_values('datetime').set_index('datetime')
        if len(group) > 10:
            resampled = group.resample('3s')['dport'].nunique()
            if (resampled > 10).any():
                max_ports = resampled.max()
                score -= 30
                alerts.append({
                    "severity": "High",
                    "type": "Port Scan Detected",
                    "target": src,
                    "confidence": "95%",
                    "evidence": f"Observed {int(max_ports)} unique destination ports targeted within a 3.0s window. Normal behavior rarely exceeds 5."
                })
                break

    # 2. Cleartext HTTP
    http_traffic = df[df['dport'] == 80]
    if not http_traffic.empty:
        unique_http_hosts = http_traffic['hostname'].dropna().unique()
        for host in unique_http_hosts[:3]:
            score -= 10
            alerts.append({
                "severity": "Medium",
                "type": "Cleartext HTTP",
                "target": host,
                "confidence": "100%",
                "evidence": "Packet captured transmitting on unencrypted port 80. Credentials and payloads are exposed."
            })

    # 3. Real Large Uploads (Outbound only)
    if local_ip:
        outbound = df[df['src'] == local_ip]
        upload_threshold = 500 * 1024 * 1024 # 500MB
        uploads = outbound.groupby('dst')['length'].sum()
        large_uploads = uploads[uploads > upload_threshold]
        for dst, size in large_uploads.items():
            score -= 20
            size_mb = size / (1024*1024)
            alerts.append({
                "severity": "High",
                "type": "Large Outbound Transfer",
                "target": dst,
                "confidence": "99%",
                "evidence": f"Confirmed continuous outbound transfer totaling {size_mb:.1f} MB. Potential data exfiltration."
            })

    # 4. Traffic Spike Detection (mean + 3*std)
    pps = df.groupby('time').size()
    if len(pps) > 2:
        avg_pps = pps.mean()
        std_pps = pps.std()
        threshold = max(avg_pps + 3 * std_pps, 20)
        spikes = pps[pps > threshold]
        for time_val, count in spikes.items():
            score -= 10
            alerts.append({
                "severity": "Medium",
                "type": "Traffic Spike",
                "target": str(time_val),
                "confidence": "85%",
                "evidence": f"Traffic volume reached {count} pps, violating the established baseline of {avg_pps:.1f} pps (+3 standard deviations)."
            })
            break

    # 5. DNS Tunneling (Hostname Length)
    dns_traffic = df[df['dport'] == 53]
    if not dns_traffic.empty and 'hostname' in dns_traffic.columns:
        long_domains = dns_traffic[dns_traffic['hostname'].astype(str).str.len() > 50]
        if not long_domains.empty:
            score -= 40
            suspicious_hosts = long_domains['hostname'].unique()
            host_disp = suspicious_hosts[0]
            if len(host_disp) > 30: host_disp = host_disp[:30] + "..."
            alerts.append({
                "severity": "High",
                "type": "Possible DNS Tunneling",
                "target": host_disp,
                "confidence": "90%",
                "evidence": f"Abnormally long DNS query detected ({len(suspicious_hosts[0])} chars). Malware often uses padded subdomains to exfiltrate data."
            })

    return max(0, score), alerts

def load_data():
    connections, packets = [], []
    if os.path.exists("connections.json"):
        with open("connections.json", "r") as f:
            try: connections = json.load(f)
            except Exception: pass
    if os.path.exists("packets.json"):
        with open("packets.json", "r") as f:
            try: packets = json.load(f)
            except Exception: pass
            
    df_conn = pd.DataFrame(connections)
    df_pkts = pd.DataFrame(packets)
    return df_conn, df_pkts

df_conn, df_pkts = load_data()

if df_conn.empty and df_pkts.empty:
    st.warning("Waiting for live packet capture... Run `sudo python3 packet_sniffer.py`")
    st.stop()

# Build Tabs
tabs = st.tabs([
    "Overview", 
    "Host Intelligence",
    "Endpoints (GeoIP)",
    "Timeline", 
    "Alerts", 
    "Analytics Insights",
    "Network Graph"
])

# 1. OVERVIEW
with tabs[0]:
    st.header("Live Traffic Overview")
    
    col1, col2, col3, col4 = st.columns(4)
    total_packets = df_pkts.shape[0] if not df_pkts.empty else (df_conn['packets'].sum() if not df_conn.empty else 0)
    unique_ips = df_conn['ip2'].nunique() if not df_conn.empty else 0
    top_protocol = df_pkts['protocol'].mode()[0] if not df_pkts.empty else "N/A"
    top_host = df_conn.groupby('host2')['packets'].sum().idxmax() if not df_conn.empty else "N/A"
    
    col1.metric("Total Packets", total_packets)
    col2.metric("Unique External IPs", unique_ips)
    col3.metric("Top Protocol", top_protocol)
    col4.metric("Top Talker", top_host)

    st.divider()
    colA, colB = st.columns(2)
    with colA:
        st.subheader("Protocol Distribution")
        if not df_pkts.empty:
            proto_counts = df_pkts['protocol'].value_counts().reset_index()
            proto_counts.columns = ['Protocol', 'Count']
            chart = alt.Chart(proto_counts).mark_arc().encode(
                theta="Count", color="Protocol", tooltip=["Protocol", "Count"]
            ).interactive()
            st.altair_chart(chart, use_container_width=True)
            
    with colB:
        st.subheader("Top Hosts (by Packet Count)")
        if not df_conn.empty:
            host_counts = df_conn.groupby('host2')['packets'].sum().reset_index()
            host_counts = host_counts.sort_values(by="packets", ascending=False).head(10)
            st.bar_chart(host_counts.set_index('host2'))

# 2. HOST INTELLIGENCE & REPUTATION
with tabs[1]:
    st.header("Host Intelligence & Reputation")
    if not df_conn.empty:
        geoip_map = get_geoip_data(df_conn['ip2'].tolist())
        
        df_rep = df_conn.copy()
        df_rep['DomainRep'] = df_rep['host2'].apply(get_reputation)
        df_rep['ISP'] = df_rep['ip2'].map(lambda ip: geoip_map.get(ip, {}).get('isp', 'Unknown'))
        
        def determine_rep(row):
            if row['DomainRep'] != 'Unknown': return row['DomainRep']
            if row['ISP'] != 'Unknown': return row['ISP']
            return 'Unknown'
            
        df_rep['FinalReputation'] = df_rep.apply(determine_rep, axis=1)
        
        known_pkts = df_rep[df_rep['FinalReputation'] != 'Unknown']['packets'].sum()
        total_pkts = df_rep['packets'].sum()
        known_pct = (known_pkts / total_pkts) * 100 if total_pkts > 0 else 0
        
        st.metric("Trusted/Known Traffic Volume", f"{known_pct:.1f}%")
        st.progress(known_pct / 100)
        
        st.subheader("Unknown / Unverified Hosts")
        unknowns = df_rep[df_rep['FinalReputation'] == 'Unknown']
        unknowns = unknowns[~unknowns['ip2'].str.startswith(('192.168.', '10.', '172.'))]
        if not unknowns.empty:
            st.dataframe(unknowns[['ip2', 'host2', 'packets', 'bytes']].sort_values(by="packets", ascending=False), use_container_width=True)
        else:
            st.success("All external traffic matches known benign hosts and ISPs.")

# 3. ENDPOINTS (GEOIP)
with tabs[2]:
    st.header("Global Endpoints (GeoIP Mapping)")
    
    if not df_conn.empty:
        df_ep = df_conn[['host2', 'ip2', 'packets', 'bytes']].copy()
        df_ep.rename(columns={'host2': 'Resolved Host', 'ip2': 'IP Address', 'packets': 'Packets', 'bytes': 'Bytes'}, inplace=True)
        df_ep = df_ep.groupby(['Resolved Host', 'IP Address']).sum().reset_index()
        
        # Batch GeoIP Lookup
        geoip_map = get_geoip_data(df_ep['IP Address'].tolist())
        df_ep['Country'] = df_ep['IP Address'].map(lambda ip: geoip_map.get(ip, {}).get('country', "Local/Unknown"))
        df_ep['ISP'] = df_ep['IP Address'].map(lambda ip: geoip_map.get(ip, {}).get('isp', "Unknown"))
        df_ep['Lat'] = df_ep['IP Address'].map(lambda ip: geoip_map.get(ip, {}).get('lat', None))
        df_ep['Lon'] = df_ep['IP Address'].map(lambda ip: geoip_map.get(ip, {}).get('lon', None))
        
        df_ep = df_ep.sort_values(by="Packets", ascending=False).reset_index(drop=True)
        st.dataframe(df_ep[['Resolved Host', 'IP Address', 'Country', 'ISP', 'Packets', 'Bytes']], use_container_width=True)
        
        map_data = df_ep.dropna(subset=['Lat', 'Lon'])
        if not map_data.empty:
            st.subheader("Global Traffic Map")
            layer = pdk.Layer(
                "ScatterplotLayer",
                map_data,
                get_position=["Lon", "Lat"],
                get_color="[200, 30, 0, 160]",
                get_radius="Packets * 5000",
                radius_min_pixels=5,
                radius_max_pixels=30,
                pickable=True
            )
            view_state = pdk.ViewState(latitude=20, longitude=0, zoom=1)
            st.pydeck_chart(pdk.Deck(
                map_style="mapbox://styles/mapbox/dark-v10",
                layers=[layer],
                initial_view_state=view_state,
                tooltip={"text": "{Resolved Host}\n{Country}\nISP: {ISP}\nPackets: {Packets}"}
            ))

# 4. TIMELINE
with tabs[3]:
    st.header("Live Traffic Timeline")
    if not df_pkts.empty and 'time' in df_pkts.columns:
        timeline_df = df_pkts.groupby('time').size().reset_index(name='Packets')
        st.line_chart(timeline_df.set_index('time'))

# 5. ALERTS
with tabs[4]:
    st.header("Threat Scoring & Explainable Alerts")
    score, alerts = analyze_threats(df_pkts)
    
    if score >= 90: status, color = "🟢 Safe", "green"
    elif score >= 70: status, color = "🟡 Monitor", "yellow"
    elif score >= 50: status, color = "🟠 Suspicious", "orange"
    else: status, color = "🔴 Critical", "red"

    st.markdown(f"### Safety Score: **{score}/100** ({status})")
    st.progress(score / 100)
    st.divider()
    
    if len(alerts) == 0:
        st.success("No threats detected. Network traffic appears normal.")
    else:
        st.warning(f"Detected {len(alerts)} security events!")
        for alert in alerts:
            if alert['severity'] == "High":
                st.error(f"**[{alert['severity']}] {alert['type']}**")
            elif alert['severity'] == "Medium":
                st.warning(f"**[{alert['severity']}] {alert['type']}**")
            else:
                st.info(f"**[{alert['severity']}] {alert['type']}**")
                
            st.markdown(f"> **Target/Source:** {alert['target']}  \n> **Confidence:** {alert.get('confidence', 'N/A')}  \n> **Evidence:** {alert['desc'] if 'evidence' not in alert else alert['evidence']}")
            st.write("---")

# 6. ANALYTICS INSIGHTS
with tabs[5]:
    st.header("Traffic Analytics Insights")
    
    if df_pkts.empty or df_conn.empty:
        st.info("Insufficient data for insights.")
    else:
        # 1. Top ISP/Company
        df_rep = df_conn.copy()
        df_rep['DomainRep'] = df_rep['host2'].apply(get_reputation)
        geoip_map = get_geoip_data(df_conn['ip2'].tolist())
        df_rep['ISP'] = df_rep['ip2'].map(lambda ip: geoip_map.get(ip, {}).get('isp', 'Unknown'))
        
        def det_rep(row):
            if row['DomainRep'] != 'Unknown': return row['DomainRep']
            if row['ISP'] != 'Unknown': return row['ISP']
            return 'Unknown'
        df_rep['FinalReputation'] = df_rep.apply(det_rep, axis=1)
        
        known_traffic = df_rep[df_rep['FinalReputation'] != 'Unknown']
        if not known_traffic.empty:
            top_company = known_traffic.groupby('FinalReputation')['packets'].sum().idxmax()
            top_company_pct = (known_traffic.groupby('FinalReputation')['packets'].sum().max() / df_conn['packets'].sum()) * 100
            st.markdown(f"✅ **{top_company_pct:.1f}%** of traffic was directed to **{top_company}** infrastructure.")
            
        # 2. Largest Communication
        largest_conn = df_conn.loc[df_conn['bytes'].idxmax()]
        largest_mb = largest_conn['bytes'] / (1024*1024)
        if largest_mb < 1:
            largest_str = f"{largest_conn['bytes']/1024:.1f} KB"
        else:
            largest_str = f"{largest_mb:.1f} MB"
        st.markdown(f"📦 **Largest communication:** `{largest_conn['host2']}` ({largest_str}).")
        
        # 3. Traffic Spikes
        pps = df_pkts.groupby('time').size()
        avg_pps = pps.mean()
        std_pps = pps.std()
        threshold = max(avg_pps + 3 * std_pps, 20)
        spikes = pps[pps > threshold]
        if not spikes.empty:
            st.markdown(f"📈 Observed **{len(spikes)} traffic spikes** exceeding baseline thresholds.")
        else:
            st.markdown(f"📉 Traffic volume remained stable. No significant spikes detected.")
            
        # 4. Port Scans / Security
        scan_alerts = [a for a in alerts if a['type'] == 'Port Scan Detected']
        if not scan_alerts:
            st.markdown(f"🛡️ No suspicious port scanning patterns detected.")
        else:
            st.markdown(f"⚠️ **Warning:** Port scanning behavior was detected from {len(scan_alerts)} unique sources.")

# 7. NETWORK GRAPH
with tabs[6]:
    st.header("Knowledge Graph")
    if os.path.exists("network_graph.html"):
        with open("network_graph.html", "r", encoding="utf-8") as f:
            html_data = f.read()
        st.components.v1.html(html_data, height=800, scrolling=True)
    else:
        st.info("Network graph not found.")
