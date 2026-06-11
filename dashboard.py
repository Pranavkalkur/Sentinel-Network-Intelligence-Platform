import streamlit as st
import pandas as pd
import json
import os
import sqlite3
import altair as alt
import requests
import pydeck as pdk
from streamlit_autorefresh import st_autorefresh
from graph_generator import generate_graph

st.set_page_config(page_title="AI-Powered Network Intelligence", layout="wide")

# Auto-refresh every 2 seconds
st_autorefresh(interval=2000, limit=None, key="data_refresh")

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

INTEL_DB = "intel.db"

def init_intel_db():
    conn = sqlite3.connect(INTEL_DB)
    c = conn.cursor()
    c.execute("PRAGMA journal_mode=WAL;")
    c.execute('''
        CREATE TABLE IF NOT EXISTS threat_cache(
            ip TEXT PRIMARY KEY,
            risk_score INTEGER,
            classification TEXT,
            country TEXT,
            isp TEXT,
            usage_type TEXT,
            abuse_score INTEGER,
            last_checked TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def load_intel_cache():
    if not os.path.exists(INTEL_DB):
        init_intel_db()
    try:
        conn = sqlite3.connect(INTEL_DB)
        df = pd.read_sql_query("SELECT * FROM threat_cache", conn)
        conn.close()
        
        cache = {}
        for _, row in df.iterrows():
            cache[row['ip']] = {
                'country': row['country'],
                'isp': row['isp'],
                'lat': None, # We don't really need lat/lon for the basic map anymore, but we can simulate it if needed, or remove arc map reliance on precise lat/lon
                'lon': None,
                'risk_score': row['risk_score'],
                'classification': row['classification'],
                'abuse_score': row['abuse_score']
            }
        return cache, df
    except Exception:
        return {}, pd.DataFrame()

def get_intel_data(ips):
    cache, _ = load_intel_cache()
    # The background worker handles all new IP lookups now! We never call APIs from Streamlit anymore.
    return cache

@st.cache_data(ttl=86400)
def get_local_coords():
    try:
        response = requests.get("http://ip-api.com/json/", timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                return data.get('lat'), data.get('lon')
    except Exception:
        pass
    return None, None

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
    db_path = "sentinel.db"
    if not os.path.exists(db_path):
        return pd.DataFrame(), pd.DataFrame()
        
    try:
        # Open the DB in read-only mode so the normal user can read a root-owned file
        db_uri = f"file:{os.path.abspath(db_path)}?mode=ro"
        conn = sqlite3.connect(db_uri, uri=True, timeout=10)
        
        # Limit to the most recent 5,000 packets to prevent Streamlit from crashing/OOMing
        df_pkts = pd.read_sql_query("SELECT * FROM packets ORDER BY id DESC LIMIT 5000", conn)
        df_conn = pd.read_sql_query("SELECT * FROM connections", conn)
        conn.close()
        return df_conn, df_pkts
    except Exception as e:
        return pd.DataFrame(), pd.DataFrame()

df_conn, df_pkts = load_data()

if df_conn.empty and df_pkts.empty:
    st.warning("Waiting for live packet capture... Run `sudo python3 packet_sniffer.py`")
    st.stop()

# Build Tabs
tabs = st.tabs([
    "Overview", 
    "Threat Intelligence",
    "Endpoints",
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

# 2. THREAT INTELLIGENCE (NEW PHASE 5)
with tabs[1]:
    st.header("Active Threat Intelligence")
    st.markdown("Automated enrichment via background AbuseIPDB worker.")
    
    _, intel_df = load_intel_cache()
    if not intel_df.empty:
        # Metrics
        col1, col2, col3 = st.columns(3)
        total_intel = len(intel_df)
        critical = len(intel_df[intel_df['classification'] == 'CRITICAL'])
        high = len(intel_df[intel_df['classification'] == 'HIGH'])
        
        col1.metric("Enriched IPs", total_intel)
        col2.metric("Critical Threats", critical, delta_color="inverse")
        col3.metric("High Risk", high, delta_color="inverse")
        
        st.divider()
        st.subheader("Threat Cache Database")
        
        # Color formatting
        def color_risk(val):
            if val == 'CRITICAL': return 'color: red; font-weight: bold'
            elif val == 'HIGH': return 'color: orange; font-weight: bold'
            elif val == 'SUSPICIOUS': return 'color: yellow'
            return 'color: green'
            
        display_df = intel_df[['ip', 'country', 'isp', 'usage_type', 'abuse_score', 'risk_score', 'classification']].sort_values(by="risk_score", ascending=False)
        st.dataframe(display_df.style.map(color_risk, subset=['classification']), use_container_width=True, height=400)
    else:
        st.info("Threat Cache is empty. Make sure `enrichment_worker.py` is running in the background.")

# 3. ENDPOINTS
with tabs[2]:
    st.header("Global Endpoints")
    st.markdown("Note: Map coordinates are disabled in Phase 5 to prioritize Intelligence scoring.")
    
    if not df_conn.empty:
        df_ep = df_conn[['host2', 'ip2', 'packets', 'bytes']].copy()
        df_ep.rename(columns={'host2': 'Resolved Host', 'ip2': 'IP Address', 'packets': 'Packets', 'bytes': 'Bytes'}, inplace=True)
        df_ep = df_ep.groupby(['Resolved Host', 'IP Address']).sum().reset_index()
        
        intel_map = get_intel_data(df_ep['IP Address'].tolist())
        df_ep['Country'] = df_ep['IP Address'].map(lambda ip: intel_map.get(ip, {}).get('country', "Local/Unknown"))
        df_ep['ISP'] = df_ep['IP Address'].map(lambda ip: intel_map.get(ip, {}).get('isp', "Unknown"))
        df_ep['Risk'] = df_ep['IP Address'].map(lambda ip: intel_map.get(ip, {}).get('classification', "UNKNOWN"))
        
        df_ep = df_ep.sort_values(by="Packets", ascending=False).reset_index(drop=True)
        st.dataframe(df_ep[['Resolved Host', 'IP Address', 'Country', 'ISP', 'Risk', 'Packets', 'Bytes']], use_container_width=True)

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
    st.markdown("Visualize the relationships between your local machine, external domains, services, and protocols.")
    
    if st.button("🔄 Generate/Refresh Knowledge Graph"):
        with st.spinner("Querying SQLite and building graph..."):
            generate_graph(db_path="sentinel.db", output_html="network_graph.html")
            st.success("Graph updated!")
            
    if os.path.exists("network_graph.html"):
        with open("network_graph.html", "r", encoding="utf-8") as f:
            html_data = f.read()
        st.components.v1.html(html_data, height=800, scrolling=True)
    else:
        st.info("Click the button above to generate the network graph.")
