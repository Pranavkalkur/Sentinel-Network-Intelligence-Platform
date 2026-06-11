#!/usr/bin/env python3
"""
Sentinel Enrichment Worker (Phase 5)
=====================================
This background daemon polls the local sentinel.db for new IP connections,
runs them through the Intelligence Engine (AbuseIPDB + Risk Scoring),
and caches the results in intel.db.
"""

import sqlite3
import time
import os
from datetime import datetime
from intelligence.abuseipdb import lookup_ip
from intelligence.scoring import calculate_risk

SENTINEL_DB = "sentinel.db"
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

def get_unique_ips_from_sentinel():
    if not os.path.exists(SENTINEL_DB):
        return set()
    try:
        db_uri = f"file:{os.path.abspath(SENTINEL_DB)}?mode=ro"
        conn = sqlite3.connect(db_uri, uri=True, timeout=10)
        c = conn.cursor()
        c.execute("SELECT DISTINCT ip1 FROM connections")
        ip1s = [row[0] for row in c.fetchall()]
        c.execute("SELECT DISTINCT ip2 FROM connections")
        ip2s = [row[0] for row in c.fetchall()]
        conn.close()
        return set(ip1s + ip2s)
    except Exception:
        return set()

def get_cached_ips():
    try:
        conn = sqlite3.connect(INTEL_DB)
        c = conn.cursor()
        c.execute("SELECT ip FROM threat_cache")
        ips = {row[0] for row in c.fetchall()}
        conn.close()
        return ips
    except Exception:
        return set()

def save_intel(ip, data, risk_score, classification):
    try:
        conn = sqlite3.connect(INTEL_DB, timeout=10)
        c = conn.cursor()
        c.execute('''
            INSERT OR REPLACE INTO threat_cache 
            (ip, risk_score, classification, country, isp, usage_type, abuse_score, last_checked)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            ip, 
            risk_score, 
            classification, 
            data.get('countryCode', 'Unknown'),
            data.get('isp', 'Unknown'),
            data.get('usageType', 'Unknown'),
            data.get('abuseConfidenceScore', 0),
            datetime.now().isoformat()
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[ERROR] Failed to save intel for {ip}: {e}")

def main():
    print("=" * 50)
    print("     SENTINEL BACKGROUND ENRICHMENT WORKER      ")
    print("=" * 50)
    init_intel_db()
    
    while True:
        try:
            active_ips = get_unique_ips_from_sentinel()
            cached_ips = get_cached_ips()
            
            # Find new IPs that haven't been checked yet
            new_ips = active_ips - cached_ips
            
            if new_ips:
                print(f"[INFO] Discovered {len(new_ips)} new IPs. Beginning enrichment...")
                
                # In a real environment, we'd batch this, but for Phase 5 we iterate
                for i, ip in enumerate(list(new_ips)[:50]): # Process max 50 per cycle to avoid huge bursts
                    # We skip local network IPs
                    if ip.startswith(("192.168.", "10.", "172.", "127.", "255.", "224.")):
                        save_intel(ip, {"countryCode": "Local", "isp": "LAN", "usageType": "Local", "abuseConfidenceScore": 0}, 0, "SAFE")
                        continue
                        
                    print(f"  -> [{i+1}] Analyzing {ip}...")
                    intel_data = lookup_ip(ip)
                    risk_score, classification = calculate_risk(intel_data, is_port_scanning=False) # In the future, read port scan flags from DB
                    save_intel(ip, intel_data, risk_score, classification)
                    
                    # Small sleep to prevent hitting API rate limits instantly
                    time.sleep(0.5)
                    
                print("[INFO] Enrichment cycle complete.")
                
        except Exception as e:
            print(f"[ERROR] Worker cycle failed: {e}")
            
        time.sleep(10) # Poll every 10 seconds

if __name__ == "__main__":
    main()
