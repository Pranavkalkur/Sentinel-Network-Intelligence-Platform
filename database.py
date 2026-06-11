import sqlite3
import os

DB_PATH = "sentinel.db"

def init_db():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    c = conn.cursor()
    c.execute("PRAGMA journal_mode=WAL;")
    
    # Create packets table
    c.execute('''
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            time TEXT,
            src TEXT,
            dst TEXT,
            protocol TEXT,
            length INTEGER,
            sport INTEGER,
            dport INTEGER,
            hostname TEXT
        )
    ''')
    
    # Create connections table
    c.execute('''
        CREATE TABLE IF NOT EXISTS connections (
            ip1 TEXT,
            ip2 TEXT,
            host1 TEXT,
            host2 TEXT,
            protocol TEXT,
            service TEXT,
            packets INTEGER,
            bytes INTEGER,
            PRIMARY KEY (ip1, ip2, protocol, service)
        )
    ''')
    
    conn.commit()
    conn.close()

def insert_packets(packets):
    if not packets: return
    conn = sqlite3.connect(DB_PATH, timeout=15)
    c = conn.cursor()
    
    values = [(p.get('time'), p.get('src'), p.get('dst'), p.get('protocol'), 
               p.get('length'), p.get('sport'), p.get('dport'), p.get('hostname')) for p in packets]
    
    c.executemany('''
        INSERT INTO packets (time, src, dst, protocol, length, sport, dport, hostname)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', values)
    conn.commit()
    conn.close()

def upsert_connections(connections_table):
    if not connections_table: return
    conn = sqlite3.connect(DB_PATH, timeout=15)
    c = conn.cursor()
    
    values = []
    # connections_table: {(ip1, ip2, protocol, service): {"packets": count, "bytes": bytes}}
    for (i1, i2, p, s), stats in connections_table.items():
        # Hostnames can be resolved later, we store IP for now
        values.append((i1, i2, i1, i2, p, s, stats["packets"], stats["bytes"]))
        
    c.executemany('''
        INSERT INTO connections (ip1, ip2, host1, host2, protocol, service, packets, bytes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(ip1, ip2, protocol, service) DO UPDATE SET
            packets = excluded.packets,
            bytes = excluded.bytes
    ''', values)
    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
