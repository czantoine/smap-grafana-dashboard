#!/usr/bin/env python3
import sys
import os
import json
import sqlite3
from datetime import datetime, timezone
from typing import Optional, Generator

def ensure_schema(conn):
    c = conn.cursor()
    c.executescript("""
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY,
        scan_time TEXT,
        scanner_version TEXT,
        raw_file TEXT
    );

    CREATE TABLE IF NOT EXISTS hosts (
        id INTEGER PRIMARY KEY,
        scan_id INTEGER,
        ip TEXT,
        hostname TEXT,
        status TEXT,
        os TEXT,
        ttl INTEGER,
        raw TEXT,
        FOREIGN KEY (scan_id) REFERENCES scans(id)
    );

    CREATE TABLE IF NOT EXISTS ports (
        id INTEGER PRIMARY KEY,
        host_id INTEGER,
        port INTEGER,
        protocol TEXT,
        service TEXT,
        state TEXT,
        banner TEXT,
        cpe TEXT,
        raw TEXT,
        FOREIGN KEY (host_id) REFERENCES hosts(id)
    );

    CREATE TABLE IF NOT EXISTS vulnerabilities (
        id INTEGER PRIMARY KEY,
        scan_id INTEGER,
        host_id INTEGER,
        port_id INTEGER,
        cve TEXT,
        note TEXT,
        raw TEXT,
        FOREIGN KEY (scan_id) REFERENCES scans(id),
        FOREIGN KEY (host_id) REFERENCES hosts(id),
        FOREIGN KEY (port_id) REFERENCES ports(id)
    );

    CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip);
    CREATE INDEX IF NOT EXISTS idx_ports_host ON ports(host_id);
    CREATE INDEX IF NOT EXISTS idx_vuln_cve ON vulnerabilities(cve);
    CREATE INDEX IF NOT EXISTS idx_vuln_host ON vulnerabilities(host_id);
    """)
    conn.commit()

def find_latest_file(path: str) -> Optional[str]:
    """If path is a file -> return it. If path is a dir -> return newest file (by mtime)."""
    if os.path.isfile(path):
        return path
    if os.path.isdir(path):
        entries = [os.path.join(path, e) for e in os.listdir(path)]
        files = [p for p in entries if os.path.isfile(p)]
        if not files:
            return None
        files.sort(key=lambda p: os.path.getmtime(p), reverse=True)
        return files[0]
    return None

def detect_jsonl(path: str) -> bool:
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for _ in range(10):
            line = f.readline()
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                # if first non-empty line is a JSON object, treat as JSONL
                return True
            except json.JSONDecodeError:
                # maybe the file starts with '[' (JSON array)
                return False
    return False

def iter_records(path: str) -> Generator[dict, None, None]:
    is_jsonl = detect_jsonl(path)
    if is_jsonl:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                # if the line is a list (unlikely for JSONL), yield elements
                if isinstance(obj, list):
                    for el in obj:
                        yield el
                else:
                    yield obj
    else:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                return
            if isinstance(data, list):
                for obj in data:
                    yield obj
            elif isinstance(data, dict):
                # fallback heuristics
                if 'hosts' in data and isinstance(data['hosts'], list):
                    for obj in data['hosts']:
                        yield obj
                elif 'results' in data and isinstance(data['results'], list):
                    for obj in data['results']:
                        yield obj
                else:
                    yield data
            else:
                return

def normalize_and_insert(conn: sqlite3.Connection, scan_id: int, record):
    # handle if record is a list (defensive)
    if isinstance(record, list):
        for r in record:
            normalize_and_insert(conn, scan_id, r)
        return
    if not isinstance(record, dict):
        # nothing to do
        return

    c = conn.cursor()
    # defensive extraction
    ip = record.get('ip') or record.get('address') or record.get('target') or record.get('host')
    hostname = record.get('hostname') or record.get('hostnames')
    status = record.get('status') or record.get('state')
    os_info = record.get('os')
    ttl = record.get('ttl')
    raw_host = json.dumps(record, ensure_ascii=False)

    c.execute("""
        INSERT INTO hosts (scan_id, ip, hostname, status, os, ttl, raw)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (scan_id, ip, json.dumps(hostname) if hostname else None, status,
          json.dumps(os_info) if os_info else None, ttl, raw_host))
    host_id = c.lastrowid

    ports = []
    if 'ports' in record and isinstance(record['ports'], list):
        ports = record['ports']

    port_id_map = {}
    for p in ports:
        if isinstance(p, int):
            portnum = p
            proto = None
            service = None
            state = 'open'
            banner = None
            cpe = None
            raw_port = json.dumps(p)
        else:
            portnum = p.get('port') or p.get('portnumber') or p.get('port_id')
            proto = p.get('protocol') or p.get('proto')
            service = p.get('service') or p.get('name')
            state = p.get('state') or p.get('status') or 'open'
            banner = p.get('banner') or p.get('product') or p.get('version')
            cpe = json.dumps(p.get('cpes')) if p.get('cpes') else None
            raw_port = json.dumps(p, ensure_ascii=False)
        try:
            portnum_int = int(portnum) if portnum is not None else None
        except (TypeError, ValueError):
            portnum_int = None

        c.execute("""
            INSERT INTO ports (host_id, port, protocol, service, state, banner, cpe, raw)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (host_id, portnum_int, proto, service, state, banner, cpe, raw_port))
        port_id = c.lastrowid
        port_id_map[portnum_int] = port_id

    # host-level vulns
    vulns = record.get('vulns') or record.get('vulnerabilities') or []
    if isinstance(vulns, str):
        # if comma-separated string
        vulns = [v.strip() for v in vulns.split(',') if v.strip()]

    for cve in vulns:
        if not cve:
            continue
        # link to first port if available, else NULL
        port_id = next(iter(port_id_map.values()), None)
        c.execute("""
            INSERT INTO vulnerabilities (scan_id, host_id, port_id, cve, raw)
            VALUES (?, ?, ?, ?, ?)
        """, (scan_id, host_id, port_id, cve, json.dumps(cve)))

def import_smap(path: str, db_path: str):
    # resolve file (if path is dir choose newest file)
    file_path = find_latest_file(path)
    if not file_path:
        print(f"No file found at {path} (no action).")
        return 0

    # quick check: ensure file is not empty of records
    has_any = False
    for _ in iter_records(file_path):
        has_any = True
        break

    if not has_any:
        print(f"File {file_path} contains no records (no action).")
        return 0

    # connect DB and ensure schema
    conn = sqlite3.connect(db_path)
    ensure_schema(conn)

    # create scan entry only now that we know there's at least one record
    scan_time = datetime.now(timezone.utc).isoformat()
    scanner_version = None
    c = conn.cursor()
    c.execute("INSERT INTO scans (scan_time, scanner_version, raw_file) VALUES (?, ?, ?)",
              (scan_time, scanner_version, os.path.abspath(file_path)))
    scan_id = c.lastrowid
    conn.commit()

    count = 0
    try:
        with conn:
            for rec in iter_records(file_path):
                try:
                    normalize_and_insert(conn, scan_id, rec)
                    count += 1
                except Exception as e:
                    print("Warning: failed to import record:", e)
    finally:
        conn.close()

    print(f"Imported {count} records into DB {db_path} (scan_id={scan_id})")

    # delete source file only if at least one record imported
    if count > 0:
        try:
            os.remove(file_path)
            print(f"Deleted source file: {file_path}")
        except Exception as e:
            print(f"Warning: could not delete file {file_path}: {e}")
    else:
        print("No records imported; leaving source file in place for inspection.")

    return count

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: import_smap.py <smap-output.jsonl|json|scans_dir> <output.db>")
        sys.exit(1)
    input_path = sys.argv[1]
    db_path = sys.argv[2]
    # ensure folder for DB exists (when using Docker volume)
    db_dir = os.path.dirname(db_path)
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)
    result = import_smap(input_path, db_path)
    # exit code 0 even if nothing to do; non-zero only for errors
    sys.exit(0)
