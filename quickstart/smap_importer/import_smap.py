#!/usr/bin/env python3
"""
import_smap.py - Import smap/nmap output (JSON, JSONL, XML) into SQLite.

Handles all smap output formats:
  - nmap XML (-oX)
  - nmap JSON (-oJ) including wrapper formats
  - Shodan JSON/JSONL
  - Plain JSON arrays/objects

Usage:
    python3 import_smap.py <scan_file_or_dir> <database.db> [--verify] [--debug]
"""
import sys
import os
import json
import sqlite3
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Optional, Generator


DEBUG = "--debug" in sys.argv


def dbg(msg: str):
    if DEBUG:
        print(f"  [debug] {msg}")


# ---------------------------------------------------------------------------
# CVSS
# ---------------------------------------------------------------------------
def score_to_severity(score):
    if score is None:
        return "UNKNOWN"
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "UNKNOWN"
    if s >= 9.0: return "CRITICAL"
    if s >= 7.0: return "HIGH"
    if s >= 4.0: return "MEDIUM"
    if s >= 0.1: return "LOW"
    return "NONE"


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------
def ensure_schema(conn: sqlite3.Connection):
    conn.executescript("""
        PRAGMA journal_mode = WAL;
        PRAGMA foreign_keys = ON;

        CREATE TABLE IF NOT EXISTS scans (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_time       TEXT    NOT NULL,
            scanner_version TEXT,
            raw_file        TEXT,
            total_hosts     INTEGER DEFAULT 0,
            total_ports     INTEGER DEFAULT 0,
            total_vulns     INTEGER DEFAULT 0,
            notes           TEXT
        );
        CREATE TABLE IF NOT EXISTS hosts (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id      INTEGER NOT NULL REFERENCES scans(id),
            ip           TEXT,
            hostname     TEXT,
            status       TEXT    DEFAULT 'up',
            os           TEXT,
            ttl          INTEGER,
            country      TEXT,
            country_code TEXT,
            city         TEXT,
            latitude     REAL,
            longitude    REAL,
            org          TEXT,
            asn          TEXT,
            isp          TEXT,
            vuln_count   INTEGER DEFAULT 0,
            max_cvss     REAL    DEFAULT 0.0,
            risk_level   TEXT    DEFAULT 'NONE',
            raw          TEXT
        );
        CREATE TABLE IF NOT EXISTS ports (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id           INTEGER NOT NULL REFERENCES hosts(id),
            port              INTEGER,
            protocol          TEXT    DEFAULT 'tcp',
            service           TEXT,
            product           TEXT,
            version           TEXT,
            state             TEXT    DEFAULT 'open',
            banner            TEXT,
            cpe               TEXT,
            ssl_cert_subject  TEXT,
            ssl_cert_issuer   TEXT,
            ssl_cert_expires  TEXT,
            ssl_version       TEXT,
            ssl_cipher        TEXT,
            raw               TEXT
        );
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id         INTEGER NOT NULL REFERENCES scans(id),
            host_id         INTEGER NOT NULL REFERENCES hosts(id),
            port_id         INTEGER REFERENCES ports(id),
            cve             TEXT    NOT NULL,
            cvss            REAL,
            severity        TEXT,
            summary         TEXT,
            references_json TEXT,
            verified        INTEGER DEFAULT 0,
            note            TEXT,
            raw             TEXT
        );
        CREATE TABLE IF NOT EXISTS technologies (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id  INTEGER NOT NULL REFERENCES hosts(id),
            port_id  INTEGER REFERENCES ports(id),
            category TEXT,
            name     TEXT,
            version  TEXT,
            cpe      TEXT
        );
        CREATE TABLE IF NOT EXISTS host_tags (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER NOT NULL REFERENCES hosts(id),
            tag     TEXT    NOT NULL,
            source  TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_hosts_ip      ON hosts(ip);
        CREATE INDEX IF NOT EXISTS idx_hosts_scan    ON hosts(scan_id);
        CREATE INDEX IF NOT EXISTS idx_hosts_cc      ON hosts(country_code);
        CREATE INDEX IF NOT EXISTS idx_hosts_risk    ON hosts(risk_level);
        CREATE INDEX IF NOT EXISTS idx_ports_host    ON ports(host_id);
        CREATE INDEX IF NOT EXISTS idx_ports_port    ON ports(port);
        CREATE INDEX IF NOT EXISTS idx_vuln_cve      ON vulnerabilities(cve);
        CREATE INDEX IF NOT EXISTS idx_vuln_host     ON vulnerabilities(host_id);
        CREATE INDEX IF NOT EXISTS idx_vuln_scan     ON vulnerabilities(scan_id);
        CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerabilities(severity);
        CREATE INDEX IF NOT EXISTS idx_tech_host     ON technologies(host_id);
        CREATE INDEX IF NOT EXISTS idx_tech_name     ON technologies(name);
        CREATE INDEX IF NOT EXISTS idx_tags_host     ON host_tags(host_id);
        CREATE INDEX IF NOT EXISTS idx_tags_tag      ON host_tags(tag);
    """)
    conn.commit()
    _migrate_columns(conn)


def _migrate_columns(conn):
    table_cols = {}
    for tbl in ("scans", "hosts", "ports", "vulnerabilities"):
        cur = conn.execute(f"PRAGMA table_info({tbl});")
        table_cols[tbl] = {row[1] for row in cur.fetchall()}
    adds = [
        ("scans","total_hosts","INTEGER DEFAULT 0"),
        ("scans","total_ports","INTEGER DEFAULT 0"),
        ("scans","total_vulns","INTEGER DEFAULT 0"),
        ("scans","notes","TEXT"),
        ("hosts","country","TEXT"),("hosts","country_code","TEXT"),
        ("hosts","city","TEXT"),("hosts","latitude","REAL"),
        ("hosts","longitude","REAL"),("hosts","org","TEXT"),
        ("hosts","asn","TEXT"),("hosts","isp","TEXT"),
        ("hosts","vuln_count","INTEGER DEFAULT 0"),
        ("hosts","max_cvss","REAL DEFAULT 0.0"),
        ("hosts","risk_level","TEXT DEFAULT 'NONE'"),
        ("ports","product","TEXT"),("ports","version","TEXT"),
        ("ports","ssl_cert_subject","TEXT"),("ports","ssl_cert_issuer","TEXT"),
        ("ports","ssl_cert_expires","TEXT"),("ports","ssl_version","TEXT"),
        ("ports","ssl_cipher","TEXT"),
        ("vulnerabilities","cvss","REAL"),("vulnerabilities","severity","TEXT"),
        ("vulnerabilities","summary","TEXT"),
        ("vulnerabilities","references_json","TEXT"),
        ("vulnerabilities","verified","INTEGER DEFAULT 0"),
    ]
    for tbl, col, coldef in adds:
        if col not in table_cols.get(tbl, set()):
            try:
                conn.execute(f"ALTER TABLE {tbl} ADD COLUMN {col} {coldef};")
            except sqlite3.OperationalError:
                pass
    conn.commit()


# ---------------------------------------------------------------------------
# File handling
# ---------------------------------------------------------------------------
def find_latest_file(path: str) -> Optional[str]:
    if os.path.isfile(path):
        return path
    if os.path.isdir(path):
        files = []
        for f in os.listdir(path):
            fp = os.path.join(path, f)
            if os.path.isfile(fp) and os.path.getsize(fp) > 0:
                files.append(fp)
        if not files:
            return None
        files.sort(key=os.path.getmtime, reverse=True)
        return files[0]
    return None


def _read_start(path: str, nbytes: int = 1000) -> str:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read(nbytes).strip()


def detect_format(path: str) -> str:
    """Return 'xml', 'json', 'jsonl', 'nmap-json', or 'empty'."""
    if os.path.getsize(path) == 0:
        return "empty"

    start = _read_start(path, 2000)
    if not start:
        return "empty"

    # XML
    if start.startswith("<?xml") or start.startswith("<nmaprun") or start.startswith("<!DOCTYPE"):
        return "xml"

    # Try parsing as JSON
    # First: strip any leading non-JSON garbage (smap sometimes prints status lines)
    clean = start
    for i, ch in enumerate(start):
        if ch in ('{', '['):
            clean = start[i:]
            break

    # JSON array
    if clean.startswith("["):
        return "json"

    # JSON object - could be single object, nmap-json wrapper, or JSONL
    if clean.startswith("{"):
        # Try full file parse
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)
            # Check if it's nmap-json wrapper
            if isinstance(data, dict):
                if "nmaprun" in data:
                    return "nmap-json"
                # Single host object
                if any(k in data for k in ("ip", "ip_str", "address", "host", "target")):
                    return "json"
                # Wrapper with hosts/results
                for key in ("hosts", "results", "matches", "data"):
                    if key in data and isinstance(data[key], list):
                        return "json"
            return "json"
        except json.JSONDecodeError:
            # Maybe JSONL (multiple JSON objects, one per line)
            return "jsonl"

    return "unknown"


# ---------------------------------------------------------------------------
# XML parser (nmap/smap -oX)
# ---------------------------------------------------------------------------
def _parse_xml(path: str) -> Generator[dict, None, None]:
    try:
        tree = ET.parse(path)
    except ET.ParseError as e:
        print(f"  [warn] XML parse error: {e}")
        # Try to fix common issues (incomplete XML)
        try:
            with open(path, "r", errors="replace") as f:
                content = f.read()
            # Close unclosed nmaprun
            if "<nmaprun" in content and "</nmaprun>" not in content:
                content += "</nmaprun>"
            root = ET.fromstring(content)
            tree = ET.ElementTree(root)
        except Exception:
            return

    root = tree.getroot()

    for host_el in root.iter("host"):
        rec = {"status": "up"}

        # Status
        st = host_el.find("status")
        if st is not None:
            rec["status"] = st.get("state", "up")
            ttl = st.get("reason_ttl")
            if ttl:
                try:
                    rec["ttl"] = int(ttl)
                except ValueError:
                    pass

        # Address
        for addr in host_el.findall("address"):
            at = addr.get("addrtype", "")
            if at in ("ipv4", "ipv6"):
                rec["ip"] = addr.get("addr")

        if not rec.get("ip"):
            continue

        # Hostnames
        names = []
        for hn in host_el.iter("hostname"):
            n = hn.get("name")
            if n:
                names.append(n)
        if names:
            rec["hostname"] = names

        # OS
        for osm in host_el.iter("osmatch"):
            rec["os"] = osm.get("name")
            break
        if not rec.get("os"):
            for osc in host_el.iter("osclass"):
                parts = [osc.get("osfamily", ""), osc.get("osgen", "")]
                osname = " ".join(p for p in parts if p)
                if osname:
                    rec["os"] = osname
                break

        # Ports
        ports = []
        for port_el in host_el.iter("port"):
            pd = {
                "port": port_el.get("portid"),
                "protocol": port_el.get("protocol", "tcp"),
            }

            state_el = port_el.find("state")
            if state_el is not None:
                pd["state"] = state_el.get("state", "open")

            svc_el = port_el.find("service")
            if svc_el is not None:
                pd["service"] = svc_el.get("name")
                pd["product"] = svc_el.get("product")
                pd["version"] = svc_el.get("version")
                pd["banner"]  = svc_el.get("extrainfo")

                cpes = []
                for cpe_el in svc_el.findall("cpe"):
                    if cpe_el.text:
                        cpes.append(cpe_el.text)
                if cpes:
                    pd["cpes"] = cpes

                if not pd.get("banner"):
                    parts = [pd.get("product", ""), pd.get("version", "")]
                    b = " ".join(p for p in parts if p)
                    if b:
                        pd["banner"] = b

            # Script output (vulns)
            vulns = {}
            for script in port_el.findall("script"):
                sid = script.get("id", "")
                out = script.get("output", "")
                for m in re.finditer(r"(CVE-\d{4}-\d+)", out, re.IGNORECASE):
                    cid = m.group(1).upper()
                    if cid not in vulns:
                        vulns[cid] = {"cvss": None, "summary": None}
                # CVSS from output
                for m in re.finditer(r"(CVE-\d{4}-\d+)\s+(\d+\.?\d*)", out):
                    cid = m.group(1).upper()
                    try:
                        score = float(m.group(2))
                        if 0 <= score <= 10 and cid in vulns:
                            vulns[cid]["cvss"] = score
                    except ValueError:
                        pass
            if vulns:
                pd["vulns"] = vulns

            ports.append(pd)

        if ports:
            rec["ports"] = ports

        # Host-level scripts
        hvulns = {}
        for script in host_el.findall(".//hostscript/script"):
            out = script.get("output", "")
            for m in re.finditer(r"(CVE-\d{4}-\d+)", out, re.IGNORECASE):
                cid = m.group(1).upper()
                if cid not in hvulns:
                    hvulns[cid] = {"cvss": None, "summary": None}
        if hvulns:
            existing = rec.get("vulns") or {}
            if not isinstance(existing, dict):
                existing = {}
            existing.update(hvulns)
            rec["vulns"] = existing

        dbg(f"XML host: {rec.get('ip')} ports={len(ports)} vulns={len(rec.get('vulns', {}))}")
        yield rec


# ---------------------------------------------------------------------------
# JSON parsers
# ---------------------------------------------------------------------------
def _parse_json(path: str) -> Generator[dict, None, None]:
    """Parse a complete JSON file (array, object, or wrapper)."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        raw = f.read().strip()

    # Strip leading non-JSON (smap status output)
    for i, ch in enumerate(raw):
        if ch in ('{', '['):
            raw = raw[i:]
            break

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"  [warn] JSON parse error: {e}")
        # Try line-by-line
        yield from _parse_jsonl_from_string(raw)
        return

    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                yield from _normalize_json_record(item)
    elif isinstance(data, dict):
        yield from _normalize_json_record(data)


def _parse_nmap_json(path: str) -> Generator[dict, None, None]:
    """Parse nmap-json format: {"nmaprun": {"host": [...]}}."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        raw = f.read().strip()

    for i, ch in enumerate(raw):
        if ch in ('{', '['):
            raw = raw[i:]
            break

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"  [warn] nmap-json parse error: {e}")
        return

    if not isinstance(data, dict):
        return

    run = data.get("nmaprun", data)
    hosts = run.get("host", [])
    if isinstance(hosts, dict):
        hosts = [hosts]

    for h in hosts:
        if not isinstance(h, dict):
            continue
        rec = _convert_nmap_json_host(h)
        if rec and rec.get("ip"):
            yield rec


def _convert_nmap_json_host(h: dict) -> dict:
    """Convert a single nmap-json host object."""
    rec = {}

    # Address
    addr = h.get("address", {})
    if isinstance(addr, list):
        for a in addr:
            if isinstance(a, dict) and a.get("addrtype") in ("ipv4", "ipv6"):
                rec["ip"] = a.get("addr")
    elif isinstance(addr, dict):
        rec["ip"] = addr.get("addr")

    if not rec.get("ip"):
        return {}

    # Status
    status = h.get("status", {})
    if isinstance(status, dict):
        rec["status"] = status.get("state", "up")

    # Hostnames
    hns = h.get("hostnames", {})
    if isinstance(hns, dict):
        hn_list = hns.get("hostname", [])
    elif isinstance(hns, list):
        hn_list = hns
    else:
        hn_list = []
    if isinstance(hn_list, dict):
        hn_list = [hn_list]
    names = [x.get("name") for x in hn_list if isinstance(x, dict) and x.get("name")]
    if names:
        rec["hostname"] = names

    # OS
    os_data = h.get("os", {})
    if isinstance(os_data, dict):
        osm = os_data.get("osmatch", [])
        if isinstance(osm, dict):
            osm = [osm]
        if isinstance(osm, list) and osm:
            rec["os"] = osm[0].get("name")

    # Ports
    ports_wrap = h.get("ports", {})
    if isinstance(ports_wrap, dict):
        port_list = ports_wrap.get("port", [])
    elif isinstance(ports_wrap, list):
        port_list = ports_wrap
    else:
        port_list = []
    if isinstance(port_list, dict):
        port_list = [port_list]

    ports = []
    for p in port_list:
        if not isinstance(p, dict):
            continue
        pd = {
            "port": p.get("portid"),
            "protocol": p.get("protocol", "tcp"),
        }
        st = p.get("state", {})
        pd["state"] = st.get("state", "open") if isinstance(st, dict) else "open"

        svc = p.get("service", {})
        if isinstance(svc, dict):
            pd["service"] = svc.get("name")
            pd["product"] = svc.get("product")
            pd["version"] = svc.get("version")
            pd["banner"]  = svc.get("extrainfo")
            cpes = []
            for cpe_el in (svc.get("cpe", []) if isinstance(svc.get("cpe"), list)
                           else [svc.get("cpe")] if svc.get("cpe") else []):
                if isinstance(cpe_el, str):
                    cpes.append(cpe_el)
                elif isinstance(cpe_el, dict) and cpe_el.get("cpe"):
                    cpes.append(cpe_el["cpe"])
            if cpes:
                pd["cpes"] = cpes
        ports.append(pd)

    if ports:
        rec["ports"] = ports

    return rec


def _normalize_json_record(data: dict) -> Generator[dict, None, None]:
    """Handle wrapper objects or direct host records."""
    # Direct host record
    if any(k in data for k in ("ip", "ip_str", "address", "host", "target")):
        yield data
        return

    # Wrapper
    for key in ("hosts", "results", "matches", "data"):
        if key in data and isinstance(data[key], list):
            for item in data[key]:
                if isinstance(item, dict):
                    yield item
            return

    # nmap-json inside
    if "nmaprun" in data:
        run = data["nmaprun"]
        hosts = run.get("host", [])
        if isinstance(hosts, dict):
            hosts = [hosts]
        for h in hosts:
            if isinstance(h, dict):
                rec = _convert_nmap_json_host(h)
                if rec and rec.get("ip"):
                    yield rec
        return

    # Unknown structure - yield as-is if it has some data
    if data:
        dbg(f"Unknown JSON structure, keys: {list(data.keys())[:10]}")
        yield data


def _parse_jsonl(path: str) -> Generator[dict, None, None]:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, list):
                for item in obj:
                    if isinstance(item, dict):
                        yield item
            elif isinstance(obj, dict):
                yield from _normalize_json_record(obj)


def _parse_jsonl_from_string(raw: str) -> Generator[dict, None, None]:
    for line in raw.split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            yield from _normalize_json_record(obj)


# ---------------------------------------------------------------------------
# Unified iterator
# ---------------------------------------------------------------------------
def iter_records(path: str) -> Generator[dict, None, None]:
    fmt = detect_format(path)
    print(f"  [info] Format detected: {fmt}")

    if fmt == "xml":
        yield from _parse_xml(path)
    elif fmt == "nmap-json":
        yield from _parse_nmap_json(path)
    elif fmt == "json":
        yield from _parse_json(path)
    elif fmt == "jsonl":
        yield from _parse_jsonl(path)
    elif fmt == "empty":
        print(f"  [warn] Empty file")
    else:
        print(f"  [warn] Unknown format, trying all parsers...")
        count = 0
        for r in _parse_xml(path):
            yield r; count += 1
        if not count:
            for r in _parse_json(path):
                yield r; count += 1
        if not count:
            for r in _parse_jsonl(path):
                yield r; count += 1


# ---------------------------------------------------------------------------
# SSL / CPE helpers
# ---------------------------------------------------------------------------
def _extract_ssl(p: dict) -> dict:
    ssl = p.get("ssl") or p.get("tls") or {}
    if not isinstance(ssl, dict):
        return {}
    cert = ssl.get("cert") or {}
    if not isinstance(cert, dict):
        cert = {}
    subject = cert.get("subject") or {}
    issuer  = cert.get("issuer") or {}
    expires = cert.get("expires") or cert.get("not_after")
    versions = ssl.get("versions")
    cipher = ssl.get("cipher") or {}
    cn = cipher.get("name") if isinstance(cipher, dict) else (str(cipher) if cipher else None)
    return {
        "ssl_cert_subject": json.dumps(subject) if subject else None,
        "ssl_cert_issuer":  json.dumps(issuer) if issuer else None,
        "ssl_cert_expires": str(expires) if expires else None,
        "ssl_version":      json.dumps(versions) if versions else None,
        "ssl_cipher":       cn,
    }


_CPE_RE = re.compile(r"cpe:/([aoh]):([^:]*):?([^:]*)?")

def _parse_cpe(s: str) -> dict:
    m = _CPE_RE.match(s)
    if not m:
        return {"category": "unknown", "name": s, "version": None, "cpe": s}
    cats = {"a": "application", "o": "os", "h": "hardware"}
    return {"category": cats.get(m.group(1), m.group(1)),
            "name": m.group(2) or s, "version": m.group(3) or None, "cpe": s}


# ---------------------------------------------------------------------------
# Vuln extraction
# ---------------------------------------------------------------------------
def _extract_vulns(rec: dict) -> list:
    vulns = []
    raw = rec.get("vulns") or rec.get("vulnerabilities") or []
    if isinstance(raw, str):
        raw = [v.strip() for v in raw.split(",") if v.strip()]
    if isinstance(raw, dict):
        for cid, det in raw.items():
            if not isinstance(cid, str):
                continue
            e = {"cve": cid, "port": None, "cvss": None,
                 "summary": None, "verified": 0, "references": None}
            if isinstance(det, dict):
                e["cvss"] = det.get("cvss")
                e["summary"] = det.get("summary")
                e["verified"] = 1 if det.get("verified") else 0
                e["references"] = det.get("references")
            vulns.append(e)
    elif isinstance(raw, list):
        for item in raw:
            if isinstance(item, str):
                vulns.append({"cve": item, "port": None, "cvss": None,
                              "summary": None, "verified": 0, "references": None})
            elif isinstance(item, dict):
                vulns.append({
                    "cve": item.get("cve") or item.get("id") or "",
                    "port": item.get("port"),
                    "cvss": item.get("cvss") or item.get("score"),
                    "summary": item.get("summary") or item.get("description"),
                    "verified": 1 if item.get("verified") else 0,
                    "references": item.get("references"),
                })
    # Per-port
    for p in rec.get("ports", []):
        if not isinstance(p, dict):
            continue
        pn = p.get("port") or p.get("portnumber") or p.get("port_id")
        pv = p.get("vulns") or p.get("vulnerabilities") or {}
        if isinstance(pv, dict):
            for cid, det in pv.items():
                if not isinstance(cid, str):
                    continue
                e = {"cve": cid, "port": pn, "cvss": None,
                     "summary": None, "verified": 0, "references": None}
                if isinstance(det, dict):
                    e["cvss"] = det.get("cvss")
                    e["summary"] = det.get("summary")
                    e["verified"] = 1 if det.get("verified") else 0
                    e["references"] = det.get("references")
                vulns.append(e)
        elif isinstance(pv, list):
            for item in pv:
                cid = item if isinstance(item, str) else (item.get("cve") or item.get("id") or "")
                vulns.append({"cve": cid, "port": pn,
                    "cvss": item.get("cvss") if isinstance(item, dict) else None,
                    "summary": item.get("summary") if isinstance(item, dict) else None,
                    "verified": 0, "references": None})
    return [v for v in vulns if v.get("cve")]


# ---------------------------------------------------------------------------
# Tags
# ---------------------------------------------------------------------------
def _extract_tags(rec: dict) -> list:
    tags = set()
    for t in rec.get("tags", []):
        if isinstance(t, str):
            tags.add(("shodan", t))
    osi = rec.get("os")
    if osi:
        n = osi if isinstance(osi, str) else (osi.get("name") if isinstance(osi, dict) else None)
        if n:
            tags.add(("os", n.lower()))
    for p in rec.get("ports", []):
        if not isinstance(p, dict):
            continue
        s = p.get("service") or p.get("name")
        if s:
            tags.add(("service", s.lower()))
        if p.get("ssl") or p.get("tls"):
            tags.add(("protocol", "ssl/tls"))
    if rec.get("vulns") or rec.get("vulnerabilities"):
        tags.add(("status", "vulnerable"))
    return list(tags)


# ---------------------------------------------------------------------------
# Insert one host
# ---------------------------------------------------------------------------
def _insert_record(conn, scan_id, rec, seen):
    stats = {"hosts": 0, "ports": 0, "vulns": 0}
    if not isinstance(rec, dict):
        return stats
    c = conn.cursor()

    ip = (rec.get("ip") or rec.get("ip_str") or rec.get("address") or
          rec.get("target") or rec.get("host"))
    if isinstance(ip, int):
        import struct, socket
        ip = socket.inet_ntoa(struct.pack("!I", ip))
    if not ip:
        return stats

    key = f"{scan_id}:{ip}"
    if key in seen:
        return stats
    seen.add(key)

    hostname = rec.get("hostname") or rec.get("hostnames") or rec.get("domains")
    status = rec.get("status") or rec.get("state") or "up"
    os_info = rec.get("os")
    ttl = rec.get("ttl")
    if ttl is not None:
        try: ttl = int(ttl)
        except: ttl = None

    loc = rec.get("location") or {}
    if not isinstance(loc, dict): loc = {}
    country = loc.get("country_name") or rec.get("country_name")
    cc = loc.get("country_code") or rec.get("country_code")
    city = loc.get("city") or rec.get("city")
    lat = loc.get("latitude") or rec.get("latitude")
    lon = loc.get("longitude") or rec.get("longitude")
    org = rec.get("org")
    asn = rec.get("asn")
    isp = rec.get("isp")
    if cc: cc = str(cc).upper()

    raw_h = json.dumps(rec, ensure_ascii=False, default=str)
    os_v = os_info if isinstance(os_info, str) else (
        json.dumps(os_info, default=str) if os_info else None)
    hn_v = hostname if isinstance(hostname, str) else (
        json.dumps(hostname, default=str) if hostname else None)

    c.execute("""INSERT INTO hosts
        (scan_id,ip,hostname,status,os,ttl,country,country_code,city,
         latitude,longitude,org,asn,isp,raw)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (scan_id, ip, hn_v, status, os_v, ttl,
         country, cc, city, lat, lon, org, asn, isp, raw_h))
    host_id = c.lastrowid
    stats["hosts"] = 1

    # Ports
    ports_raw = rec.get("ports", [])
    if not ports_raw and isinstance(rec.get("data"), list):
        ports_raw = rec["data"]
    port_id_map = {}

    for p in ports_raw:
        if isinstance(p, int):
            pnum=p; proto="tcp"; svc=None; prod=None; ver=None
            st="open"; ban=None; cpe_raw=None; ssl_i={}; raw_p=str(p)
        elif isinstance(p, dict):
            pn = p.get("port") or p.get("portnumber") or p.get("port_id")
            try: pnum = int(pn) if pn is not None else None
            except: pnum = None
            proto = p.get("protocol") or p.get("proto") or p.get("transport") or "tcp"
            svc = p.get("service") or p.get("name")
            prod = p.get("product")
            ver = p.get("version")
            st = p.get("state") or p.get("status") or "open"
            ban = p.get("banner") or p.get("data")
            if isinstance(ban, (dict,list)):
                ban = json.dumps(ban, ensure_ascii=False, default=str)
            if ban and len(str(ban)) > 2000:
                ban = str(ban)[:2000]+"..."
            cpes = p.get("cpes") or p.get("cpe") or []
            if isinstance(cpes, str): cpes = [cpes]
            cpe_raw = json.dumps(cpes) if cpes else None
            ssl_i = _extract_ssl(p)
            raw_p = json.dumps(p, ensure_ascii=False, default=str)
        else:
            continue

        c.execute("""INSERT INTO ports
            (host_id,port,protocol,service,product,version,state,banner,cpe,
             ssl_cert_subject,ssl_cert_issuer,ssl_cert_expires,ssl_version,ssl_cipher,raw)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (host_id, pnum, proto, svc, prod, ver, st, ban, cpe_raw,
             ssl_i.get("ssl_cert_subject"), ssl_i.get("ssl_cert_issuer"),
             ssl_i.get("ssl_cert_expires"), ssl_i.get("ssl_version"),
             ssl_i.get("ssl_cipher"), raw_p))
        pid = c.lastrowid
        if pnum is not None:
            port_id_map[pnum] = pid
        stats["ports"] += 1

        if isinstance(p, dict):
            for cs in (p.get("cpes") or p.get("cpe") or []):
                if isinstance(cs, str):
                    t = _parse_cpe(cs)
                    c.execute("""INSERT INTO technologies
                        (host_id,port_id,category,name,version,cpe)
                        VALUES (?,?,?,?,?,?)""",
                        (host_id, pid, t["category"], t["name"], t["version"], t["cpe"]))

    # Vulns
    vlist = _extract_vulns(rec)
    mx = 0.0; seen_c = set()
    for v in vlist:
        cve = v["cve"]
        if cve in seen_c: continue
        seen_c.add(cve)
        cvss = v.get("cvss")
        if cvss is not None:
            try: cvss=float(cvss); mx=max(mx,cvss)
            except: cvss=None
        sev = score_to_severity(cvss) if cvss is not None else "UNKNOWN"
        lpid = None
        vp = v.get("port")
        if vp is not None:
            try: lpid = port_id_map.get(int(vp))
            except: pass
        if lpid is None and port_id_map:
            lpid = next(iter(port_id_map.values()))
        refs = v.get("references")
        rj = json.dumps(refs) if refs else None
        c.execute("""INSERT INTO vulnerabilities
            (scan_id,host_id,port_id,cve,cvss,severity,summary,references_json,verified,raw)
            VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (scan_id, host_id, lpid, cve, cvss, sev,
             v.get("summary"), rj, v.get("verified",0), json.dumps(v, default=str)))
        stats["vulns"] += 1

    vc = len(seen_c)
    rl = score_to_severity(mx) if mx > 0 else ("LOW" if vc > 0 else "NONE")
    c.execute("UPDATE hosts SET vuln_count=?, max_cvss=?, risk_level=? WHERE id=?",
              (vc, mx, rl, host_id))

    for src, tag in _extract_tags(rec):
        c.execute("INSERT INTO host_tags (host_id,tag,source) VALUES (?,?,?)",
                  (host_id, tag, src))

    return stats


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def import_smap(path: str, db_path: str) -> int:
    fp = find_latest_file(path)
    if not fp:
        print(f"[!] No file found at {path}")
        return 0
    if os.path.getsize(fp) == 0:
        print(f"[!] Empty file: {fp}")
        return 0

    print(f"[*] File: {fp} ({os.path.getsize(fp)} bytes)")

    # Debug: show file content
    start = _read_start(fp, 500)
    print(f"  [preview] {start[:200]}{'...' if len(start)>200 else ''}")

    has_any = False
    for rec in iter_records(fp):
        has_any = True
        if isinstance(rec, dict):
            print(f"  [first record] ip={rec.get('ip')} keys={list(rec.keys())[:8]}")
        break

    if not has_any:
        print(f"[!] No parseable records in {fp}")
        return 0

    conn = sqlite3.connect(db_path)
    ensure_schema(conn)

    st = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    c = conn.cursor()
    c.execute("INSERT INTO scans (scan_time, raw_file) VALUES (?,?)",
              (st, os.path.abspath(fp)))
    sid = c.lastrowid
    conn.commit()

    totals = {"hosts":0, "ports":0, "vulns":0}
    seen = set()

    try:
        with conn:
            for rec in iter_records(fp):
                if isinstance(rec, list):
                    for r in rec:
                        try:
                            s = _insert_record(conn, sid, r, seen)
                            for k in totals: totals[k] += s[k]
                        except Exception as e:
                            print(f"  [warn] {e}")
                elif isinstance(rec, dict):
                    try:
                        s = _insert_record(conn, sid, rec, seen)
                        for k in totals: totals[k] += s[k]
                    except Exception as e:
                        print(f"  [warn] {e}")
            conn.execute(
                "UPDATE scans SET total_hosts=?,total_ports=?,total_vulns=? WHERE id=?",
                (totals["hosts"], totals["ports"], totals["vulns"], sid))
    finally:
        conn.close()

    print(f"[+] Imported: {totals['hosts']} hosts, {totals['ports']} ports, "
          f"{totals['vulns']} vulns → {db_path} (scan #{sid})")

    if totals["hosts"] > 0:
        try:
            os.remove(fp)
            print(f"[+] Deleted: {fp}")
        except OSError as e:
            print(f"  [warn] {e}")

    return totals["hosts"]


def verify_db(db_path: str):
    if not os.path.isfile(db_path):
        print(f"[!] DB not found: {db_path}")
        return
    conn = sqlite3.connect(db_path)
    print(f"\n{'='*60}")
    print(f"  DB: {db_path} ({os.path.getsize(db_path)} bytes)")
    print(f"{'='*60}")
    for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;"):
        tbl = row[0]
        cnt = conn.execute(f"SELECT COUNT(*) FROM {tbl};").fetchone()[0]
        cols = conn.execute(f"PRAGMA table_info({tbl});").fetchall()
        print(f"\n  {tbl} ({cnt} rows): {', '.join(c[1] for c in cols)}")
    for label, q in [
        ("hosts",  "SELECT ip, os, country_code, vuln_count, risk_level FROM hosts LIMIT 3"),
        ("ports",  "SELECT h.ip, p.port, p.service, p.product FROM ports p JOIN hosts h ON p.host_id=h.id LIMIT 3"),
        ("vulns",  "SELECT v.cve, v.cvss, v.severity, h.ip FROM vulnerabilities v JOIN hosts h ON v.host_id=h.id LIMIT 3"),
        ("techs",  "SELECT t.category, t.name, t.version FROM technologies t LIMIT 3"),
    ]:
        print(f"\n  --- {label} ---")
        try:
            for r in conn.execute(q):
                print(f"    {r}")
        except Exception as e:
            print(f"    (error: {e})")
    conn.close()
    print(f"{'='*60}\n")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: import_smap.py <file_or_dir> <db> [--verify] [--debug]")
        sys.exit(1)

    input_path = sys.argv[1]
    db_path = sys.argv[2]
    db_dir = os.path.dirname(db_path)
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)

    if "--verify" in sys.argv:
        verify_db(db_path)
        sys.exit(0)

    import_smap(input_path, db_path)
    verify_db(db_path)
    sys.exit(0)