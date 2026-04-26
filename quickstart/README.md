# Quickstart — Smap → SQLite → Grafana

Step-by-step guide to get the full stack running in under 2 minutes.

For project overview, features, schema details and dashboard panel reference, see the [main README](../README.md).

---

## Requirements

- **Docker** 20.x+ and **Docker Compose** v2
- No Shodan API key needed

---

## What This Stack Provides

| Service | Role | Default Port |
|---|---|---|
| `smap-importer` | Scans targets with Smap, imports results into `smap.db` | — (exits after import) |
| `grafana` | Visualizes `smap.db` with auto-provisioned dashboard (ID 24085) | `3009` → 3000 |

---

## Launch

```bash
git clone https://github.com/czantoine/smap-grafana-dashboard
cd smap-grafana-dashboard/quickstart
docker compose up -d
```

Open Grafana after ~30–60s:

- **URL:** `http://localhost:3009`
- **Login:** `admin` / `admin`

The dashboard and datasource are **auto-provisioned** — nothing to configure manually.

---

## Dashboard Import (alternative)

If you prefer manual import instead of auto-provisioning:

- Dashboard ID: **24085** — [grafana.com/grafana/dashboards/24085](https://grafana.com/grafana/dashboards/24085)
- In Grafana: *Dashboards → Import → Enter ID `24085`* → set datasource to `SQLite`

---

## Targets

> `targets.txt` is copied into the image at **build time**.

### Option A — Rebuild (simple)

```bash
vi targets.txt
docker compose build smap-importer
docker compose up -d smap-importer
```

### Option B — Volume mount (no rebuild)

Add to `docker-compose.yml`:

```yaml
services:
  smap-importer:
    volumes:
      - ./targets.txt:/app/targets.txt:ro
```

Then edit and restart:

```bash
vi targets.txt
docker compose restart smap-importer
```

### Option C — Automated scheduling

- Cron inside the container for periodic re-scans
- External scheduler (e.g., `crazymax/swarm-cronjob`)
- Fetch from API / CMDB at runtime

### Supported formats

```
1.1.1.1          # IPv4
example.com      # Hostname
178.23.56.0/24   # CIDR
```

---

## Entrypoint Flow

`entrypoint.sh` runs this sequence on each container start:

```
PRE-FLIGHT
├── HTTPS connectivity test → internetdb.shodan.io
├── DNS resolution check
└── TLS error reporting

SCAN
├── smap -iL targets.txt -oJ smap-output.json
├── JSON validation (size > 5 bytes)
└── Fallback to XML (-oX) if JSON fails

IMPORT (import_smap.py)
├── Auto-detect format (JSON / JSONL / XML / nmap-json)
├── Extract hosts, ports, CVEs, CPEs, SSL, geo
├── Compute CVSS severity + per-host risk level
├── Generate host tags (shodan / os / service / status)
└── Write 7 tables + 14 indexes → smap.db

VERIFY
└── Print DB summary (tables, row counts, samples)
```

---

## Validate

```bash
# Check containers
docker compose ps

# Expected:
#   NAME              STATUS          PORTS
#   smap-importer     exited (0)
#   grafana           Up              0.0.0.0:3009->3000/tcp

# Verify database
docker compose run --rm smap-importer \
  python3 /app/import_smap.py /app/scans /app/data/smap.db --verify

# Check Grafana logs
docker compose logs grafana | tail -20
```

---

## Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `GF_SECURITY_ADMIN_USER` | `admin` | Grafana admin username |
| `GF_SECURITY_ADMIN_PASSWORD` | `admin` | Grafana admin password |
| `GF_INSTALL_PLUGINS` | `frser-sqlite-datasource` | Plugins installed at startup |
| `GF_PLUGINS_ALLOW_LOADING_UNSIGNED_PLUGINS` | `frser-sqlite-datasource` | Allow unsigned SQLite plugin |

---

## Volumes

| Volume | Path | Purpose |
|---|---|---|
| `smap-data` | `/app/data` | Shared `smap.db` between importer and Grafana |
| `grafana-storage` | `/var/lib/grafana` | Grafana persistent data (users, prefs, etc.) |

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `internetdb.shodan.io ... FAILED` | No HTTPS outbound to Shodan | Disable VPN/proxy, open firewall to `internetdb.shodan.io:443` |
| `0 hosts imported` | Shodan blocked | Same as above |
| `Illegal number` in entrypoint | Old `entrypoint.sh` bug | Pull latest version (fixed `ERRS` sanitization) |
| `No file found at smap-output.json` | Normal post-import cleanup | Not an error — import succeeded, file was deleted |
| Dashboard says "No data" | DB not mounted or wrong path | Verify `sqlite.yml` path matches volume mount |
| SQLite plugin not loading | Plugin not installed | Ensure `GF_INSTALL_PLUGINS=frser-sqlite-datasource` |

---

## Cleanup

```bash
# Stop (keep data)
docker compose down

# Full reset (removes DB + Grafana data)
docker compose down -v

# Also remove built images
docker compose down -v --rmi all
```

---

## Next Steps

| Action | How |
|---|---|
| Add more targets | Edit `targets.txt` → rebuild or restart |
| Schedule periodic scans | Add cron to importer or use external scheduler |
| Enrich missing CVSS | Query NVD API to backfill scores |
| Set up alerting | Grafana alerts on CVE count or risk thresholds |
| Export reports | Grafana PDF/CSV export or Reporter plugin |
| Scale to larger infra | Migrate from SQLite to PostgreSQL |
