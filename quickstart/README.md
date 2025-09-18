# Smap → SQLite → Grafana (Docker Compose) — Quickstart README

A small, self-contained stack to visualize Smap network scan results in Grafana using a local SQLite database.
This repository runs a lightweight importer that converts Smap JSON (Shodan-based passive scans) into `smap.db` and provisions Grafana with a SQLite datasource.

---

## Requirements

* Docker (20.x+) and Docker Compose (v2 recommended) installed locally
* \~2 of your time

---

## What this Compose stack provides

* `smap-importer` — imports Smap JSON results into `smap.db` (targets provided via `targets.txt` or runtime strategy)
* `grafana` — Grafana with `frser-sqlite-datasource` plugin installed and a provisioned SQLite datasource pointing to `/var/lib/sqlite/smap.db`

Ports used in examples below assume Grafana is published on `3009` (container port 3000 → host 3009).

---

## Quick start

Clone the repo and start the stack:

```bash
git clone https://github.com/czantoine/smap-grafana-dashboard
cd smap-grafana-dashboard/quickstart
docker compose up -d
```

Open Grafana after a short initialization (\~30–60s):

* Grafana: `http://localhost:3009`
* Login: admin/admin

---

## Dashboard: get / import dashboard 24085

The Grafana dashboard used for visualization is available on Grafana.com:

* Dashboard ID: **24085** — *Smap Network Scanner – Nmap Alternative with Shodan.io*
  [https://grafana.com/grafana/dashboards/24085](https://grafana.com/grafana/dashboards/24085)

* Import via Grafana UI: *Dashboards → Import → Upload JSON* and set the datasource to `SQLite`.

---

## Targets (how to add hosts)

Important: in the current repo configuration `targets.txt` is copied into the importer image at **build time**. That means updating targets requires rebuilding the image unless you use a runtime approach.

Two recommended approaches:

### Option A — Rebuild workflow (simple & reproducible)

1. Edit `targets.txt` locally.
2. Rebuild the importer image:

   ```bash
   docker compose build smap-importer
   ```
3. Redeploy the importer service:

   ```bash
   docker compose up -d smap-importer
   ```

This replaces the container with a fresh image that contains the updated `targets.txt`.

### Option B — Runtime scheduling (no image rebuild)

* Add a small cron inside the `smap-importer` image that fetches an external `targets.txt` from a URL or a mounted file and runs the importer regularly.
* Or use a scheduler for Docker Swarm such as `crazymax/swarm-cronjob` to schedule periodic runs of the importer with a mounted `targets.txt` (or remote fetch).
  These methods let you change targets without rebuilding images.

---

## Validate that containers are running

```bash
docker ps
# Example output
CONTAINER ID   IMAGE                     COMMAND   CREATED         STATUS         PORTS                    NAMES
...            grafana:latest            "/run.sh" 2 minutes ago   Up 1 minute    0.0.0.0:3009->3000/tcp   grafana
...            smap-importer:latest      "/start.sh" Up 1 minute    smap-importer
```

---

## Cleanup

```bash
docker compose down
# Remove volumes if you want to reset DB (careful: this deletes stored data)
docker compose down -v
```
