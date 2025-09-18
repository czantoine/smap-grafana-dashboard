<p align="center">
	<a href="https://twitter.com/cz_antoine"><img alt="Twitter" src="https://img.shields.io/twitter/follow/cz_antoine?style=social"></a>
	<a href="https://www.linkedin.com/in/antoine-cichowicz-837575b1"><img alt="Linkedin" src="https://img.shields.io/badge/-Antoine-blue?style=flat-square&logo=Linkedin&logoColor=white"></a>
	<a href="https://github.com/czantoine/smap-grafana-dashboard"><img alt="Stars" src="https://img.shields.io/github/stars/czantoine/smap-grafana-dashboard"></a>
	<a href="https://github.com/czantoine/smap-grafana-dashboard"><img alt="Issues" src="https://img.shields.io/github/issues/czantoine/smap-grafana-dashboard"></a>
	<img alt="Last Commit" src="https://img.shields.io/github/last-commit/czantoine/smap-grafana-dashboard">
  <a href="https://grafana.com/dashboards/24085">
    <img src="https://grafana-dashboard-badge.netlify.app/.netlify/functions/api/badge?id_dashboard=24085&logo=true" alt="Grafana Dashboard Badge">
  </a>
</p>

If you enjoy my projects and want to support my work, consider buying me a coffee! ☕️

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/V7V22V693)

# Smap Network Scanner – Nmap Alternative with Shodan.io

## Project overview
This project shows how to use **Smap** (a passive network scanner that leverages the Shodan.io API as an Nmap alternative) together with a lightweight pipeline that imports Smap JSON output into a local SQLite database and visualizes results with Grafana. The purpose is to provide an easy, reproducible way to monitor scanned hosts, open ports, services and detected CVEs over time — useful for monitoring, historical analysis and basic vulnerability tracking.

The packaged Grafana dashboard used in this project is **“Smap Network Scanner – Nmap Alternative with Shodan.io”** (Grafana Dashboard ID **24085**). It visualizes hosts, ports, service fingerprints and CVE information coming from the SQLite import of Smap JSON results.

![grafana_dashboard_smap](docs/images/dashboard.png)

A Docker Compose setup is available if you wish to test the dashboard. Available [here](quickstart/README.md).

## Key concepts / data flow
1. **Smap** queries Shodan (passively) and produces JSON scan results for target hosts.  
2. A small **importer** converts the Smap JSON into rows and stores them in a SQLite database (`smap.db`).  
3. **Grafana** uses a provisioned SQLite datasource that reads `smap.db`.  
4. The Grafana dashboard (ID 24085) (to import manually) reads that datasource and displays:
   - list of scanned hosts and metadata,
   - discovered open ports and services,
   - detected CVEs and their counts,
   - historical trends and simple vulnerability tracking.

This setup is intended to be lightweight and easy to run locally or in a small containerized environment.

## Adding targets (how to include new hosts)
Adding new scan targets is intentionally simple, but how you update targets depends on how the importer is deployed:

**Important:** in this project `targets.txt` is copied into the Docker image at build time. That means the built image contains the target list baked in.

Two practical options to update targets:

- **Option 1 — rebuild the image with an updated `targets.txt`**  
  1. Edit `targets.txt` in your project working tree.  
  2. Rebuild the importer image via `docker compose build smap-importer`
  3. Redeploy the `smap-importer` service so the new image (containing the updated `targets.txt`) is used via `docker compose up -d smap-importer`
  
  This replaces the running container with an image that contains the new target list.

- **Option 2 — schedule automated updates instead of rebuilding**  
  If you prefer not to rebuild the image every time you change targets, consider:
  - Adding a small cron job inside the `smap-importer` image that periodically pulls an external `targets.txt` (or otherwise refreshes targets) and triggers the importer; or  
  - Using a scheduler for Docker Swarm such as `crazymax/swarm-cronjob` to run the importer periodically with an externally mounted or dynamically provided `targets.txt`.  
  Both approaches let you change targets without an image rebuild: the importer fetches or reads the current target list at runtime.

## Why this approach
- Using **Shodan** makes Smap passive and quick to run against many hosts without active probing overhead.  
- Importing structured Smap JSON into **SQLite** keeps the stack simple and self-contained.  
- Grafana gives immediate, shareable visualizations (dashboard 24085 is focused on hosts, ports and CVEs), making the output easy to explore and useful for monitoring or light SOC workflows.

## Smap

Smap project: [https://github.com/s0md3v/Smap](https://github.com/s0md3v/Smap) see more for additional information.

### Features

* Scans 200 hosts per second
* Doesn’t require any account / API key (note: querying Shodan directly requires an API key; you can also import local Smap JSON output without using a Shodan key)
* Vulnerability detection (CVE enumeration from service fingerprints)
* Supports all Nmap output formats (import Smap/Nmap JSON outputs)
* Service and version fingerprinting
* Makes no contact to the targets (passive scanning using Shodan data)

You can directly find the [dashboard here](https://grafana.com/grafana/dashboards/24085) or use the ID: 24085.

--- 

If you find this project useful, please give it a star ⭐️ ! Your support is greatly appreciated. Also, feel free to contribute to this project. All contributions, whether bug fixes, improvements, or new features, are welcome!