# Palo Alto Log Analyzer

Streamlit web dashboard for analysing Palo Alto firewall traffic logs exported as CSV.
Log data is stored in a local DuckDB database — the app handles 700 MB+ CSV files without
loading them fully into RAM.

## Features

- **Overview** — session counts, action distribution, top apps by bytes, bytes/minute timeline
- **Top Talkers** — top source/destination IPs, applications, and ports ranked by bytes, sessions, or packets
- **Blocked Traffic** — denied/dropped/reset sessions with charts and filterable table
- **Bandwidth** — time-bucketed area charts grouped by application, zone, or protocol
- **Rules** — firewall rule hit counts and byte totals with drill-down
- **Classification** — define custom application profiles using ports, IPs, protocols, and URL categories; see classification results
- **Log View** — full log browser with classification column and quick-classify panel
- **Flow Visualization** — Sankey diagram (source → application → destination) with flow detail table and log examples
- **VLANs** — define VLANs by CIDR subnet; use as a global traffic filter across all tabs

## Quick start

```bash
pip install -r requirements.txt
streamlit run app.py --server.port 8501 --server.address 0.0.0.0 --server.headless true
```

Then open `http://<host>:8501` in a browser and import a CSV log file via the sidebar.

### Behind a Cloudflare Tunnel with a path prefix

The included `.streamlit/config.toml` sets `baseUrlPath = "palo"` so the app is reachable
at `https://<tunnel-host>/palo`.  Change or remove that setting as needed.

> **Upload limit:** Cloudflare tunnels impose a ~100 MB hard limit on uploads regardless of
> Streamlit's `maxUploadSize` setting.  For large files (700 MB+) use the **Server file path**
> import option, which reads directly from disk and bypasses the tunnel entirely.

## Configuration files

These files are **not** included in the repository because they contain site-specific data.
Copy the example files to get started:

```bash
cp app_definitions.example.json app_definitions.json
cp vlans.example.json vlans.json
```

| File | Purpose |
|------|---------|
| `app_definitions.json` | User-defined application classification rules |
| `vlans.json` | User-defined VLANs with CIDR subnets |

Both files are created automatically when you save your first rule or VLAN through the UI.

## Project layout

```
app.py                        Entry point: page config, sidebar, tab orchestration
db.py                         DuckDB connection, CSV import, query utilities
rules.py                      Application classification rule CRUD + SQL generation
vlans.py                      VLAN definition CRUD + SQL generation
components.py                 Reusable Streamlit widgets (quick-classify panel, etc.)
tabs/
  overview.py                 Tab 1 — Overview
  top_talkers.py              Tab 2 — Top Talkers
  blocked.py                  Tab 3 — Blocked Traffic
  bandwidth.py                Tab 4 — Bandwidth
  rules_tab.py                Tab 5 — Rules
  classification.py           Tab 6 — Classification
  log_view.py                 Tab 7 — Log View
  flow_viz.py                 Tab 8 — Flow Visualization
  vlans_tab.py                Tab 9 — VLANs
app_definitions.example.json  Example classification rules (copy → app_definitions.json)
vlans.example.json            Example VLAN definitions (copy → vlans.json)
```

## Requirements

- Python 3.10+
- See `requirements.txt` for package versions
