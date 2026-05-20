"""
Palo Alto Log Analyzer
======================
Streamlit web dashboard for analysing Palo Alto firewall traffic logs exported
as CSV.  Log data is stored in a local DuckDB database so files are never fully
loaded into RAM — the app handles 700 MB+ CSVs without issues.

Module layout
-------------
app.py          entry point: page config, sidebar, tab orchestration
db.py           DuckDB connection, import, query utilities
rules.py        application classification rule CRUD and SQL generation
vlans.py        VLAN definition CRUD and SQL generation
components.py   reusable Streamlit UI widgets
tabs/           one module per tab (each exposes a render() function)

Global filters (date range, VLAN) are computed in the sidebar and appended to
the `dw` string, which every tab query includes as an AND condition.

Tabs
----
1  Overview          — session counts, action pie, top apps by bytes, timeline
2  Top Talkers       — top sources / destinations / apps / ports by bytes
3  Blocked Traffic   — denied/drop/reset sessions with filterable table
4  Bandwidth         — time-bucketed area charts grouped by app / zone / protocol
5  Rules             — firewall rule hit counts and byte totals, drill-down
6  Classification    — CRUD for application definitions; classification results
7  Log View          — full log with classification column and quick-classify
8  Flow Visualization — Sankey diagram (src → app → dst) with flow detail table
9  VLANs             — CRUD for VLANs; file import; per-VLAN traffic summary
"""

import streamlit as st
import tempfile
import os
from pathlib import Path

import rules
from db import (
    get_db, logs_exist, total_rows, get_ts_expr, get_url_cols,
    q, import_file, DB_PATH,
)
from vlans import load_vlans, vlan_sql
from tabs import (overview, top_talkers, blocked, bandwidth,
                  rules_tab, classification, log_view, flow_viz, vlans_tab)

st.set_page_config(
    page_title="Palo Alto Log Analyzer",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── Startup ──────────────────────────────────────────────────────────────────

con = get_db()
TS_EXPR = get_ts_expr(con)
rules.URL_COLS = get_url_cols(con)   # make URL column data available to rules module

# ─── Sidebar ──────────────────────────────────────────────────────────────────

with st.sidebar:
    st.title("Palo Alto Analyzer")

    n    = total_rows(con)
    t0   = t1 = None
    if n:
        st.metric("Log entries in DB", f"{n:,}")
        mm = q(con, f"SELECT MIN({TS_EXPR}) AS t0, MAX({TS_EXPR}) AS t1 FROM traffic_logs")
        t0, t1 = mm["t0"][0], mm["t1"][0]
        if t0:
            st.caption(f"{t0:%Y-%m-%d %H:%M}  →  {t1:%Y-%m-%d %H:%M}")
        db_size = DB_PATH.stat().st_size / 1e6 if DB_PATH.exists() else 0
        st.caption(f"Database size: {db_size:.0f} MB")
    else:
        st.info("No log data yet — import a file below.")

    st.markdown("---")
    st.subheader("Import Log Files")

    method = st.radio("Import from", ["Server file path", "Browser upload"])

    if method == "Browser upload":
        st.warning(
            "Browser upload is limited to ~100 MB by Cloudflare. "
            "For larger files use **Server file path** — it reads directly "
            "from disk and bypasses this limit entirely."
        )

    if method == "Server file path":
        spath = st.text_input("File path on server",
                              placeholder="/root/palo-log-check/log.csv")
        if st.button("Import", key="imp_path"):
            p = Path(spath.strip())
            if not p.exists():
                st.error(f"File not found: {p}")
            else:
                with st.spinner(f"Importing {p.name} ({p.stat().st_size/1e6:.0f} MB)…"):
                    res = import_file(con, str(p), p.name, p.stat().st_size)
                if res["status"] == "ok":
                    st.success(f"+{res['rows_added']:,} rows  ({res['total']:,} total)")
                    st.rerun()
                elif res["status"] == "skipped":
                    st.warning(res["reason"])
                else:
                    st.error(res["reason"])
    else:
        up = st.file_uploader("Upload CSV", type=["csv"])
        if up and st.button("Import", key="imp_upload"):
            with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tmp:
                tmp.write(up.getvalue())
                tmp_path = tmp.name
            try:
                with st.spinner(f"Importing {up.name}…"):
                    res = import_file(con, tmp_path, up.name, up.size)
            finally:
                os.unlink(tmp_path)
            if res["status"] == "ok":
                st.success(f"+{res['rows_added']:,} rows  ({res['total']:,} total)")
                st.rerun()
            elif res["status"] == "skipped":
                st.warning(res["reason"])
            else:
                st.error(res["reason"])

    # Import history
    hist = q(con, "SELECT filename, imported_at, row_count FROM import_history ORDER BY imported_at DESC")
    if not hist.empty:
        st.markdown("---")
        st.caption("Imported files")
        for _, row in hist.iterrows():
            st.caption(f"• {row['filename']}  ({int(row['row_count']):,} rows)")

    # Clear database
    if n:
        st.markdown("---")
        if st.button("Clear database", type="secondary"):
            con.execute("DROP TABLE IF EXISTS traffic_logs")
            con.execute("DELETE FROM import_history")
            st.rerun()

    # `dw` is a string of extra AND conditions (e.g. " AND ts BETWEEN … AND …")
    # that every tab query appends verbatim.  Both the date filter and the VLAN
    # filter write into it so all tabs are narrowed by a single mechanism.
    dw = ""
    if n and t0:
        st.markdown("---")
        st.subheader("Date Filter")
        use_df = st.checkbox("Limit to date range")
        if use_df:
            d0 = st.date_input("From", value=t0.date())
            d1 = st.date_input("To",   value=t1.date())
            dw = f" AND {TS_EXPR} BETWEEN '{d0}' AND '{d1} 23:59:59'"

    # Global VLAN filter
    _vlans_sidebar = load_vlans()
    if _vlans_sidebar:
        st.markdown("---")
        st.subheader("VLAN Filter")
        _vlan_opts = ["All VLANs"] + list(_vlans_sidebar.keys())
        _sel_vlan = st.selectbox("Show traffic for", _vlan_opts, key="sidebar_vlan")
        if _sel_vlan != "All VLANs":
            _subnets = _vlans_sidebar[_sel_vlan].get("subnets", [])
            if _subnets:
                _src = vlan_sql("Source address", _subnets)
                _dst = vlan_sql("Destination address", _subnets)
                dw += f" AND ({_src} OR {_dst})"
                st.caption(f"{len(_subnets)} subnet(s): " +
                           ", ".join(_subnets[:3]) +
                           (" …" if len(_subnets) > 3 else ""))

# ─── Tabs ─────────────────────────────────────────────────────────────────────

has_data = logs_exist(con) and n > 0

tab_list = st.tabs([
    "Overview", "Top Talkers", "Blocked Traffic",
    "Bandwidth", "Rules", "Classification", "Log View", "Flow Visualization", "VLANs",
])

with tab_list[0]: overview.render(con, dw, TS_EXPR, has_data)
with tab_list[1]: top_talkers.render(con, dw, has_data)
with tab_list[2]: blocked.render(con, dw, has_data)
with tab_list[3]: bandwidth.render(con, dw, TS_EXPR, has_data)
with tab_list[4]: rules_tab.render(con, dw, has_data)
with tab_list[5]: classification.render(con, dw, has_data)
with tab_list[6]: log_view.render(con, dw, has_data)
with tab_list[7]: flow_viz.render(con, dw, has_data)
with tab_list[8]: vlans_tab.render(con, dw, has_data)
