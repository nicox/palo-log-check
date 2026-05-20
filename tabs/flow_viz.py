import streamlit as st
import streamlit.components.v1 as components
import plotly.graph_objects as go

from db import q, safe, fmt_bytes, NO_DATA
from rules import load_app_defs, app_def_sql
from vlans import load_vlans, vlan_sql, parse_subnet


def render(con, dw, has_data):
    st.header("Traffic Flow Visualization")
    if not has_data:
        st.warning(NO_DATA)
        return

    app_defs_flow      = load_app_defs()
    app_defs_flow_vlans = load_vlans()

    _flow_modes = ["All Traffic", "By Application", "By Classified App", "By IP / Range"]
    if app_defs_flow_vlans:
        _flow_modes.append("By VLAN")

    c1, c2, c3 = st.columns([3, 1, 1])
    with c1:
        flow_mode = st.radio("View", _flow_modes, horizontal=True)
    with c2:
        max_nodes = st.number_input("Max nodes per layer", min_value=1, max_value=500, value=10, step=5, key="flow_max_nodes")
    with c3:
        max_links = st.number_input("Max links total", min_value=10, max_value=5000, value=200, step=50, key="flow_max_links")

    base_cond   = f"1=1{dw}"
    _flow_ready = True
    title       = ""

    if flow_mode == "By Application":
        apps_list = q(con, f"""
            SELECT Application FROM traffic_logs WHERE 1=1{dw}
            GROUP BY Application ORDER BY SUM(Bytes) DESC LIMIT 200
        """)["Application"].tolist()
        sel_app = st.selectbox("Application", apps_list)
        base_cond += f" AND Application='{safe(sel_app)}'"
        title = f"Flow: {sel_app}"

    elif flow_mode == "By Classified App":
        if not app_defs_flow:
            st.info("No classified applications defined — go to the Classification tab.")
            _flow_ready = False
        else:
            sel_capp = st.selectbox("Classified Application", list(app_defs_flow.keys()))
            expr = app_def_sql(app_defs_flow[sel_capp]["rules"])
            base_cond += f" AND ({expr})"
            title = f"Flow: {sel_capp} (classified)"

    elif flow_mode == "By IP / Range":
        ip_input = st.text_input(
            "IP address(es) or CIDR range(s)",
            placeholder="10.1.2.3  or  10.1.0.0/24  or  10.1.2.3, 10.2.0.0/16",
            key="flow_ip_filter",
        )
        ip_entries = [s.strip() for s in ip_input.replace(";", ",").split(",") if s.strip()]
        if not ip_entries:
            st.info("Enter one or more IP addresses or CIDR ranges (comma-separated) to draw the flow.")
            _flow_ready = False
        else:
            _valid_ips, _bad_ips = [], []
            for _e in ip_entries:
                _norm, _err = parse_subnet(_e)
                if _err:
                    _bad_ips.append(_err)
                elif _norm:
                    _valid_ips.append(_norm)
            if _bad_ips:
                for _e in _bad_ips:
                    st.error(_e)
                _flow_ready = False
            else:
                _ip_src = vlan_sql("Source address", _valid_ips)
                _ip_dst = vlan_sql("Destination address", _valid_ips)
                base_cond += f" AND ({_ip_src} OR {_ip_dst})"
                title = "Flow: " + ", ".join(_valid_ips)

    elif flow_mode == "By VLAN":
        sel_vlan_flow = st.selectbox("VLAN", list(app_defs_flow_vlans.keys()), key="flow_vlan")
        _vlan_subnets = app_defs_flow_vlans[sel_vlan_flow].get("subnets", [])
        if not _vlan_subnets:
            st.warning(f"VLAN '{sel_vlan_flow}' has no subnets defined.")
            _flow_ready = False
        else:
            _vsrc = vlan_sql("Source address", _vlan_subnets)
            _vdst = vlan_sql("Destination address", _vlan_subnets)
            base_cond += f" AND ({_vsrc} OR {_vdst})"
            title = f"Flow: {sel_vlan_flow} (VLAN)"

    else:
        title = "All Traffic Flow"

    # Top sources / apps / destinations
    _mn = int(max_nodes)
    _ml = int(max_links)
    top_srcs, top_dsts, top_apps = [], [], []

    if _flow_ready:
        top_srcs = q(con, f"""
            SELECT "Source address" AS ip, SUM(Bytes) AS b
            FROM traffic_logs WHERE {base_cond}
            GROUP BY ip ORDER BY b DESC LIMIT {_mn}
        """)["ip"].tolist()

        top_dsts = q(con, f"""
            SELECT "Destination address" AS ip, SUM(Bytes) AS b
            FROM traffic_logs WHERE {base_cond}
            GROUP BY ip ORDER BY b DESC LIMIT {_mn}
        """)["ip"].tolist()

        top_apps = q(con, f"""
            SELECT Application AS app, SUM(Bytes) AS b
            FROM traffic_logs WHERE {base_cond}
            GROUP BY app ORDER BY b DESC LIMIT {_mn}
        """)["app"].tolist()

    if not top_srcs and _flow_ready:
        st.warning("No traffic matching this filter.")
    else:
        srcs_sql = ",".join(f"'{safe(s)}'" for s in top_srcs)
        dsts_sql = ",".join(f"'{safe(d)}'" for d in top_dsts)
        apps_sql = ",".join(f"'{safe(a)}'" for a in top_apps)

        sa = q(con, f"""
            SELECT "Source address" AS src, Application AS app, SUM(Bytes) AS b
            FROM traffic_logs
            WHERE {base_cond}
              AND "Source address" IN ({srcs_sql})
              AND Application IN ({apps_sql})
            GROUP BY src, app
            ORDER BY b DESC
            LIMIT {_ml}
        """)
        ad = q(con, f"""
            SELECT Application AS app, "Destination address" AS dst, SUM(Bytes) AS b
            FROM traffic_logs
            WHERE {base_cond}
              AND "Destination address" IN ({dsts_sql})
              AND Application IN ({apps_sql})
            GROUP BY app, dst
            ORDER BY b DESC
            LIMIT {_ml}
        """)

        srcs = list(sa["src"].unique()) if not sa.empty else []
        apps = list(sa["app"].unique()) if not sa.empty else []
        dsts = list(ad["dst"].unique()) if not ad.empty else []

        node_labels = srcs + apps + dsts
        src_idx = {v: i                        for i, v in enumerate(srcs)}
        app_idx = {v: i + len(srcs)            for i, v in enumerate(apps)}
        dst_idx = {v: i + len(srcs) + len(apps) for i, v in enumerate(dsts)}

        ls, lt, lv, ll = [], [], [], []
        for _, row in sa.iterrows():
            if row["src"] in src_idx and row["app"] in app_idx:
                ls.append(src_idx[row["src"]])
                lt.append(app_idx[row["app"]])
                lv.append(float(row["b"]))
                ll.append(fmt_bytes(row["b"]))
        for _, row in ad.iterrows():
            if row["app"] in app_idx and row["dst"] in dst_idx:
                ls.append(app_idx[row["app"]])
                lt.append(dst_idx[row["dst"]])
                lv.append(float(row["b"]))
                ll.append(fmt_bytes(row["b"]))

        if ls:
            colors = (
                ["rgba(31,119,180,0.85)"] * len(srcs) +
                ["rgba(255,127,14,0.85)"] * len(apps) +
                ["rgba(44,160,44,0.85)"]  * len(dsts)
            )
            fig = go.Figure(go.Sankey(
                arrangement="snap",
                node=dict(pad=12, thickness=18,
                          line=dict(color="black", width=0.4),
                          label=node_labels, color=colors),
                link=dict(source=ls, target=lt, value=lv,
                          customdata=ll,
                          hovertemplate="%{source.label} → %{target.label}: %{customdata}<extra></extra>"),
            ))
            fig.update_layout(
                title_text=title, height=620,
                font=dict(family="Arial, sans-serif", size=14, color="#111111"),
                paper_bgcolor="white",
                margin=dict(l=10, r=10, t=40, b=10),
            )
            # Plotly.js hard-codes `stroke: white` on Sankey labels to create a
            # legibility halo, but on dense diagrams it makes the text blurry.
            # There is no Python/layout API to override it.  Workaround: render
            # the figure as a self-contained HTML page, inject a CSS rule that
            # strips the stroke inside the <head>, then embed it via an iframe so
            # the injected style is scoped to that document and can't leak out.
            html = fig.to_html(
                include_plotlyjs="cdn",
                full_html=True,
                config={"responsive": True, "displayModeBar": True},
            )
            html = html.replace(
                "<head>",
                "<head><style>"
                "body{margin:0;padding:0;background:white}"
                ".sankey text{"
                "  stroke:none!important;"
                "  stroke-width:0!important;"
                "  paint-order:fill!important;"
                "  font-family:Arial,sans-serif!important;"
                "  font-size:14px!important;"
                "  fill:#111111!important;"
                "}"
                "</style>",
            )
            components.html(html, height=660, scrolling=False)

            m1, m2, m3 = st.columns(3)
            m1.metric("Source nodes",      len(srcs))
            m2.metric("Application nodes", len(apps))
            m3.metric("Destination nodes", len(dsts))

            # ── Flow detail table ──────────────────────────────────────────
            st.markdown("---")
            st.subheader("Flow Details")
            st.caption("Click a row to see example log entries for that flow.")

            flow_trips = q(con, f"""
                SELECT
                    "Source address"      AS "Source",
                    Application,
                    "Destination address" AS "Destination",
                    "Destination Port",
                    COUNT(*)              AS Sessions,
                    SUM(Bytes)            AS Bytes
                FROM traffic_logs
                WHERE {base_cond}
                  AND "Source address"      IN ({srcs_sql})
                  AND Application           IN ({apps_sql})
                  AND "Destination address" IN ({dsts_sql})
                GROUP BY "Source", Application, "Destination", "Destination Port"
                ORDER BY Bytes DESC
                LIMIT {_ml}
            """)

            flow_sel = st.dataframe(
                flow_trips, use_container_width=True, hide_index=True,
                selection_mode="single-row", on_select="rerun",
                key="flow_detail_table",
            )

            if flow_sel.selection.rows:
                _fr = flow_trips.iloc[flow_sel.selection.rows[0]]
                _fsrc   = str(_fr["Source"])
                _fapp   = str(_fr["Application"])
                _fdst   = str(_fr["Destination"])
                _fdport = int(_fr["Destination Port"])

                st.markdown(
                    f"**Sample logs — `{_fsrc}` → `{_fapp}` → `{_fdst}:{_fdport}`**"
                )
                sample_logs = q(con, f"""
                    SELECT
                        "Receive Time",
                        "Source address",
                        "Source Port",
                        "Destination address",
                        "Destination Port",
                        Application,
                        "IP Protocol",
                        Action,
                        Bytes,
                        "Session End Reason",
                        Rule
                    FROM traffic_logs
                    WHERE {base_cond}
                      AND "Source address"      = '{safe(_fsrc)}'
                      AND Application           = '{safe(_fapp)}'
                      AND "Destination address" = '{safe(_fdst)}'
                      AND "Destination Port"    = {_fdport}
                    ORDER BY "Receive Time" DESC
                    LIMIT 20
                """)
                st.dataframe(sample_logs, use_container_width=True, hide_index=True)
        else:
            st.warning("Not enough overlapping data to draw a Sankey diagram.")
