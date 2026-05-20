import streamlit as st
import plotly.express as px

from db import q, safe, NO_DATA
from components import quick_classify_panel, row_prefill

DENY = "lower(Action) IN ('deny','drop','reset-client','reset-server','reset-both')"


def render(con, dw, has_data):
    st.header("Blocked / Denied Traffic")
    if not has_data:
        st.warning(NO_DATA)
        return

    bs = q(con, f"""
        SELECT COUNT(*) AS blocked,
               COUNT(DISTINCT "Source address") AS srcs
        FROM traffic_logs WHERE {DENY}{dw}
    """).iloc[0]
    total_s = q(con, f"SELECT COUNT(*) AS n FROM traffic_logs WHERE 1=1{dw}")["n"][0]

    c1, c2, c3 = st.columns(3)
    c1.metric("Blocked Sessions",       f"{int(bs.blocked):,}")
    c2.metric("Unique Blocked Sources", f"{int(bs.srcs):,}")
    pct = bs.blocked / total_s * 100 if total_s else 0
    c3.metric("Block Rate", f"{pct:.1f}%")

    col1, col2 = st.columns(2)
    with col1:
        df_bs = q(con, f"""
            SELECT "Source address" AS src, COUNT(*) AS cnt
            FROM traffic_logs WHERE {DENY}{dw}
            GROUP BY src ORDER BY cnt DESC LIMIT 15
        """)
        if not df_bs.empty:
            fig = px.bar(df_bs, x="cnt", y="src", orientation="h",
                         title="Top Blocked Sources",
                         labels={"cnt": "Sessions", "src": "Source IP"})
            fig.update_layout(yaxis=dict(autorange="reversed"))
            st.plotly_chart(fig, use_container_width=True)

    with col2:
        df_ba = q(con, f"""
            SELECT Application, COUNT(*) AS cnt
            FROM traffic_logs WHERE {DENY}{dw}
            GROUP BY Application ORDER BY cnt DESC LIMIT 15
        """)
        if not df_ba.empty:
            fig = px.bar(df_ba, x="cnt", y="Application", orientation="h",
                         title="Top Blocked Applications",
                         labels={"cnt": "Sessions"})
            fig.update_layout(yaxis=dict(autorange="reversed"))
            st.plotly_chart(fig, use_container_width=True)

    st.subheader("Blocked Traffic Table")
    st.caption("Click a row to pre-fill Quick Classify below.")
    src_filter = st.text_input("Filter by Source IP", key="blk_src")
    src_cond = f' AND "Source address" LIKE \'%{safe(src_filter)}%\'' if src_filter else ""

    detail = q(con, f"""
        SELECT "Receive Time", "Source address", "Destination address",
               "Source Port", "Destination Port", Application,
               "IP Protocol", Action, Rule, "Source Zone", "Destination Zone"
        FROM traffic_logs
        WHERE {DENY}{dw}{src_cond}
        ORDER BY "Receive Time" DESC, "Source address", "Destination address",
                 "Destination Port" LIMIT 500
    """)
    blk_sel = st.dataframe(detail, use_container_width=True, hide_index=True,
                           selection_mode="single-row", on_select="rerun",
                           key="blk_table")
    blk_prefill = row_prefill(detail, blk_sel.selection.rows, {
        "src_ip":      "Source address",
        "dst_ip":      "Destination address",
        "dst_port":    "Destination Port",
        "application": "Application",
        "protocol":    "IP Protocol",
    })
    quick_classify_panel("blocked", blk_prefill)
