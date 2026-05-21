import streamlit as st
import plotly.express as px

from db import q, safe, NO_DATA
from components import quick_classify_panel, row_prefill


def render(con, dw, has_data):
    st.header("Top Talkers")
    if not has_data:
        st.warning(NO_DATA)
        return

    c1, c2 = st.columns(2)
    with c1:
        metric = st.selectbox("Rank by", ["Bytes", "Sessions", "Packets"], key="tt_m")
    with c2:
        top_n = st.slider("Top N", 5, 50, 15, key="tt_n")

    val_sql = {"Bytes": "SUM(Bytes)", "Sessions": "COUNT(*)", "Packets": "SUM(Packets)"}[metric]

    def top_chart(col, title):
        df2 = q(con, f"""
            SELECT "{safe(col)}" AS grp, {val_sql} AS val
            FROM traffic_logs WHERE 1=1{dw}
            GROUP BY grp ORDER BY val DESC LIMIT {top_n}
        """)
        if df2.empty:
            return
        fig = px.bar(df2, x="val", y="grp", orientation="h", title=title,
                     labels={"val": metric, "grp": col})
        fig.update_layout(yaxis=dict(autorange="reversed"), margin=dict(l=0))
        st.plotly_chart(fig, width="stretch")

    c1, c2 = st.columns(2)
    with c1: top_chart("Source address",      f"Top {top_n} Sources by {metric}")
    with c2: top_chart("Destination address", f"Top {top_n} Destinations by {metric}")
    c3, c4 = st.columns(2)
    with c3: top_chart("Application",      f"Top {top_n} Applications by {metric}")
    with c4: top_chart("Destination Port", f"Top {top_n} Dest Ports by {metric}")

    st.subheader("Aggregated Session Table")
    st.caption("Click a row to pre-fill Quick Classify below.")
    agg = q(con, f"""
        SELECT "Source address", "Destination address", Application,
               COUNT(*)     AS Sessions,
               SUM(Bytes)   AS Bytes,
               SUM(Packets) AS Packets
        FROM traffic_logs WHERE 1=1{dw}
        GROUP BY "Source address", "Destination address", Application
        ORDER BY Bytes DESC, "Source address", "Destination address", Application LIMIT 500
    """)
    tt_sel = st.dataframe(agg, width="stretch", hide_index=True,
                          selection_mode="single-row", on_select="rerun",
                          key="tt_table")
    tt_prefill = row_prefill(agg, tt_sel.selection.rows, {
        "src_ip":      "Source address",
        "dst_ip":      "Destination address",
        "application": "Application",
    })
    quick_classify_panel("top_talkers", tt_prefill)
