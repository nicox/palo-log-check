import streamlit as st
import plotly.express as px

from db import q, safe, NO_DATA
from components import quick_classify_panel, row_prefill


def render(con, dw, has_data):
    st.header("Firewall Rule Analysis")
    if not has_data:
        st.warning(NO_DATA)
        return

    rule_df = q(con, f"""
        SELECT Rule,
               COUNT(*)                              AS Sessions,
               SUM(Bytes)                            AS Bytes,
               COUNT(DISTINCT "Source address")      AS Sources,
               COUNT(DISTINCT "Destination address") AS Destinations
        FROM traffic_logs WHERE 1=1{dw}
        GROUP BY Rule ORDER BY Sessions DESC
    """)

    c1, c2 = st.columns(2)
    with c1:
        fig = px.bar(rule_df.head(20), x="Sessions", y="Rule", orientation="h",
                     title="Top 20 Rules by Hit Count")
        fig.update_layout(yaxis=dict(autorange="reversed"))
        st.plotly_chart(fig, use_container_width=True)
    with c2:
        fig = px.bar(rule_df.sort_values("Bytes", ascending=False).head(20),
                     x="Bytes", y="Rule", orientation="h",
                     title="Top 20 Rules by Bytes")
        fig.update_layout(yaxis=dict(autorange="reversed"))
        st.plotly_chart(fig, use_container_width=True)

    st.subheader("Rule Summary")
    st.dataframe(rule_df, use_container_width=True, hide_index=True)

    st.subheader("Drill into a Rule")
    rule_names = [""] + sorted(rule_df["Rule"].dropna().tolist())
    sel_rule = st.selectbox("Rule", rule_names)
    rule_prefill = {}
    if sel_rule:
        rd = q(con, f"""
            SELECT "Receive Time", "Source address", "Destination address",
                   Application, "Destination Port", "IP Protocol",
                   Action, Bytes, "Session End Reason"
            FROM traffic_logs
            WHERE Rule='{safe(sel_rule)}'{dw}
            ORDER BY "Receive Time" DESC LIMIT 500
        """)
        st.caption("Click a row to pre-fill Quick Classify below.")
        rule_sel = st.dataframe(rd, use_container_width=True, hide_index=True,
                                selection_mode="single-row", on_select="rerun",
                                key="rule_table")
        rule_prefill = row_prefill(rd, rule_sel.selection.rows, {
            "src_ip":      "Source address",
            "dst_ip":      "Destination address",
            "dst_port":    "Destination Port",
            "application": "Application",
            "protocol":    "IP Protocol",
        })
    quick_classify_panel("rules", rule_prefill)
