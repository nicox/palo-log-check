import streamlit as st
import plotly.express as px

from db import q, safe, NO_DATA
from components import quick_classify_panel

BUCKETS = {
    "1 minute":   "1 minute",
    "5 minutes":  "5 minutes",
    "15 minutes": "15 minutes",
    "1 hour":     "1 hour",
    "1 day":      "1 day",
}


def render(con, dw, ts_expr, has_data):
    st.header("Bandwidth Usage")
    if not has_data:
        st.warning(NO_DATA)
        return

    c1, c2 = st.columns(2)
    with c1:
        bucket = BUCKETS[st.selectbox("Time bucket", list(BUCKETS), index=1)]
    with c2:
        grp_by = st.selectbox("Group by",
            ["None", "Application", "Source Zone", "Destination Zone",
             "IP Protocol", "Action"])

    if grp_by == "None":
        ts = q(con, f"""
            SELECT TIME_BUCKET(INTERVAL '{bucket}', {ts_expr}) AS t,
                   SUM(Bytes) AS Bytes
            FROM traffic_logs WHERE {ts_expr} IS NOT NULL{dw}
            GROUP BY t ORDER BY t
        """)
        fig = px.area(ts, x="t", y="Bytes", title="Total Bytes Over Time",
                      labels={"t": "Time"})
    else:
        top_cats = q(con, f"""
            SELECT "{safe(grp_by)}" AS cat
            FROM traffic_logs WHERE 1=1{dw}
            GROUP BY cat ORDER BY SUM(Bytes) DESC LIMIT 8
        """)["cat"].tolist()
        cats_sql = ",".join(f"'{safe(c)}'" for c in top_cats)
        ts = q(con, f"""
            SELECT TIME_BUCKET(INTERVAL '{bucket}', {ts_expr}) AS t,
                   "{safe(grp_by)}" AS grp,
                   SUM(Bytes) AS Bytes
            FROM traffic_logs
            WHERE {ts_expr} IS NOT NULL
              AND "{safe(grp_by)}" IN ({cats_sql}){dw}
            GROUP BY t, grp ORDER BY t
        """)
        fig = px.area(ts, x="t", y="Bytes", color="grp",
                      title=f"Bytes by {grp_by}", labels={"t": "Time", "grp": grp_by})
    st.plotly_chart(fig, use_container_width=True)

    c1, c2 = st.columns(2)
    with c1:
        sr = q(con, f"""
            SELECT TIME_BUCKET(INTERVAL '{bucket}', {ts_expr}) AS t,
                   SUM("Bytes Sent")     AS "Bytes Sent",
                   SUM("Bytes Received") AS "Bytes Received"
            FROM traffic_logs WHERE {ts_expr} IS NOT NULL{dw}
            GROUP BY t ORDER BY t
        """)
        fig = px.line(sr, x="t", y=["Bytes Sent", "Bytes Received"],
                      title="Bytes Sent vs Received", labels={"t": "Time"})
        st.plotly_chart(fig, use_container_width=True)

    with c2:
        proto = q(con, f"""
            SELECT "IP Protocol" AS Protocol, SUM(Bytes) AS Bytes
            FROM traffic_logs WHERE 1=1{dw}
            GROUP BY Protocol ORDER BY Bytes DESC
        """)
        fig = px.pie(proto, names="Protocol", values="Bytes", title="Bytes by Protocol")
        st.plotly_chart(fig, use_container_width=True)

    quick_classify_panel("bandwidth")
