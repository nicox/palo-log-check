import streamlit as st
import plotly.express as px

from db import q, fmt_bytes, NO_DATA
from components import quick_classify_panel


def render(con, dw, ts_expr, has_data):
    st.header("Overview")
    if not has_data:
        st.warning(NO_DATA)
        return

    s = q(con, f"""
        SELECT COUNT(*)                         AS sessions,
               SUM(Bytes)                       AS bytes,
               COUNT(DISTINCT "Source address") AS src_ips,
               COUNT(DISTINCT Application)      AS apps
        FROM traffic_logs WHERE 1=1{dw}
    """).iloc[0]

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Sessions",          f"{int(s.sessions):,}")
    c2.metric("Total Bytes",       fmt_bytes(s.bytes))
    c3.metric("Unique Source IPs", f"{int(s.src_ips):,}")
    c4.metric("Unique Apps",       f"{int(s.apps):,}")

    col1, col2 = st.columns(2)
    with col1:
        df_a = q(con, f"""
            SELECT Action, COUNT(*) AS cnt
            FROM traffic_logs WHERE 1=1{dw}
            GROUP BY Action ORDER BY cnt DESC
        """)
        fig = px.pie(df_a, names="Action", values="cnt", title="Action Distribution")
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        df_b = q(con, f"""
            SELECT Application, SUM(Bytes) AS Bytes
            FROM traffic_logs WHERE 1=1{dw}
            GROUP BY Application ORDER BY Bytes DESC LIMIT 10
        """)
        fig = px.bar(df_b, x="Bytes", y="Application", orientation="h",
                     title="Top 10 Applications by Bytes")
        fig.update_layout(yaxis=dict(autorange="reversed"))
        st.plotly_chart(fig, use_container_width=True)

    ts_df = q(con, f"""
        SELECT TIME_BUCKET(INTERVAL '1 minute', {ts_expr}) AS t,
               SUM(Bytes) AS Bytes
        FROM traffic_logs
        WHERE {ts_expr} IS NOT NULL{dw}
        GROUP BY t ORDER BY t
    """)
    if not ts_df.empty:
        fig = px.area(ts_df, x="t", y="Bytes", title="Bytes per Minute",
                      labels={"t": "Time"})
        st.plotly_chart(fig, use_container_width=True)

    st.subheader("Session End Reasons")
    df_r = q(con, f"""
        SELECT "Session End Reason" AS Reason, COUNT(*) AS Count
        FROM traffic_logs WHERE 1=1{dw}
        GROUP BY Reason ORDER BY Count DESC
    """)
    st.dataframe(df_r, use_container_width=True, hide_index=True)
    quick_classify_panel("overview")
