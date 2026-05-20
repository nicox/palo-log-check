import streamlit as st
import plotly.express as px

import rules as _rules_mod
from db import q, safe, NO_DATA
from rules import load_app_defs, build_classify_sql
from components import quick_classify_panel, row_prefill


def render(con, dw, has_data):
    st.header("Log View")
    if not has_data:
        st.warning(NO_DATA)
        return

    app_defs_lv = load_app_defs()
    cls_sql = build_classify_sql(app_defs_lv)

    # ── Classification stats ───────────────────────────────────────────────
    stats = q(con, f"""
        WITH c AS (SELECT {cls_sql} AS cls FROM traffic_logs WHERE 1=1{dw})
        SELECT COUNT(*) AS total, COUNT(cls) AS classified
        FROM c
    """).iloc[0]
    total_lv     = int(stats.total or 0)
    classified   = int(stats.classified or 0)
    unclassified = total_lv - classified
    pct_cls = classified   / total_lv * 100 if total_lv else 0
    pct_unc = unclassified / total_lv * 100 if total_lv else 0

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total Sessions", f"{total_lv:,}")
    m2.metric("Classified",     f"{classified:,}",   f"{pct_cls:.1f}%")
    m3.metric("Unclassified",   f"{unclassified:,}", f"{pct_unc:.1f}%")
    if app_defs_lv:
        m4.metric("Defined apps", len(app_defs_lv))

    if app_defs_lv:
        cls_breakdown = q(con, f"""
            WITH c AS (
                SELECT COALESCE({cls_sql}, '— unclassified —') AS cls
                FROM traffic_logs WHERE 1=1{dw}
            )
            SELECT cls AS Classification, COUNT(*) AS Sessions
            FROM c GROUP BY cls ORDER BY Sessions DESC
        """)
        fig = px.pie(cls_breakdown, names="Classification", values="Sessions",
                     title="Sessions by Classification",
                     hole=0.4,
                     color_discrete_sequence=px.colors.qualitative.Safe)
        st.plotly_chart(fig, use_container_width=True)

    # ── Filters ───────────────────────────────────────────────────────────
    st.subheader("Filter & Browse")
    show_opts = ["All traffic", "Unclassified only", "Classified only"]
    if app_defs_lv:
        show_opts += [f"App: {_app_name}" for _app_name in app_defs_lv]

    fc1, fc2, fc3 = st.columns(3)
    show_filter = fc1.selectbox("Show", show_opts, key="lv_show")
    src_f = fc2.text_input("Source IP contains", key="lv_src")
    dst_f = fc3.text_input("Dest IP contains",   key="lv_dst")

    fc4, fc5, fc6 = st.columns(3)
    app_f  = fc4.text_input("Application contains", key="lv_appf")
    act_f  = fc5.selectbox("Action", ["Any", "allow", "deny", "drop",
                                       "reset-client", "reset-server"],
                            key="lv_act")
    limit  = fc6.number_input("Max rows", 100, 5000, 1000, step=100, key="lv_limit")

    url_cat_f = host_f_lv = ""
    URL_COLS = _rules_mod.URL_COLS
    if "url_category" in URL_COLS or "dst_hostname" in URL_COLS or "src_hostname" in URL_COLS:
        fc7, fc8, _ = st.columns(3)
        if "url_category" in URL_COLS:
            url_cat_f = fc7.text_input("URL Category contains", key="lv_urlcat")
        if "dst_hostname" in URL_COLS or "src_hostname" in URL_COLS:
            host_f_lv = fc8.text_input("Hostname contains", key="lv_host")

    # Build WHERE clauses
    extra = []
    if src_f: extra.append(f'"Source address" LIKE \'%{safe(src_f)}%\'')
    if dst_f: extra.append(f'"Destination address" LIKE \'%{safe(dst_f)}%\'')
    if app_f: extra.append(f'Application LIKE \'%{safe(app_f)}%\'')
    if act_f != "Any": extra.append(f"lower(Action) = '{safe(act_f)}'")
    if url_cat_f and "url_category" in URL_COLS:
        extra.append(f'"{URL_COLS["url_category"]}" LIKE \'%{safe(url_cat_f)}%\'')
    if host_f_lv:
        _hc = []
        if "dst_hostname" in URL_COLS:
            _hc.append(f'"{URL_COLS["dst_hostname"]}" LIKE \'%{safe(host_f_lv)}%\'')
        if "src_hostname" in URL_COLS:
            _hc.append(f'"{URL_COLS["src_hostname"]}" LIKE \'%{safe(host_f_lv)}%\'')
        if _hc:
            extra.append("(" + " OR ".join(_hc) + ")")
    base_where = "1=1" + dw + ((" AND " + " AND ".join(extra)) if extra else "")

    if show_filter == "Unclassified only":
        cls_filter = "AND _cls IS NULL"
    elif show_filter == "Classified only":
        cls_filter = "AND _cls IS NOT NULL"
    elif show_filter.startswith("App: "):
        cls_filter = f"AND _cls = '{safe(show_filter[5:])}'"
    else:
        cls_filter = ""

    # Build extra URL/hostname column selects
    _url_aliases: list[str] = []
    _url_inner = ""
    if "url_category" in URL_COLS:
        _url_inner += f', "{URL_COLS["url_category"]}" AS "URL Category"'
        _url_aliases.append('"URL Category"')
    if "dst_hostname" in URL_COLS:
        _url_inner += f', "{URL_COLS["dst_hostname"]}" AS "Destination Hostname"'
        _url_aliases.append('"Destination Hostname"')
    if "src_hostname" in URL_COLS:
        _url_inner += f', "{URL_COLS["src_hostname"]}" AS "Source Hostname"'
        _url_aliases.append('"Source Hostname"')
    _url_outer = (", " + ", ".join(_url_aliases)) if _url_aliases else ""

    # ── Table ─────────────────────────────────────────────────────────────
    lv_df = q(con, f"""
        WITH base AS (
            SELECT
                "Receive Time", "Source address", "Destination address",
                "Source Port", "Destination Port", Application,
                "IP Protocol", Action, Bytes, Rule,
                "Source Zone", "Destination Zone"
                {_url_inner},
                {cls_sql} AS _cls
            FROM traffic_logs WHERE {base_where}
        )
        SELECT
            "Receive Time",
            COALESCE(_cls, '— unclassified —') AS Classification,
            "Source address", "Destination address",
            "Source Port", "Destination Port",
            Application, "IP Protocol", Action, Bytes,
            Rule, "Source Zone", "Destination Zone"
            {_url_outer}
        FROM base
        WHERE 1=1 {cls_filter}
        ORDER BY "Receive Time" DESC, "Source address", "Destination address",
                 "Source Port", "Destination Port", Application
        LIMIT {int(limit)}
    """)

    unclass_count = (lv_df["Classification"] == "— unclassified —").sum()
    st.caption(
        f"{len(lv_df):,} rows shown — "
        f"{unclass_count:,} unclassified. "
        "Click a row to pre-fill Quick Classify below."
    )

    lv_sel = st.dataframe(
        lv_df, use_container_width=True, hide_index=True,
        selection_mode="single-row", on_select="rerun",
        key="lv_table",
        column_config={
            "Classification": st.column_config.TextColumn(
                "Classification", width="medium"
            ),
        },
    )
    lv_col_map: dict = {
        "src_ip":      "Source address",
        "dst_ip":      "Destination address",
        "dst_port":    "Destination Port",
        "application": "Application",
        "protocol":    "IP Protocol",
    }
    if "url_category" in URL_COLS:
        lv_col_map["url_category"] = "URL Category"
    if "dst_hostname" in URL_COLS:
        lv_col_map["dst_hostname"] = "Destination Hostname"
    if "src_hostname" in URL_COLS:
        lv_col_map["src_hostname"] = "Source Hostname"
    lv_prefill = row_prefill(lv_df, lv_sel.selection.rows, lv_col_map)
    quick_classify_panel("logview", lv_prefill)
