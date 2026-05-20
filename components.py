"""Reusable Streamlit UI components for Palo Alto Log Analyzer."""

import streamlit as st
import pandas as pd

import rules
from rules import load_app_defs, save_app_defs, parse_ports
from db import safe


def quick_classify_panel(tab_key: str, prefill: dict | None = None):
    """
    Inline panel to create a new classification or append a rule to an existing
    one. prefill keys: src_ip, dst_ip, src_port, dst_port, application, protocol.
    Including prefill values in widget keys forces Streamlit to recreate the
    inputs (with new defaults) whenever the selection changes.
    """
    prefill = prefill or {}
    # Including the prefill values in every widget key forces Streamlit to
    # destroy and recreate the inputs whenever the selected row changes, which
    # is the only reliable way to update default values mid-session.
    pk = str(abs(hash(frozenset((k, str(v)) for k, v in prefill.items()))))

    with st.expander("Quick Classify — save this traffic pattern as an application"):
        app_defs_c = load_app_defs()
        mode = st.radio(
            "Action",
            ["New classification", "Add rule to existing"],
            key=f"qc_mode_{tab_key}",
            horizontal=True,
        )

        if mode == "New classification":
            app_name = st.text_input("Application name", key=f"qc_name_{tab_key}_{pk}")
        else:
            if not app_defs_c:
                st.info("No classifications yet — create one in the Classification tab first.")
                return
            app_name = st.selectbox(
                "Add rule to", list(app_defs_c.keys()), key=f"qc_sel_{tab_key}"
            )

        if prefill:
            st.caption("Pre-filled from selected row — edit as needed.")
        st.markdown("*Matching criteria — leave blank to match anything:*")

        c1, c2, c3 = st.columns(3)
        sp    = c1.text_input("Source port(s)",  key=f"qc_sp_{tab_key}_{pk}",
                              value=str(prefill.get("src_port",    "")))
        dp    = c2.text_input("Dest port(s)",    key=f"qc_dp_{tab_key}_{pk}",
                              value=str(prefill.get("dst_port",    "")))
        app_v = c3.text_input("Application(s)",  key=f"qc_app_{tab_key}_{pk}",
                              value=str(prefill.get("application", "")))
        c4, c5, c6 = st.columns(3)
        proto  = c4.text_input("Protocol(s)",    key=f"qc_proto_{tab_key}_{pk}",
                               value=str(prefill.get("protocol",   "")))
        src_ip = c5.text_input("Source IP(s)",   key=f"qc_sip_{tab_key}_{pk}",
                               value=str(prefill.get("src_ip",     "")))
        dst_ip = c6.text_input("Dest IP(s)",     key=f"qc_dip_{tab_key}_{pk}",
                               value=str(prefill.get("dst_ip",     "")))

        qc_url_cat = qc_host = ""
        if rules.URL_COLS:
            c7, c8 = st.columns(2)
            if "url_category" in rules.URL_COLS:
                qc_url_cat = c7.text_input(
                    "URL Category",
                    key=f"qc_urlcat_{tab_key}_{pk}",
                    value=str(prefill.get("url_category", "")),
                    placeholder="e.g. business-and-economy",
                )
            if "dst_hostname" in rules.URL_COLS or "src_hostname" in rules.URL_COLS:
                qc_host = c8.text_input(
                    "Hostname(s)",
                    key=f"qc_host_{tab_key}_{pk}",
                    value=str(prefill.get("dst_hostname", prefill.get("src_hostname", ""))),
                    placeholder="e.g. teams.microsoft.com",
                )

        if st.button("Save Rule", key=f"qc_save_{tab_key}"):
            name = (app_name or "").strip()
            if not name:
                st.error("Application name is required.")
                return
            rule: dict = {}
            if sp.strip():          rule["src_ports"]     = [x.strip() for x in sp.split(",")         if x.strip()]
            if dp.strip():          rule["dst_ports"]     = [x.strip() for x in dp.split(",")         if x.strip()]
            if app_v.strip():       rule["applications"]  = [x.strip() for x in app_v.split(",")      if x.strip()]
            if proto.strip():       rule["protocols"]     = [x.strip() for x in proto.split(",")      if x.strip()]
            if src_ip.strip():      rule["src_ips"]       = [x.strip() for x in src_ip.split(",")     if x.strip()]
            if dst_ip.strip():      rule["dst_ips"]       = [x.strip() for x in dst_ip.split(",")     if x.strip()]
            if qc_url_cat.strip():  rule["url_categories"]= [x.strip() for x in qc_url_cat.split(",") if x.strip()]
            if qc_host.strip():     rule["hostnames"]     = [x.strip() for x in qc_host.split(",")    if x.strip()]
            if not rule:
                st.error("Add at least one criterion.")
                return
            port_errors = []
            for field, label in [("src_ports", "Source port"), ("dst_ports", "Dest port")]:
                if rule.get(field):
                    _, bad = parse_ports(rule[field])
                    if bad:
                        port_errors.append(f"{label}: '{', '.join(bad)}' not valid")
            if port_errors:
                for e in port_errors:
                    st.error(e)
                return
            defs = load_app_defs()
            if name in defs:
                defs[name]["rules"].append(rule)
            else:
                defs[name] = {"description": "", "rules": [rule]}
            save_app_defs(defs)
            st.success(f"Rule saved to '{name}'")


def row_prefill(df: pd.DataFrame, selected_rows: list, col_map: dict) -> dict:
    """Extract prefill dict from a selected dataframe row."""
    if not selected_rows:
        return {}
    row = df.iloc[selected_rows[0]]
    result = {}
    for prefill_key, col_name in col_map.items():
        val = row.get(col_name, "")
        if val is not None and str(val) not in ("", "nan", "None"):
            result[prefill_key] = str(val)
    return result
