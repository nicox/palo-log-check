import streamlit as st
import plotly.express as px
import pandas as pd

from db import q, safe, NO_DATA
from rules import (
    load_app_defs, save_app_defs, parse_ports,
    app_def_sql, build_classify_sql,
)


def render(con, dw, has_data):
    st.header("Traffic Classification")
    st.markdown(
        "Define what traffic belongs to each application using any combination of "
        "source/destination ports, Palo Alto application names, and IP protocols. "
        "Rows matching **any** rule are classified as that application."
    )

    app_defs = load_app_defs()

    # ── Initialise session state keys (must run before any widget renders) ────
    if "editing" not in st.session_state:
        st.session_state["editing"] = None

    # ── Pre-widget state mutations ────────────────────────────────────────────
    # Streamlit raises StreamlitAPIException if you write to a widget's session-
    # state key after that widget has already rendered in the current run.  To
    # pre-populate or clear the form we therefore use a two-run staging pattern:
    # set a _pending_* flag on run N, then read and apply it here at the very
    # top of run N+1, before any widget in this tab is instantiated.
    if st.session_state.pop("_pending_clear", False):
        st.session_state["editing"]   = None
        st.session_state["def_name"]  = ""
        st.session_state["def_desc"]  = ""
        st.session_state["num_rules"] = 1
        for _i in range(10):
            for _k in [f"sp_{_i}", f"dp_{_i}", f"app_{_i}",
                       f"proto_{_i}", f"sip_{_i}", f"dip_{_i}",
                       f"url_cat_{_i}", f"app_cat_{_i}", f"subcat_{_i}", f"host_{_i}"]:
                st.session_state[_k] = ""

    # Pending edit: pre-populate the form with a saved definition
    if "_pending_edit" in st.session_state:
        _pe_name, _pe_defn = st.session_state.pop("_pending_edit")
        st.session_state["editing"]   = _pe_name
        st.session_state["def_name"]  = _pe_name
        st.session_state["def_desc"]  = _pe_defn.get("description", "")
        _pe_rules = _pe_defn.get("rules", [{}])
        st.session_state["num_rules"] = len(_pe_rules)
        for _i, _r in enumerate(_pe_rules):
            st.session_state[f"sp_{_i}"]      = ",".join(str(p) for p in _r.get("src_ports",    []))
            st.session_state[f"dp_{_i}"]      = ",".join(str(p) for p in _r.get("dst_ports",    []))
            st.session_state[f"app_{_i}"]     = ",".join(_r.get("applications",  []))
            st.session_state[f"proto_{_i}"]   = ",".join(_r.get("protocols",     []))
            st.session_state[f"sip_{_i}"]     = ",".join(_r.get("src_ips",       []))
            st.session_state[f"dip_{_i}"]     = ",".join(_r.get("dst_ips",       []))
            st.session_state[f"url_cat_{_i}"] = ",".join(_r.get("url_categories",[]))
            st.session_state[f"app_cat_{_i}"] = ",".join(_r.get("app_categories", []))
            st.session_state[f"subcat_{_i}"]  = ",".join(_r.get("subcategories",  []))
            st.session_state[f"host_{_i}"]    = ",".join(_r.get("hostnames",      []))

    editing = st.session_state["editing"]

    # ── Add / Edit form ───────────────────────────────────────────────────────
    import rules as _rules_mod
    st.subheader("Edit Application Definition" if editing else "Add Application Definition")

    if editing:
        st.info(f"Editing **{editing}** — save to apply changes or cancel to discard.")
        if st.button("Cancel", key="cancel_edit"):
            st.session_state["_pending_clear"] = True
            st.rerun()

    def_name = st.text_input("Application name (e.g. SAP ERP)", key="def_name")
    def_desc = st.text_area("Description / notes", key="def_desc", height=60)

    st.markdown("**Rules** — leave a field blank to match anything in that field. "
                "All filled fields in a rule must match (AND). Any rule can match (OR).")
    num_rules = st.number_input("Number of rules", 1, 10, 1, key="num_rules")
    new_rules = []
    for i in range(int(num_rules)):
        st.markdown(f"*Rule {i + 1}*")
        r1 = st.columns(3)
        sp    = r1[0].text_input("Source port(s)",  key=f"sp_{i}",    placeholder="e.g. 1234")
        dp    = r1[1].text_input("Dest port(s)",    key=f"dp_{i}",    placeholder="e.g. 443,8443")
        apps  = r1[2].text_input("Application(s)",  key=f"app_{i}",   placeholder="e.g. ssl,http")
        r2 = st.columns(3)
        proto  = r2[0].text_input("Protocol(s)",    key=f"proto_{i}", placeholder="e.g. tcp,udp")
        src_ip = r2[1].text_input("Source IP(s)",   key=f"sip_{i}",   placeholder="e.g. 10.82.1.5")
        dst_ip = r2[2].text_input("Dest IP(s)",     key=f"dip_{i}",   placeholder="e.g. 10.93.0.0/16")
        url_cat_v = app_cat_v = subcat_v = host_v = ""
        if _rules_mod.URL_COLS:
            r3 = st.columns(4)
            if "url_category" in _rules_mod.URL_COLS:
                url_cat_v = r3[0].text_input("URL Category",    key=f"url_cat_{i}", placeholder="e.g. business-and-economy")
            if "app_category" in _rules_mod.URL_COLS:
                app_cat_v = r3[1].text_input("App Category",    key=f"app_cat_{i}", placeholder="e.g. saas-and-web")
            if "subcategory" in _rules_mod.URL_COLS:
                subcat_v  = r3[2].text_input("App Subcategory", key=f"subcat_{i}",  placeholder="e.g. collaboration")
            if "dst_hostname" in _rules_mod.URL_COLS or "src_hostname" in _rules_mod.URL_COLS:
                host_v    = r3[3].text_input("Hostname(s)",     key=f"host_{i}",    placeholder="e.g. teams.microsoft.com")
        rule: dict = {}
        if sp.strip():          rule["src_ports"]     = [x.strip() for x in sp.split(",")         if x.strip()]
        if dp.strip():          rule["dst_ports"]     = [x.strip() for x in dp.split(",")         if x.strip()]
        if apps.strip():        rule["applications"]  = [x.strip() for x in apps.split(",")       if x.strip()]
        if proto.strip():       rule["protocols"]     = [x.strip() for x in proto.split(",")      if x.strip()]
        if src_ip.strip():      rule["src_ips"]       = [x.strip() for x in src_ip.split(",")     if x.strip()]
        if dst_ip.strip():      rule["dst_ips"]       = [x.strip() for x in dst_ip.split(",")     if x.strip()]
        if url_cat_v.strip():   rule["url_categories"]= [x.strip() for x in url_cat_v.split(",")  if x.strip()]
        if app_cat_v.strip():   rule["app_categories"]= [x.strip() for x in app_cat_v.split(",")  if x.strip()]
        if subcat_v.strip():    rule["subcategories"] = [x.strip() for x in subcat_v.split(",")   if x.strip()]
        if host_v.strip():      rule["hostnames"]     = [x.strip() for x in host_v.split(",")     if x.strip()]
        new_rules.append(rule)

    if st.button("Save Definition"):
        if not def_name.strip():
            st.error("Name is required.")
        else:
            errors = []
            for i, rule in enumerate(new_rules):
                for field, label in [("src_ports", "Source port"), ("dst_ports", "Dest port")]:
                    if rule.get(field):
                        _, bad = parse_ports(rule[field])
                        if bad:
                            errors.append(
                                f"Rule {i+1} — {label}: **{', '.join(bad)}** "
                                f"{'is' if len(bad) == 1 else 'are'} not valid "
                                f"port number(s). Ports must be integers 0–65535."
                            )
            if errors:
                for e in errors:
                    st.error(e)
            else:
                new_name = def_name.strip()
                if editing and editing != new_name and editing in app_defs:
                    del app_defs[editing]
                app_defs[new_name] = {"description": def_desc, "rules": new_rules}
                save_app_defs(app_defs)
                st.session_state["_pending_clear"] = True
                st.rerun()

    # ── Defined applications list ─────────────────────────────────────────────
    if app_defs:
        st.markdown("---")
        st.subheader("Defined Applications")
        for name, defn in list(app_defs.items()):
            with st.expander(f"**{name}** — {defn.get('description', '')}"):
                st.json(defn["rules"])
                col_edit, col_del, _ = st.columns([1, 1, 5])
                if col_edit.button("Edit", key=f"edit_{name}"):
                    # Stage the definition; it will be loaded at the top on next run
                    st.session_state["_pending_edit"] = (name, defn)
                    st.rerun()
                if col_del.button("Delete", key=f"del_{name}"):
                    del app_defs[name]
                    save_app_defs(app_defs)
                    if editing == name:
                        st.session_state["_pending_clear"] = True
                    st.rerun()

        if has_data:
            st.subheader("Classification Results")
            _cls_parts = []
            for _cls_name, _cls_defn in app_defs.items():
                _cls_expr = app_def_sql(_cls_defn["rules"])
                _cls_parts.append(f"""
                    SELECT '{safe(_cls_name)}' AS app_name,
                           COUNT(*) AS s, SUM(Bytes) AS b,
                           COUNT(DISTINCT "Source address")      AS src,
                           COUNT(DISTINCT "Destination address") AS dst
                    FROM traffic_logs WHERE ({_cls_expr}){dw}
                """)
            _cls_raw = q(con, " UNION ALL ".join(_cls_parts))
            results = [
                {
                    "Application": row["app_name"],
                    "Sessions":    int(row["s"] or 0),
                    "Bytes":       row["b"],
                    "Sources":     int(row["src"] or 0),
                    "Destinations":int(row["dst"] or 0),
                    "Description": app_defs[row["app_name"]].get("description", ""),
                }
                for _, row in _cls_raw.iterrows()
            ]
            res_df = pd.DataFrame(results).sort_values("Bytes", ascending=False)
            st.dataframe(res_df, use_container_width=True, hide_index=True)

            drill = st.selectbox("Drill into classified app",
                                 [""] + list(app_defs.keys()), key="cls_drill")
            if drill:
                expr = app_def_sql(app_defs[drill]["rules"])
                detail = q(con, f"""
                    SELECT "Receive Time", "Source address", "Destination address",
                           "Source Port", "Destination Port", Application,
                           "IP Protocol", Action, Bytes, Rule
                    FROM traffic_logs WHERE ({expr}){dw}
                    ORDER BY Bytes DESC LIMIT 500
                """)
                st.dataframe(detail, use_container_width=True, hide_index=True)
    elif has_data:
        st.info("No application definitions yet — add one above.")
