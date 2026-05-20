import streamlit as st
import pandas as pd

from db import q, NO_DATA
from vlans import load_vlans, save_vlans, parse_subnet, vlan_sql


def render(con, dw, has_data):
    st.header("VLAN Management")
    st.markdown(
        "Define VLANs with their IP subnets. "
        "Once defined, select a VLAN in the sidebar to filter all tabs to traffic "
        "originating from or destined to that VLAN."
    )

    vlans = load_vlans()

    # ── Pre-widget state mutations ────────────────────────────────────────────
    if "vlan_editing" not in st.session_state:
        st.session_state["vlan_editing"] = None

    if st.session_state.pop("_vlan_pending_clear", False):
        st.session_state["vlan_editing"] = None
        st.session_state["vlan_name"]    = ""
        st.session_state["vlan_desc"]    = ""
        st.session_state["vlan_subnets"] = ""

    if "_vlan_pending_edit" in st.session_state:
        _vpe_name, _vpe_defn = st.session_state.pop("_vlan_pending_edit")
        st.session_state["vlan_editing"] = _vpe_name
        st.session_state["vlan_name"]    = _vpe_name
        st.session_state["vlan_desc"]    = _vpe_defn.get("description", "")
        st.session_state["vlan_subnets"] = "\n".join(_vpe_defn.get("subnets", []))

    vlan_editing = st.session_state["vlan_editing"]

    # ── Add / Edit form ───────────────────────────────────────────────────────
    st.subheader("Edit VLAN" if vlan_editing else "Add VLAN")
    if vlan_editing:
        st.info(f"Editing **{vlan_editing}** — save to apply or cancel to discard.")
        if st.button("Cancel", key="vlan_cancel"):
            st.session_state["_vlan_pending_clear"] = True
            st.rerun()

    vlan_name_v    = st.text_input("VLAN name", key="vlan_name", placeholder="e.g. Management")
    vlan_desc_v    = st.text_input("Description", key="vlan_desc", placeholder="e.g. Server management network")
    vlan_subnets_v = st.text_area(
        "Subnets (one per line or comma-separated)",
        key="vlan_subnets",
        height=120,
        placeholder="10.1.0.0/24\n10.1.1.0/24",
    )

    if st.button("Save VLAN", key="vlan_save"):
        name = vlan_name_v.strip()
        if not name:
            st.error("VLAN name is required.")
        else:
            raw = [s.strip() for s in vlan_subnets_v.replace(",", "\n").splitlines() if s.strip()]
            if not raw:
                st.error("Add at least one subnet.")
            else:
                errors, good = [], []
                for s in raw:
                    norm, err = parse_subnet(s)
                    if err:
                        errors.append(err)
                    elif norm:
                        good.append(norm)
                if errors:
                    for e in errors:
                        st.error(e)
                else:
                    if vlan_editing and vlan_editing != name and vlan_editing in vlans:
                        del vlans[vlan_editing]
                    vlans[name] = {"description": vlan_desc_v.strip(), "subnets": good}
                    save_vlans(vlans)
                    st.session_state["_vlan_pending_clear"] = True
                    st.rerun()

    # ── Import from CSV / text ────────────────────────────────────────────────
    st.markdown("---")
    with st.expander("Import VLANs from file"):
        st.markdown(
            "Upload a CSV or text file. Supported formats:\n"
            "- **One VLAN per line:** `VLAN Name, 10.0.0.0/24, 10.0.1.0/24`\n"
            "- **CSV with header `Name,Subnets`:** subnets comma-separated in the second column\n"
            "- **CSV with header `Name,Subnet`:** one subnet per row (rows with the same name are merged)"
        )
        imp_file = st.file_uploader("Upload file", type=["csv", "txt"], key="vlan_import_file")
        imp_mode = st.radio(
            "On conflict",
            ["Merge subnets into existing VLAN", "Overwrite existing VLAN"],
            key="vlan_imp_mode",
            horizontal=True,
        )
        if imp_file and st.button("Import", key="vlan_import_btn"):
            text  = imp_file.getvalue().decode("utf-8", errors="replace")
            lines = [l.strip() for l in text.splitlines() if l.strip()]
            imported: dict[str, list[str]] = {}
            parse_errors: list[str] = []
            skip_header = False

            if lines and lines[0].lower().replace(" ", "").startswith("name,"):
                skip_header = True

            for lineno, line in enumerate(lines, 1):
                if skip_header and lineno == 1:
                    continue
                parts = [p.strip() for p in line.split(",")]
                if len(parts) < 2:
                    continue
                vname = parts[0].strip('"').strip()
                subnets_raw = [s.strip('"').strip() for s in parts[1:] if s.strip('"').strip()]
                if not vname:
                    continue
                for s in subnets_raw:
                    norm, err = parse_subnet(s)
                    if err:
                        parse_errors.append(f"Line {lineno}: {err}")
                    elif norm:
                        imported.setdefault(vname, []).append(norm)

            if parse_errors:
                for e in parse_errors[:10]:
                    st.error(e)
                if len(parse_errors) > 10:
                    st.error(f"… and {len(parse_errors) - 10} more errors.")
            else:
                current = load_vlans()
                added, updated = 0, 0
                for vname, subnets in imported.items():
                    if vname in current:
                        if imp_mode.startswith("Merge"):
                            existing = current[vname].get("subnets", [])
                            current[vname]["subnets"] = list(dict.fromkeys(existing + subnets))
                        else:
                            current[vname] = {"description": "", "subnets": subnets}
                        updated += 1
                    else:
                        current[vname] = {"description": "", "subnets": subnets}
                        added += 1
                save_vlans(current)
                st.success(f"Imported: {added} new VLAN(s), {updated} updated.")
                st.rerun()

    # ── Defined VLANs list ────────────────────────────────────────────────────
    if vlans:
        st.markdown("---")
        st.subheader("Defined VLANs")
        for vname, vdefn in list(vlans.items()):
            subnets = vdefn.get("subnets", [])
            desc    = vdefn.get("description", "")
            label   = (f"**{vname}**" + (f" — {desc}" if desc else "") +
                       f"  ({len(subnets)} subnet{'s' if len(subnets) != 1 else ''})")
            with st.expander(label):
                st.write(", ".join(subnets) if subnets else "*(no subnets)*")
                vc1, vc2, _ = st.columns([1, 1, 5])
                if vc1.button("Edit", key=f"vlan_edit_{vname}"):
                    st.session_state["_vlan_pending_edit"] = (vname, vdefn)
                    st.rerun()
                if vc2.button("Delete", key=f"vlan_del_{vname}"):
                    del vlans[vname]
                    save_vlans(vlans)
                    if vlan_editing == vname:
                        st.session_state["_vlan_pending_clear"] = True
                    st.rerun()

        if has_data:
            st.markdown("---")
            st.subheader("VLAN Traffic Summary")
            vlan_rows = []
            for vname, vdefn in vlans.items():
                subnets = vdefn.get("subnets", [])
                if not subnets:
                    continue
                src_c = vlan_sql("Source address", subnets)
                dst_c = vlan_sql("Destination address", subnets)
                r = q(con, f"""
                    SELECT
                        COUNT(*) AS Sessions,
                        SUM(Bytes) AS Bytes,
                        COUNT(DISTINCT "Source address") AS Sources,
                        COUNT(DISTINCT "Destination address") AS Destinations
                    FROM traffic_logs
                    WHERE ({src_c} OR {dst_c}){dw}
                """).iloc[0]
                vlan_rows.append({
                    "VLAN":         vname,
                    "Description":  vdefn.get("description", ""),
                    "Subnets":      len(subnets),
                    "Sessions":     int(r.Sessions or 0),
                    "Bytes":        r.Bytes,
                    "Sources":      int(r.Sources or 0),
                    "Destinations": int(r.Destinations or 0),
                })
            if vlan_rows:
                vdf = pd.DataFrame(vlan_rows).sort_values("Bytes", ascending=False)
                st.dataframe(vdf, use_container_width=True, hide_index=True)
    else:
        st.info("No VLANs defined yet — add one above or import from a file.")
