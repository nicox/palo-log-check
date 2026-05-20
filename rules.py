"""Application classification rules for Palo Alto Log Analyzer.

Defines CRUD helpers for app_definitions.json and SQL-generation functions
that translate rule dicts into DuckDB WHERE conditions.

URL_COLS is a module-level dict populated by app.py after the database
connection is established:

    import rules
    rules.URL_COLS = get_url_cols(con)

Functions in this module read it as a global so callers need not pass it.
"""

from pathlib import Path
import json

from db import safe

APP_DEFS_FILE = Path(__file__).parent / "app_definitions.json"

URL_COLS: dict = {}  # set by app.py at startup after DB initialisation


def load_app_defs() -> dict:
    """Load application classification definitions from app_definitions.json."""
    if APP_DEFS_FILE.exists():
        with open(APP_DEFS_FILE) as f:
            return json.load(f)
    return {}


def save_app_defs(defs: dict):
    """Persist application classification definitions to app_definitions.json."""
    with open(APP_DEFS_FILE, "w") as f:
        json.dump(defs, f, indent=2)


def parse_ports(raw: list) -> tuple[list[int], list[str]]:
    """Split port strings into valid integers and invalid entries."""
    valid, invalid = [], []
    for p in raw:
        try:
            n = int(str(p).strip())
            if 0 <= n <= 65535:
                valid.append(n)
            else:
                invalid.append(str(p))
        except ValueError:
            invalid.append(str(p))
    return valid, invalid


def ip_condition(col: str, ips: list[str]) -> str:
    """Build a SQL condition for a list of IPs (exact) or CIDR prefixes (prefix match).
    Uses the same octet-boundary LIKE strategy as vlan_sql."""
    exact, prefix = [], []
    for ip in ips:
        if "/" in ip:
            ip_str, prefix_str = ip.split("/", 1)
            try:
                plen = int(prefix_str)
            except ValueError:
                continue
            octets = ip_str.split(".")
            if len(octets) != 4:
                continue
            full_octets = plen // 8
            if full_octets >= 4:
                exact.append(f"'{safe(ip_str)}'")
            elif plen % 8 == 0:
                net = ".".join(octets[:full_octets])
                prefix.append(f'"{col}" LIKE \'{safe(net)}.%\'')
            else:
                # Non-octet boundary: include the partial octet for a tighter match.
                net = ".".join(octets[:full_octets + 1])
                prefix.append(f'"{col}" LIKE \'{safe(net)}.%\'')
        else:
            exact.append(f"'{safe(ip)}'")
    parts = []
    if exact:
        parts.append(f'"{col}" IN ({",".join(exact)})')
    parts.extend(prefix)
    return "(" + " OR ".join(parts) + ")" if parts else "TRUE"


def app_def_sql(rule_list: list) -> str:
    """Convert an app-definition rule list into a SQL boolean expression.
    Rules are OR-ed together; conditions within a rule are AND-ed.
    Returns 'FALSE' for an empty rule list, 'TRUE' if rules have no conditions."""
    if not rule_list:
        return "FALSE"
    parts = []
    for rule in rule_list:
        conds = []
        if rule.get("src_ports"):
            valid, _ = parse_ports(rule["src_ports"])
            if valid:
                conds.append(f'"Source Port" IN ({",".join(str(p) for p in valid)})')
        if rule.get("dst_ports"):
            valid, _ = parse_ports(rule["dst_ports"])
            if valid:
                conds.append(f'"Destination Port" IN ({",".join(str(p) for p in valid)})')
        if rule.get("applications"):
            vals = ",".join(f"'{a.lower()}'" for a in rule["applications"])
            conds.append(f"lower(Application) IN ({vals})")
        if rule.get("protocols"):
            vals = ",".join(f"'{p.lower()}'" for p in rule["protocols"])
            conds.append(f'lower("IP Protocol") IN ({vals})')
        if rule.get("src_ips"):
            conds.append(ip_condition("Source address", rule["src_ips"]))
        if rule.get("dst_ips"):
            conds.append(ip_condition("Destination address", rule["dst_ips"]))
        if rule.get("url_categories") and "url_category" in URL_COLS:
            vals = ",".join(f"'{safe(v)}'" for v in rule["url_categories"])
            conds.append(f'"{URL_COLS["url_category"]}" IN ({vals})')
        if rule.get("app_categories") and "app_category" in URL_COLS:
            vals = ",".join(f"'{safe(v)}'" for v in rule["app_categories"])
            conds.append(f'"{URL_COLS["app_category"]}" IN ({vals})')
        if rule.get("subcategories") and "subcategory" in URL_COLS:
            vals = ",".join(f"'{safe(v)}'" for v in rule["subcategories"])
            conds.append(f'"{URL_COLS["subcategory"]}" IN ({vals})')
        if rule.get("hostnames"):
            host_conds = []
            for h in rule["hostnames"]:
                hs = safe(h)
                if "dst_hostname" in URL_COLS:
                    host_conds.append(f'"{URL_COLS["dst_hostname"]}" LIKE \'%{hs}%\'')
                if "src_hostname" in URL_COLS:
                    host_conds.append(f'"{URL_COLS["src_hostname"]}" LIKE \'%{hs}%\'')
            if host_conds:
                conds.append("(" + " OR ".join(host_conds) + ")")
        if conds:
            parts.append("(" + " AND ".join(conds) + ")")
    return " OR ".join(parts) if parts else "TRUE"


def build_classify_sql(app_defs: dict) -> str:
    """Build a CASE expression returning the first matching classification name or NULL."""
    if not app_defs:
        return "NULL"
    cases = []
    for name, defn in app_defs.items():
        expr = app_def_sql(defn.get("rules", []))
        if expr not in ("FALSE", "TRUE"):
            cases.append(f"WHEN ({expr}) THEN '{safe(name)}'")
    return ("CASE " + " ".join(cases) + " ELSE NULL END") if cases else "NULL"
