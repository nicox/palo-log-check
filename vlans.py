"""VLAN management helpers for Palo Alto Log Analyzer.

Defines CRUD helpers for vlans.json and SQL-generation functions that
translate CIDR subnets into DuckDB WHERE conditions.
"""

from pathlib import Path
import json

from db import safe

VLANS_FILE = Path(__file__).parent / "vlans.json"


def load_vlans() -> dict:
    """Load VLAN definitions (name → {description, subnets}) from vlans.json."""
    if VLANS_FILE.exists():
        with open(VLANS_FILE) as f:
            return json.load(f)
    return {}


def save_vlans(vlans: dict):
    """Persist VLAN definitions to vlans.json."""
    with open(VLANS_FILE, "w") as f:
        json.dump(vlans, f, indent=2)


def parse_subnet(s: str) -> tuple[str | None, str | None]:
    """Validate and normalise an IPv4 address or CIDR string.
    Returns (normalised, None) on success or (None, error_message) on failure."""
    s = s.strip()
    if not s:
        return None, None
    if "/" in s:
        ip_str, prefix_str = s.split("/", 1)
        ip_str = ip_str.strip()
        try:
            plen = int(prefix_str.strip())
            if not (0 <= plen <= 32):
                return None, f"'{s}': prefix length must be 0–32"
        except ValueError:
            return None, f"'{s}': invalid prefix length"
    else:
        ip_str = s
        plen = None
    octets = ip_str.split(".")
    if len(octets) != 4:
        return None, f"'{s}': expected 4 octets"
    for o in octets:
        try:
            n = int(o)
            if not (0 <= n <= 255):
                return None, f"'{s}': octet {o} out of range"
        except ValueError:
            return None, f"'{s}': invalid octet '{o}'"
    return (f"{ip_str}/{plen}" if plen is not None else ip_str), None


def vlan_sql(col: str, subnets: list[str]) -> str:
    """Build a SQL OR condition matching a column against a list of CIDR subnets/IPs."""
    parts = []
    for s in subnets:
        s = s.strip()
        if not s:
            continue
        if "/" in s:
            ip_str, prefix_str = s.split("/", 1)
            try:
                plen = int(prefix_str)
            except ValueError:
                continue
            octets = ip_str.split(".")
            if len(octets) != 4:
                continue
            full_octets = plen // 8
            if full_octets >= 4:
                parts.append(f'"{col}" = \'{safe(ip_str)}\'')
            elif plen % 8 == 0:
                prefix = ".".join(octets[:full_octets])
                parts.append(f'"{col}" LIKE \'{safe(prefix)}.%\'')
            else:
                # Non-octet boundary: match on the partial octet's prefix
                prefix = ".".join(octets[:full_octets + 1])
                parts.append(f'"{col}" LIKE \'{safe(prefix)}.%\'')
        else:
            parts.append(f'"{col}" = \'{safe(s)}\'')
    return ("(" + " OR ".join(parts) + ")") if parts else "FALSE"
