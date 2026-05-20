"""Database utilities for Palo Alto Log Analyzer.

Provides the DuckDB connection, table helpers, CSV import logic, and low-level
query utilities.  The only Streamlit dependency here is the @st.cache_resource
decorator on get_db().
"""

from pathlib import Path
import os

import streamlit as st
import pandas as pd
import duckdb

DB_PATH = Path(__file__).parent / "logs.duckdb"
NO_DATA = "No log data in the database yet — use the sidebar to import a CSV file."


@st.cache_resource
def get_db():
    """Open (or create) the DuckDB database. cache_resource means one shared
    connection is reused across all Streamlit sessions in the same process."""
    con = duckdb.connect(str(DB_PATH))
    con.execute("""
        CREATE TABLE IF NOT EXISTS import_history (
            file_key    TEXT PRIMARY KEY,
            filename    TEXT,
            imported_at TIMESTAMP DEFAULT current_timestamp,
            row_count   BIGINT
        )
    """)
    return con


def logs_exist(con) -> bool:
    """Return True if the traffic_logs table exists and has at least one row.
    Uses try/except rather than information_schema because the table may not
    exist at all on a fresh database."""
    try:
        con.execute("SELECT 1 FROM traffic_logs LIMIT 1")
        return True
    except Exception:
        return False


def total_rows(con) -> int:
    """Return the total number of rows in traffic_logs, or 0 if none exist."""
    if not logs_exist(con):
        return 0
    row = con.execute("SELECT COUNT(*) FROM traffic_logs").fetchone()
    return row[0] if row else 0


def get_ts_expr(con) -> str:
    """Return a SQL expression that yields 'Receive Time' as TIMESTAMP.
    DuckDB's read_csv_auto may already parse the column as TIMESTAMP, in which
    case TRY_STRPTIME (which requires VARCHAR) would fail.

    Detection is done in two stages:
    1. Metadata check via duckdb_columns() — fast but the type name varies
       across DuckDB versions (TIMESTAMP, TIMESTAMP_S, TIMESTAMP WITH TIME ZONE…).
    2. Runtime probe — actually execute TRY_STRPTIME on a sample row; if DuckDB
       raises a BinderException the column is already a TIMESTAMP, so return the
       bare column reference instead."""
    if not logs_exist(con):
        return '"Receive Time"'
    # Stage 1: metadata
    try:
        row = con.execute("""
            SELECT data_type FROM duckdb_columns()
            WHERE table_name='traffic_logs' AND column_name='Receive Time'
        """).fetchone()
        if row and "TIMESTAMP" in str(row[0]).upper():
            return '"Receive Time"'
    except Exception:
        pass
    # Stage 2: runtime probe — TRY_STRPTIME requires VARCHAR; it raises a
    # BinderException if the column is already a TIMESTAMP type.
    try:
        con.execute(
            "SELECT TRY_STRPTIME(\"Receive Time\", '%Y/%m/%d %H:%M:%S') "
            "FROM traffic_logs LIMIT 1"
        )
        return "TRY_STRPTIME(\"Receive Time\", '%Y/%m/%d %H:%M:%S')"
    except Exception:
        return '"Receive Time"'


def get_url_cols(con) -> dict:
    """Detect which URL/hostname columns exist and have meaningful (non-null, non-zero) data.
    Returns a dict mapping role key → actual column name."""
    if not logs_exist(con):
        return {}
    candidates = {
        "url_category": "Category",
        "app_category": "Category of app",
        "subcategory":  "Subcategory of app",
        "dst_hostname": "Destination Hostname",
        "src_hostname": "Source Hostname",
    }
    result = {}
    try:
        existing = {
            row[0] for row in
            con.execute(
                "SELECT column_name FROM duckdb_columns() WHERE table_name='traffic_logs'"
            ).fetchall()
        }
        for role, col in candidates.items():
            if col not in existing:
                continue
            row = con.execute(f"""
                SELECT 1 FROM traffic_logs
                WHERE "{col}" IS NOT NULL
                  AND CAST("{col}" AS VARCHAR) NOT IN ('', '0', '0.0')
                LIMIT 1
            """).fetchone()
            if row is not None:
                result[role] = col
    except Exception:
        pass
    return result


def q(con, sql: str) -> pd.DataFrame:
    """Execute a SQL string and return the result as a pandas DataFrame."""
    return con.execute(sql).df()


def fmt_bytes(b) -> str:
    """Human-readable byte size (e.g. 1.23 GB). Returns '—' for None/NaN."""
    if b is None or (isinstance(b, float) and pd.isna(b)):
        return "—"
    b = float(b)
    if b >= 1e9: return f"{b/1e9:.2f} GB"
    if b >= 1e6: return f"{b/1e6:.2f} MB"
    if b >= 1e3: return f"{b/1e3:.1f} KB"
    return f"{b:.0f} B"


def safe(s: str) -> str:
    """Escape single quotes for inline SQL strings."""
    return s.replace("'", "''")


def import_file(con, file_path: str, filename: str, file_size: int) -> dict:
    """Import a CSV into traffic_logs using DuckDB's read_csv_auto (no RAM load).
    Deduplication key is filename::filesize — reimporting the same file is a no-op.
    Returns a dict with keys: status ('ok'|'skipped'|'error'), and context fields."""
    file_key = f"{filename}::{file_size}"
    if con.execute("SELECT COUNT(*) FROM import_history WHERE file_key=?", [file_key]).fetchone()[0]:
        return {"status": "skipped", "reason": f"'{filename}' is already in the database."}
    before = total_rows(con)
    try:
        escaped = file_path.replace("'", "''")
        if not logs_exist(con):
            con.execute(f"""
                CREATE TABLE traffic_logs AS
                SELECT * FROM read_csv_auto('{escaped}', ignore_errors=true, header=true)
            """)
        else:
            con.execute(f"""
                INSERT INTO traffic_logs
                SELECT * FROM read_csv_auto('{escaped}', ignore_errors=true, header=true)
            """)
    except Exception as e:
        return {"status": "error", "reason": str(e)}
    after = total_rows(con)
    added = after - before
    con.execute(
        "INSERT OR REPLACE INTO import_history (file_key, filename, row_count) VALUES (?,?,?)",
        [file_key, filename, added],
    )
    return {"status": "ok", "rows_added": added, "total": after}
