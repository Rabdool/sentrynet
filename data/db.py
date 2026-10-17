"""Database connection and initialisation for the data layer.

Uses SQLite so the platform runs on a single lab host with no server to
administer; the schema in ``schema.sql`` is kept portable to MySQL.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA_PATH = Path(__file__).with_name("schema.sql")


def get_connection(db_path: str = ":memory:") -> sqlite3.Connection:
    """Open a connection with row access by name and foreign keys enforced."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(conn: sqlite3.Connection, schema_path: Path = SCHEMA_PATH) -> sqlite3.Connection:
    """Create the tables defined in ``schema.sql`` if they do not yet exist."""
    conn.executescript(Path(schema_path).read_text(encoding="utf-8"))
    conn.commit()
    return conn
