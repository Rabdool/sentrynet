"""Data-access helpers for the SentryNet store.

Thin wrappers over the four tables in ``schema.sql`` so the honeypot,
alerting and dashboard layers never embed SQL of their own.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --- writes -----------------------------------------------------------------

def add_service(conn: sqlite3.Connection, name: str, protocol: str, port: int) -> int:
    cur = conn.execute(
        "INSERT INTO honeypot_service (name, protocol, port) VALUES (?, ?, ?)",
        (name, protocol, port),
    )
    conn.commit()
    return cur.lastrowid


def start_session(conn: sqlite3.Connection, service_id: int, src_ip: str) -> int:
    cur = conn.execute(
        "INSERT INTO attack_session (service_id, src_ip) VALUES (?, ?)",
        (service_id, src_ip),
    )
    conn.commit()
    return cur.lastrowid


def end_session(conn: sqlite3.Connection, session_id: int) -> None:
    conn.execute(
        "UPDATE attack_session SET ended_at = ? WHERE id = ?", (_now(), session_id)
    )
    conn.commit()


def log_event(
    conn: sqlite3.Connection, session_id: int, event_type: str, detail: str | None = None
) -> int:
    cur = conn.execute(
        "INSERT INTO attack_log (session_id, event_type, detail) VALUES (?, ?, ?)",
        (session_id, event_type, detail),
    )
    conn.commit()
    return cur.lastrowid


def create_alert(conn: sqlite3.Connection, log_id: int, severity: str, message: str) -> int:
    cur = conn.execute(
        "INSERT INTO alert (log_id, severity, message) VALUES (?, ?, ?)",
        (log_id, severity, message),
    )
    conn.commit()
    return cur.lastrowid


def acknowledge_alert(conn: sqlite3.Connection, alert_id: int) -> None:
    conn.execute("UPDATE alert SET acknowledged = 1 WHERE id = ?", (alert_id,))
    conn.commit()


# --- reads ------------------------------------------------------------------

def recent_alerts(conn: sqlite3.Connection, limit: int = 50) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM alert ORDER BY created_at DESC, id DESC LIMIT ?", (limit,)
    ).fetchall()

def login_attempts_from_ip(conn: sqlite3.Connection, src_ip: str) -> int:
    """Count login-attempt events seen from an IP across all its sessions."""
    row = conn.execute(
        """SELECT COUNT(*) AS n
             FROM attack_log l
             JOIN attack_session s ON s.id = l.session_id
            WHERE s.src_ip = ? AND l.event_type = 'login_attempt'""",
        (src_ip,),
    ).fetchone()
    return row["n"]


def services_touched_by_ip(conn: sqlite3.Connection, src_ip: str) -> int:
    """Count distinct honeypot services an IP has opened a session against."""
    row = conn.execute(
        "SELECT COUNT(DISTINCT service_id) AS n FROM attack_session WHERE src_ip = ?",
        (src_ip,),
    ).fetchone()
    return row["n"]
