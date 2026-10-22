"""Data-access helpers for the SentryNet store.

Thin wrappers over the tables in ``schema.sql`` so the honeypot,
alerting and dashboard layers never embed SQL of their own.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone


def format_ts(moment: datetime | None = None) -> str:
    """Render a UTC timestamp in the one format every table uses.

    A fixed, zero-padded format keeps string comparison equal to time order,
    which the alert engine's time-window queries rely on.
    """
    moment = (moment or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return moment.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def _now() -> str:
    return format_ts()


# --- writes -----------------------------------------------------------------

def add_service(conn: sqlite3.Connection, name: str, protocol: str, port: int) -> int:
    cur = conn.execute(
        "INSERT INTO honeypot_service (name, protocol, port) VALUES (?, ?, ?)",
        (name, protocol, port),
    )
    conn.commit()
    return cur.lastrowid


def get_or_create_service(conn: sqlite3.Connection, name: str, protocol: str, port: int) -> int:
    row = conn.execute("SELECT id FROM honeypot_service WHERE name = ?", (name,)).fetchone()
    return row["id"] if row else add_service(conn, name, protocol, port)


def start_session(
    conn: sqlite3.Connection, service_id: int, src_ip: str, started_at: datetime | None = None
) -> int:
    cur = conn.execute(
        "INSERT INTO attack_session (service_id, src_ip, started_at) VALUES (?, ?, ?)",
        (service_id, src_ip, format_ts(started_at)),
    )
    conn.commit()
    return cur.lastrowid


def end_session(conn: sqlite3.Connection, session_id: int) -> None:
    conn.execute(
        "UPDATE attack_session SET ended_at = ? WHERE id = ?", (_now(), session_id)
    )
    conn.commit()


def log_event(
    conn: sqlite3.Connection,
    session_id: int,
    event_type: str,
    detail: str | None = None,
    logged_at: datetime | None = None,
) -> int:
    cur = conn.execute(
        "INSERT INTO attack_log (session_id, event_type, detail, logged_at) VALUES (?, ?, ?, ?)",
        (session_id, event_type, detail, format_ts(logged_at)),
    )
    conn.commit()
    return cur.lastrowid


def create_alert(
    conn: sqlite3.Connection, log_id: int, severity: str, message: str, alert_type: str = "event"
) -> int:
    cur = conn.execute(
        "INSERT INTO alert (log_id, alert_type, severity, message, created_at)"
        " VALUES (?, ?, ?, ?, ?)",
        (log_id, alert_type, severity, message, _now()),
    )
    conn.commit()
    return cur.lastrowid


def acknowledge_alert(conn: sqlite3.Connection, alert_id: int) -> None:
    conn.execute("UPDATE alert SET acknowledged = 1 WHERE id = ?", (alert_id,))
    conn.commit()


def create_user(
    conn: sqlite3.Connection, username: str, password_hash: str, role: str = "admin"
) -> int:
    cur = conn.execute(
        "INSERT INTO user (username, password_hash, role) VALUES (?, ?, ?)",
        (username, password_hash, role),
    )
    conn.commit()
    return cur.lastrowid


def record_login(conn: sqlite3.Connection, user_id: int) -> None:
    conn.execute("UPDATE user SET last_login = ? WHERE id = ?", (_now(), user_id))
    conn.commit()


# --- reads ------------------------------------------------------------------

def recent_alerts(conn: sqlite3.Connection, limit: int = 50) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM alert ORDER BY created_at DESC, id DESC LIMIT ?", (limit,)
    ).fetchall()


def get_user_by_username(conn: sqlite3.Connection, username: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM user WHERE username = ?", (username,)).fetchone()


def get_user(conn: sqlite3.Connection, user_id: int) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM user WHERE id = ?", (user_id,)).fetchone()


def login_attempts_from_ip(conn: sqlite3.Connection, src_ip: str, since: datetime) -> int:
    """Count login attempts (failed or successful) from an IP since ``since``."""
    row = conn.execute(
        """SELECT COUNT(*) AS n
             FROM attack_log l
             JOIN attack_session s ON s.id = l.session_id
            WHERE s.src_ip = ?
              AND l.event_type IN ('login_attempt', 'login_success')
              AND l.logged_at >= ?""",
        (src_ip, format_ts(since)),
    ).fetchone()
    return row["n"]


def services_touched_by_ip(conn: sqlite3.Connection, src_ip: str, since: datetime) -> int:
    """Count distinct honeypot services an IP has opened a session against since ``since``."""
    row = conn.execute(
        """SELECT COUNT(DISTINCT service_id) AS n
             FROM attack_session
            WHERE src_ip = ? AND started_at >= ?""",
        (src_ip, format_ts(since)),
    ).fetchone()
    return row["n"]


def has_open_alert(conn: sqlite3.Connection, src_ip: str, alert_type: str) -> bool:
    """True if an unacknowledged alert of this type already exists for the IP."""
    row = conn.execute(
        """SELECT 1
             FROM alert a
             JOIN attack_log l ON l.id = a.log_id
             JOIN attack_session s ON s.id = l.session_id
            WHERE s.src_ip = ? AND a.alert_type = ? AND a.acknowledged = 0
            LIMIT 1""",
        (src_ip, alert_type),
    ).fetchone()
    return row is not None
