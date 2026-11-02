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


# --- reporting --------------------------------------------------------------

def record_report(
    conn: sqlite3.Connection, user_id: int, start: datetime, end: datetime, fmt: str = "html"
) -> int:
    """Record that ``user_id`` generated a report for [start, end) (audit trail)."""
    cur = conn.execute(
        "INSERT INTO report (user_id, period_start, period_end, format, generated_at)"
        " VALUES (?, ?, ?, ?, ?)",
        (user_id, format_ts(start), format_ts(end), fmt, _now()),
    )
    conn.commit()
    return cur.lastrowid


def recent_reports(conn: sqlite3.Connection, limit: int = 10) -> list[sqlite3.Row]:
    return conn.execute(
        """SELECT r.*, u.username
             FROM report r JOIN user u ON u.id = r.user_id
            ORDER BY r.generated_at DESC, r.id DESC LIMIT ?""",
        (limit,),
    ).fetchall()


def report_summary(
    conn: sqlite3.Connection, start: datetime, end: datetime, top: int = 10
) -> dict:
    """Summarise honeypot activity and alerts in the half-open period [start, end).

    Computed live from attack_log, attack_session and alert so a report can
    never disagree with the underlying records.
    """
    lo, hi = format_ts(start), format_ts(end)

    events = conn.execute(
        """SELECT COUNT(*) AS events, COUNT(DISTINCT s.src_ip) AS attackers
             FROM attack_log l JOIN attack_session s ON s.id = l.session_id
            WHERE l.logged_at >= ? AND l.logged_at < ?""",
        (lo, hi),
    ).fetchone()

    events_by_type = conn.execute(
        """SELECT event_type AS name, COUNT(*) AS n
             FROM attack_log WHERE logged_at >= ? AND logged_at < ?
            GROUP BY event_type ORDER BY n DESC, name""",
        (lo, hi),
    ).fetchall()

    alert_rows = conn.execute(
        "SELECT alert_type, severity, acknowledged FROM alert WHERE created_at >= ? AND created_at < ?",
        (lo, hi),
    ).fetchall()
    by_severity = {"high": 0, "medium": 0, "low": 0}
    by_type: dict[str, int] = {}
    for a in alert_rows:
        by_severity[a["severity"]] = by_severity.get(a["severity"], 0) + 1
        by_type[a["alert_type"]] = by_type.get(a["alert_type"], 0) + 1
    acknowledged = sum(1 for a in alert_rows if a["acknowledged"])

    top_sources = conn.execute(
        """SELECT s.src_ip AS ip,
                  COUNT(*) AS events,
                  COUNT(DISTINCT s.service_id) AS services,
                  (SELECT COUNT(*)
                     FROM alert a
                     JOIN attack_log l2 ON l2.id = a.log_id
                     JOIN attack_session s2 ON s2.id = l2.session_id
                    WHERE s2.src_ip = s.src_ip
                      AND a.created_at >= ? AND a.created_at < ?) AS alerts,
                  MIN(l.logged_at) AS first_seen,
                  MAX(l.logged_at) AS last_seen
             FROM attack_log l JOIN attack_session s ON s.id = l.session_id
            WHERE l.logged_at >= ? AND l.logged_at < ?
            GROUP BY s.src_ip ORDER BY events DESC, ip LIMIT ?""",
        (lo, hi, lo, hi, top),
    ).fetchall()

    services = conn.execute(
        """SELECT h.name, h.protocol, h.port,
                  COUNT(DISTINCT s.id) AS sessions, COUNT(l.id) AS events
             FROM attack_log l
             JOIN attack_session s ON s.id = l.session_id
             JOIN honeypot_service h ON h.id = s.service_id
            WHERE l.logged_at >= ? AND l.logged_at < ?
            GROUP BY h.id ORDER BY events DESC, h.name""",
        (lo, hi),
    ).fetchall()

    return {
        "events": events["events"],
        "attackers": events["attackers"],
        "events_by_type": [dict(r) for r in events_by_type],
        "alerts": len(alert_rows),
        "acknowledged": acknowledged,
        "by_severity": by_severity,
        "by_type": sorted(by_type.items(), key=lambda kv: (-kv[1], kv[0])),
        "top_sources": [dict(r) for r in top_sources],
        "services": [dict(r) for r in services],
    }
