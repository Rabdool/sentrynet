"""Single entry point the honeypot layer calls for every observed event.

Persists the event, runs the alert rules, and stores any resulting alerts in
one place so the honeypot adapters stay thin.
"""
from __future__ import annotations

import sqlite3

from . import alert_engine, repository
from .alert_engine import AlertRules


def record_event(
    conn: sqlite3.Connection,
    session_id: int,
    src_ip: str,
    event_type: str,
    detail: str | None = None,
    rules: AlertRules | None = None,
) -> int:
    """Log one honeypot event and raise any alerts it triggers.

    Returns the new ``attack_log`` id.
    """
    log_id = repository.log_event(conn, session_id, event_type, detail)
    for severity, message in alert_engine.evaluate(conn, event_type, src_ip, rules):
        repository.create_alert(conn, log_id, severity, message)
    return log_id
