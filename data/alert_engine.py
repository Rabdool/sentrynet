"""Configurable alert evaluation for the data layer.

Each honeypot event is scored against a small set of rules. Thresholds are
configurable so an administrator can tune sensitivity to their tolerance for
false alarms (Chapter Three, non-functional requirements).
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field

from . import repository


@dataclass
class AlertRules:
    #: login attempts from one IP before a brute-force alert is raised
    brute_force_threshold: int = 5
    #: distinct services probed by one IP before a port-scan alert is raised
    port_scan_threshold: int = 3
    #: per-event-type severity for events that alert on their own
    event_severity: dict[str, str] = field(
        default_factory=lambda: {"command": "medium", "download": "high"}
    )


def evaluate(
    conn: sqlite3.Connection,
    event_type: str,
    src_ip: str,
    rules: AlertRules | None = None,
) -> list[tuple[str, str]]:
    """Return ``(severity, message)`` pairs this event warrants.

    The event must already be persisted (so counts include it).
    """
    rules = rules or AlertRules()
    alerts: list[tuple[str, str]] = []

    severity = rules.event_severity.get(event_type)
    if severity:
        alerts.append((severity, f"{event_type} observed from {src_ip}"))

    if event_type == "login_attempt":
        n = repository.login_attempts_from_ip(conn, src_ip)
        if n >= rules.brute_force_threshold:
            alerts.append(
                ("high", f"Possible brute-force: {n} login attempts from {src_ip}")
            )

    touched = repository.services_touched_by_ip(conn, src_ip)
    if touched >= rules.port_scan_threshold:
        alerts.append(
            ("medium", f"Possible port scan: {src_ip} probed {touched} services")
        )

    return alerts
