"""Configurable alert evaluation for the data layer.

Each honeypot event is scored against a small set of rules. Thresholds are
configurable so an administrator can tune sensitivity to their tolerance for
false alarms (Chapter Three, non-functional requirements).

Detection rules (the three attack classes in Objective 6, plus post-login
activity):

* brute force         -- ``brute_force_threshold`` or more login attempts from
                         one IP inside ``window_seconds`` (Listing 4.2: 4 in 60 s)
* port scan           -- one IP opening sessions against ``port_scan_threshold``
                         or more distinct services inside ``window_seconds``
* unauthorized access -- any successful login to a honeypot service; no real
                         user has an account on a decoy, so every success is hostile
* command / download  -- activity an intruder performs once inside

At most one *open* (unacknowledged) alert is kept per attacker IP per alert
type: further matching events are still logged, but do not raise duplicates
until the administrator acknowledges the existing alert (Listing 4.2).
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from . import repository


@dataclass
class AlertRules:
    #: login attempts from one IP within the window before a brute-force alert
    brute_force_threshold: int = 4
    #: distinct services probed by one IP within the window before a port-scan alert
    port_scan_threshold: int = 3
    #: sliding window, in seconds, for the brute-force and port-scan rules
    window_seconds: int = 60
    #: event types that alert on their own: event_type -> (alert_type, severity)
    event_alerts: dict[str, tuple[str, str]] = field(
        default_factory=lambda: {
            "login_success": ("unauthorized_access", "high"),
            "command": ("intruder_command", "medium"),
            "download": ("malware_download", "high"),
        }
    )


def evaluate(
    conn: sqlite3.Connection,
    event_type: str,
    src_ip: str,
    rules: AlertRules | None = None,
    occurred_at: datetime | None = None,
) -> list[tuple[str, str, str]]:
    """Return ``(alert_type, severity, message)`` triples this event warrants.

    The event must already be persisted (so counts include it). ``occurred_at``
    is when the honeypot saw the event; the window is measured back from it, so
    replaying an old log gives the same alerts as watching it live.
    """
    rules = rules or AlertRules()
    occurred_at = occurred_at or datetime.now(timezone.utc)
    since = occurred_at - timedelta(seconds=rules.window_seconds)
    candidates: list[tuple[str, str, str]] = []

    if event_type in rules.event_alerts:
        alert_type, severity = rules.event_alerts[event_type]
        label = alert_type.replace("_", " ")
        candidates.append((alert_type, severity, f"{label.capitalize()}: {event_type} from {src_ip}"))

    if event_type in ("login_attempt", "login_success"):
        n = repository.login_attempts_from_ip(conn, src_ip, since)
        if n >= rules.brute_force_threshold:
            candidates.append((
                "brute_force",
                "high",
                f"Possible brute-force: {n} login attempts from {src_ip}"
                f" within {rules.window_seconds} s",
            ))

    touched = repository.services_touched_by_ip(conn, src_ip, since)
    if touched >= rules.port_scan_threshold:
        candidates.append((
            "port_scan",
            "medium",
            f"Possible port scan: {src_ip} probed {touched} services"
            f" within {rules.window_seconds} s",
        ))

    return [c for c in candidates if not repository.has_open_alert(conn, src_ip, c[0])]
