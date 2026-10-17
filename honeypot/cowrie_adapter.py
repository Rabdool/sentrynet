"""Cowrie honeypot adapter (honeypot layer).

Reads Cowrie's JSON event log and feeds each relevant event into the data
layer via its public API, so captured SSH/Telnet activity flows into the
alert engine. Standard library only.

Cowrie writes one JSON object per line. The fields used here are ``eventid``,
``session`` (Cowrie's own session id) and ``src_ip``.
"""
from __future__ import annotations

import json
import sqlite3
from typing import Iterable

from data import record_event, repository
from data.alert_engine import AlertRules

# Cowrie eventid -> data-layer event_type
_EVENT_TYPE = {
    "cowrie.login.failed": "login_attempt",
    "cowrie.login.success": "login_attempt",
    "cowrie.command.input": "command",
    "cowrie.session.file_download": "download",
}


def _detail_for(eventid: str, event: dict) -> str | None:
    if eventid in ("cowrie.login.failed", "cowrie.login.success"):
        user, pw = event.get("username"), event.get("password")
        return f"{user}/{pw}" if (user is not None or pw is not None) else None
    if eventid == "cowrie.command.input":
        return event.get("input")
    if eventid == "cowrie.session.file_download":
        return event.get("url") or event.get("outfile")
    return None


def ingest_cowrie_events(
    conn: sqlite3.Connection,
    service_id: int,
    events: Iterable[dict],
    rules: AlertRules | None = None,
) -> int:
    """Feed parsed Cowrie event dicts into the data layer.

    Returns the number of events that produced an ``attack_log`` entry
    (session connect/closed events are tracked but not themselves logged).
    """
    sessions: dict[str, tuple[int, str]] = {}  # cowrie sid -> (data session_id, src_ip)
    logged = 0

    for event in events:
        if not isinstance(event, dict):
            continue
        eventid = event.get("eventid")
        cowrie_sid = event.get("session")
        src_ip = event.get("src_ip")

        if eventid == "cowrie.session.connect":
            if cowrie_sid is not None and src_ip is not None:
                sid = repository.start_session(conn, service_id, src_ip)
                sessions[cowrie_sid] = (sid, src_ip)
            continue

        if eventid == "cowrie.session.closed":
            entry = sessions.pop(cowrie_sid, None)
            if entry is not None:
                repository.end_session(conn, entry[0])
            continue

        event_type = _EVENT_TYPE.get(eventid)
        if event_type is None:
            continue  # ignore unknown / uninteresting event ids

        entry = sessions.get(cowrie_sid)
        if entry is None:
            # event for a session we never saw connect: open one lazily
            if src_ip is None:
                continue
            sid = repository.start_session(conn, service_id, src_ip)
            entry = sessions[cowrie_sid] = (sid, src_ip)

        sid, session_ip = entry
        record_event(
            conn,
            sid,
            src_ip or session_ip,
            event_type,
            detail=_detail_for(eventid, event),
            rules=rules,
        )
        logged += 1

    return logged


def ingest_cowrie_file(
    conn: sqlite3.Connection,
    service_id: int,
    path: str,
    rules: AlertRules | None = None,
) -> int:
    """Read a Cowrie JSON-lines log file and ingest it.

    Blank lines and malformed JSON are skipped without raising.
    """
    def _parsed() -> Iterable[dict]:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except (ValueError, TypeError):
                    continue

    return ingest_cowrie_events(conn, service_id, _parsed(), rules=rules)
