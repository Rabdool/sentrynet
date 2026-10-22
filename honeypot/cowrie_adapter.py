"""Cowrie honeypot adapter (honeypot layer).

Reads Cowrie's JSON event log and feeds each relevant event into the data
layer via its public API, so captured SSH/Telnet activity flows into the
alert engine. Standard library only.

Cowrie writes one JSON object per line. The fields used here are ``eventid``,
``session`` (Cowrie's own session id), ``src_ip`` and ``timestamp``.

Watch a live Cowrie log and raise alerts as events arrive:
    python -m honeypot.cowrie_adapter --db sentrynet.db --log cowrie.json --follow
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import time
from datetime import datetime
from typing import Callable, Iterable, Iterator

from data import db, record_event, repository
from data.alert_engine import AlertRules

# Cowrie eventid -> data-layer event_type
_EVENT_TYPE = {
    "cowrie.login.failed": "login_attempt",
    "cowrie.login.success": "login_success",
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


def _timestamp(event: dict) -> datetime | None:
    """Cowrie's own event time, so alert windows reflect when the attack happened."""
    raw = event.get("timestamp")
    if not isinstance(raw, str):
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
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
        occurred_at = _timestamp(event)

        if eventid == "cowrie.session.connect":
            if cowrie_sid is not None and src_ip is not None:
                sid = repository.start_session(conn, service_id, src_ip, started_at=occurred_at)
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
            sid = repository.start_session(conn, service_id, src_ip, started_at=occurred_at)
            entry = sessions[cowrie_sid] = (sid, src_ip)

        sid, session_ip = entry
        record_event(
            conn,
            sid,
            src_ip or session_ip,
            event_type,
            detail=_detail_for(eventid, event),
            rules=rules,
            occurred_at=occurred_at,
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
    with open(path, encoding="utf-8") as fh:
        return ingest_cowrie_events(conn, service_id, _parse_lines(fh), rules=rules)


def _parse_lines(lines: Iterable[str]) -> Iterator[dict]:
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except (ValueError, TypeError):
            continue


def _tail(path: str, poll_interval: float, should_stop: Callable[[], bool]) -> Iterator[str]:
    """Yield complete lines appended to ``path``, like ``tail -F``.

    Waits for the file to appear, and buffers a partly written last line until
    Cowrie finishes it.
    """
    while not should_stop():
        try:
            fh = open(path, encoding="utf-8")
            break
        except FileNotFoundError:
            time.sleep(poll_interval)
    else:
        return
    with fh:
        partial = ""
        while True:
            chunk = fh.readline()
            if chunk:
                partial += chunk
                if partial.endswith("\n"):
                    yield partial
                    partial = ""
                continue
            if should_stop():
                return
            time.sleep(poll_interval)


def follow_cowrie_file(
    conn: sqlite3.Connection,
    service_id: int,
    path: str,
    rules: AlertRules | None = None,
    poll_interval: float = 0.2,
    should_stop: Callable[[], bool] = lambda: False,
) -> int:
    """Ingest a live Cowrie log as it grows, until ``should_stop()`` is true."""
    lines = _tail(path, poll_interval, should_stop)
    return ingest_cowrie_events(conn, service_id, _parse_lines(lines), rules=rules)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Feed Cowrie's JSON log into SentryNet.")
    parser.add_argument("--db", required=True, help="SentryNet SQLite database")
    parser.add_argument("--log", required=True, help="Cowrie cowrie.json log file")
    parser.add_argument("--follow", action="store_true", help="keep watching for new events")
    parser.add_argument("--service-name", default="cowrie-ssh")
    parser.add_argument("--port", type=int, default=22)
    args = parser.parse_args(argv)

    conn = db.init_db(db.get_connection(args.db))
    service_id = repository.get_or_create_service(conn, args.service_name, "ssh", args.port)
    try:
        if args.follow:
            follow_cowrie_file(conn, service_id, args.log)
        else:
            print(f"ingested {ingest_cowrie_file(conn, service_id, args.log)} events")
    except KeyboardInterrupt:
        pass
    finally:
        conn.close()


if __name__ == "__main__":
    main()
