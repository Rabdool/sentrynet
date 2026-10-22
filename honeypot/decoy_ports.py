"""Decoy TCP port sensor (honeypot layer).

Listens on a set of otherwise unused ports that no legitimate client has any
reason to contact, in the low-interaction style of OpenCanary. Every
connection is recorded as a session against that port's honeypot service, so
an attacker sweeping several ports trips the port-scan rule in the alert
engine. Standard library only.

    python -m honeypot.decoy_ports --db sentrynet.db --ports 21,80,445,3306,3389

The sensor sees completed TCP connections, i.e. connect scans (``nmap -sT``,
the default when Nmap runs unprivileged). A half-open SYN scan never completes
the handshake, so it does not reach a user-space listener.
"""
from __future__ import annotations

import argparse
import asyncio
import sqlite3

from data import db, record_event, repository
from data.alert_engine import AlertRules


async def serve(
    conn: sqlite3.Connection,
    ports: list[int],
    host: str = "0.0.0.0",
    rules: AlertRules | None = None,
) -> list[asyncio.base_events.Server]:
    """Start one listener per port; returns the servers (caller keeps them alive)."""
    servers = []
    for port in ports:
        service_id = repository.get_or_create_service(conn, f"decoy-tcp-{port}", "tcp", port)

        async def on_connect(reader, writer, port=port, service_id=service_id):
            src_ip = writer.get_extra_info("peername")[0]
            sid = repository.start_session(conn, service_id, src_ip)
            record_event(conn, sid, src_ip, "connection", detail=f"tcp/{port}", rules=rules)
            repository.end_session(conn, sid)
            writer.close()

        servers.append(await asyncio.start_server(on_connect, host, port))
    return servers


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Run SentryNet decoy TCP ports.")
    parser.add_argument("--db", required=True, help="SentryNet SQLite database")
    parser.add_argument("--ports", required=True, help="comma-separated list, e.g. 21,80,445")
    parser.add_argument("--host", default="0.0.0.0")
    args = parser.parse_args(argv)
    ports = [int(p) for p in args.ports.split(",") if p.strip()]

    conn = db.init_db(db.get_connection(args.db))

    async def run():
        await serve(conn, ports, args.host)
        print(f"decoy ports listening: {', '.join(map(str, ports))}", flush=True)
        await asyncio.Event().wait()

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        pass
    finally:
        conn.close()


if __name__ == "__main__":
    main()
