"""Tests for the decoy TCP port sensor.

Opens real sockets on loopback ports chosen by the OS; no external services.
Run: python -m unittest discover -s tests
"""
import asyncio
import os
import socket
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from data import db, repository  # noqa: E402
from honeypot.decoy_ports import serve  # noqa: E402


def _free_ports(n):
    socks = [socket.socket() for _ in range(n)]
    for s in socks:
        s.bind(("127.0.0.1", 0))
    ports = [s.getsockname()[1] for s in socks]
    for s in socks:
        s.close()
    return ports


class DecoyPortsTest(unittest.TestCase):
    def setUp(self):
        self.conn = db.init_db(db.get_connection(":memory:"))

    def tearDown(self):
        self.conn.close()

    def _scan(self, ports, probe):
        async def run():
            servers = await serve(self.conn, ports, host="127.0.0.1")
            for port in probe:
                _, writer = await asyncio.open_connection("127.0.0.1", port)
                await asyncio.sleep(0.05)
                writer.close()
            await asyncio.sleep(0.1)
            for s in servers:
                s.close()
                await s.wait_closed()

        asyncio.run(run())

    def test_each_connection_is_logged_against_its_port(self):
        ports = _free_ports(2)
        self._scan(ports, ports[:1])
        rows = self.conn.execute(
            """SELECT h.port, s.src_ip, l.event_type FROM attack_log l
               JOIN attack_session s ON s.id = l.session_id
               JOIN honeypot_service h ON h.id = s.service_id"""
        ).fetchall()
        self.assertEqual([tuple(r) for r in rows], [(ports[0], "127.0.0.1", "connection")])
        self.assertEqual(repository.recent_alerts(self.conn), [])

    def test_sweep_across_ports_raises_one_port_scan_alert(self):
        ports = _free_ports(5)
        self._scan(ports, ports)
        alerts = repository.recent_alerts(self.conn)
        self.assertEqual([a["alert_type"] for a in alerts], ["port_scan"])


if __name__ == "__main__":
    unittest.main()
