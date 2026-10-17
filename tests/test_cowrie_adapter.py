"""Tests for the Cowrie honeypot adapter.

In-memory SQLite; no external services. Run: python -m unittest discover -s tests
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from data import db, repository  # noqa: E402
from data.alert_engine import AlertRules  # noqa: E402
from honeypot.cowrie_adapter import ingest_cowrie_events, ingest_cowrie_file  # noqa: E402


class CowrieAdapterTest(unittest.TestCase):
    def setUp(self):
        self.conn = db.init_db(db.get_connection(":memory:"))
        self.svc = repository.add_service(self.conn, "cowrie-ssh", "ssh", 22)

    def tearDown(self):
        self.conn.close()

    def _flow(self, ip="10.0.0.5", sid="s1", logins=1):
        events = [{"eventid": "cowrie.session.connect", "session": sid, "src_ip": ip}]
        for i in range(logins):
            events.append({
                "eventid": "cowrie.login.failed", "session": sid, "src_ip": ip,
                "username": "root", "password": f"pw{i}",
            })
        events.append({"eventid": "cowrie.command.input", "session": sid, "src_ip": ip, "input": "uname -a"})
        events.append({"eventid": "cowrie.session.file_download", "session": sid, "src_ip": ip, "url": "http://evil/x.sh"})
        events.append({"eventid": "cowrie.session.closed", "session": sid, "src_ip": ip})
        return events

    def test_full_flow_logs_events_and_ends_session(self):
        n = ingest_cowrie_events(self.conn, self.svc, self._flow(logins=1))
        self.assertEqual(n, 3)  # 1 login + 1 command + 1 download; connect/closed not counted
        self.assertEqual(self.conn.execute("SELECT COUNT(*) AS c FROM attack_log").fetchone()["c"], 3)
        self.assertIsNotNone(self.conn.execute("SELECT ended_at FROM attack_session").fetchone()["ended_at"])

    def test_download_raises_high_alert(self):
        ingest_cowrie_events(self.conn, self.svc, self._flow(logins=1))
        self.assertTrue(any(a["severity"] == "high" for a in repository.recent_alerts(self.conn)))

    def test_brute_force_alert_from_repeated_logins(self):
        rules = AlertRules(brute_force_threshold=3, port_scan_threshold=99)
        ingest_cowrie_events(self.conn, self.svc, self._flow(ip="10.0.0.9", logins=4), rules=rules)
        self.assertTrue(any("brute-force" in a["message"] for a in repository.recent_alerts(self.conn)))

    def test_unknown_event_ids_ignored(self):
        events = [
            {"eventid": "cowrie.session.connect", "session": "s1", "src_ip": "10.0.0.5"},
            {"eventid": "cowrie.client.version", "session": "s1", "src_ip": "10.0.0.5", "version": "SSH-2.0"},
            {"eventid": "cowrie.direct-tcpip.request", "session": "s1", "src_ip": "10.0.0.5"},
        ]
        n = ingest_cowrie_events(self.conn, self.svc, events)
        self.assertEqual(n, 0)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) AS c FROM attack_log").fetchone()["c"], 0)

    def test_file_ingest_skips_blank_and_malformed_lines(self):
        events = self._flow(logins=2)
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
            f.write("\n")            # blank
            f.write("{not valid json}\n")  # malformed
            for e in events:
                f.write(json.dumps(e) + "\n")
            f.write("   \n")         # whitespace-only
            path = f.name
        try:
            n = ingest_cowrie_file(self.conn, self.svc, path)
        finally:
            os.unlink(path)
        self.assertEqual(n, 4)  # 2 logins + command + download

    def test_event_without_connect_opens_session_lazily(self):
        events = [{"eventid": "cowrie.command.input", "session": "orphan", "src_ip": "10.0.0.7", "input": "id"}]
        n = ingest_cowrie_events(self.conn, self.svc, events)
        self.assertEqual(n, 1)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) AS c FROM attack_session").fetchone()["c"], 1)


if __name__ == "__main__":
    unittest.main()
