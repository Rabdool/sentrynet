"""Tests for the Cowrie honeypot adapter.

In-memory SQLite; no external services. Run: python -m unittest discover -s tests
"""
import json
import os
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from data import db, repository  # noqa: E402
from data.alert_engine import AlertRules  # noqa: E402
from honeypot.cowrie_adapter import (  # noqa: E402
    follow_cowrie_file,
    ingest_cowrie_events,
    ingest_cowrie_file,
)


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

    def test_login_success_is_unauthorized_access(self):
        events = [
            {"eventid": "cowrie.session.connect", "session": "s9", "src_ip": "10.0.0.20"},
            {"eventid": "cowrie.login.success", "session": "s9", "src_ip": "10.0.0.20",
             "username": "root", "password": "toor"},
        ]
        ingest_cowrie_events(self.conn, self.svc, events)
        types = [a["alert_type"] for a in repository.recent_alerts(self.conn)]
        self.assertEqual(types, ["unauthorized_access"])
        detail = self.conn.execute("SELECT event_type, detail FROM attack_log").fetchone()
        self.assertEqual((detail["event_type"], detail["detail"]), ("login_success", "root/toor"))

    def test_cowrie_timestamp_is_stored(self):
        events = [
            {"eventid": "cowrie.session.connect", "session": "t1", "src_ip": "10.0.0.21",
             "timestamp": "2026-03-01T09:15:00.250000Z"},
            {"eventid": "cowrie.login.failed", "session": "t1", "src_ip": "10.0.0.21",
             "username": "a", "password": "b", "timestamp": "2026-03-01T09:15:02.500000Z"},
        ]
        ingest_cowrie_events(self.conn, self.svc, events)
        logged = self.conn.execute("SELECT logged_at FROM attack_log").fetchone()["logged_at"]
        started = self.conn.execute("SELECT started_at FROM attack_session").fetchone()["started_at"]
        self.assertEqual(logged, "2026-03-01 09:15:02.500")
        self.assertEqual(started, "2026-03-01 09:15:00.250")

    def test_follow_ingests_lines_appended_later(self):
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        conn = db.init_db(db.get_connection(path + ".db"))
        conn.close()
        stop = threading.Event()
        result = {}

        def run():
            c = db.get_connection(path + ".db")
            svc = repository.get_or_create_service(c, "cowrie-ssh", "ssh", 22)
            result["n"] = follow_cowrie_file(c, svc, path, poll_interval=0.02,
                                             should_stop=stop.is_set)
            c.close()

        t = threading.Thread(target=run)
        t.start()
        try:
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps({"eventid": "cowrie.session.connect", "session": "f1",
                                     "src_ip": "10.0.0.30"}) + "\n")
                fh.flush()
                time.sleep(0.1)
                # a line written in two parts must be read as one event
                line = json.dumps({"eventid": "cowrie.login.success", "session": "f1",
                                   "src_ip": "10.0.0.30", "username": "root", "password": "x"})
                fh.write(line[:20])
                fh.flush()
                time.sleep(0.1)
                fh.write(line[20:] + "\n")
                fh.flush()
            deadline = time.time() + 3
            while time.time() < deadline:
                c = db.get_connection(path + ".db")
                n = len(repository.recent_alerts(c))
                c.close()
                if n:
                    break
                time.sleep(0.05)
            self.assertEqual(n, 1, "alert should appear while the log is still being watched")
        finally:
            stop.set()
            t.join(timeout=3)
            os.unlink(path)
            os.unlink(path + ".db")
        self.assertEqual(result["n"], 1)


if __name__ == "__main__":
    unittest.main()
