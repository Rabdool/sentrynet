"""Tests for the SentryNet data / alerting layer.

Runs against an in-memory SQLite database; no external services required.
Run: python -m unittest discover -s tests
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from data import db, repository  # noqa: E402
from data.alert_engine import AlertRules, evaluate  # noqa: E402
from data.ingest import record_event  # noqa: E402


class DataLayerTest(unittest.TestCase):
    def setUp(self):
        self.conn = db.init_db(db.get_connection(":memory:"))
        self.svc = repository.add_service(self.conn, "cowrie-ssh", "ssh", 22)

    def tearDown(self):
        self.conn.close()

    def test_session_and_log_flow(self):
        sid = repository.start_session(self.conn, self.svc, "10.0.0.5")
        log_id = repository.log_event(self.conn, sid, "login_attempt", "root/123456")
        self.assertIsInstance(log_id, int)
        repository.end_session(self.conn, sid)
        row = self.conn.execute(
            "SELECT ended_at FROM attack_session WHERE id = ?", (sid,)
        ).fetchone()
        self.assertIsNotNone(row["ended_at"])

    def test_foreign_keys_enforced(self):
        import sqlite3

        with self.assertRaises(sqlite3.IntegrityError):
            # session_id 999 does not exist
            self.conn.execute(
                "INSERT INTO attack_log (session_id, event_type) VALUES (999, 'x')"
            )
            self.conn.commit()

    def test_brute_force_alert_fires_on_threshold(self):
        rules = AlertRules(brute_force_threshold=3, port_scan_threshold=99)
        sid = repository.start_session(self.conn, self.svc, "10.0.0.9")
        alerts_seen = []
        for _ in range(3):
            record_event(self.conn, sid, "10.0.0.9", "login_attempt", rules=rules)
        stored = repository.recent_alerts(self.conn)
        self.assertTrue(
            any("brute-force" in a["message"] for a in stored),
            "expected a brute-force alert once the threshold was reached",
        )

    def test_no_alert_below_threshold(self):
        rules = AlertRules(brute_force_threshold=5, port_scan_threshold=99)
        sid = repository.start_session(self.conn, self.svc, "10.0.0.10")
        for _ in range(2):
            record_event(self.conn, sid, "10.0.0.10", "login_attempt", rules=rules)
        self.assertEqual(len(repository.recent_alerts(self.conn)), 0)

    def test_download_event_is_high_severity(self):
        sid = repository.start_session(self.conn, self.svc, "10.0.0.11")
        record_event(self.conn, sid, "10.0.0.11", "download", detail="malware.sh")
        alerts = repository.recent_alerts(self.conn)
        self.assertTrue(any(a["severity"] == "high" for a in alerts))

    def test_port_scan_alert_across_services(self):
        rules = AlertRules(brute_force_threshold=99, port_scan_threshold=3)
        http = repository.add_service(self.conn, "opencanary-http", "http", 80)
        ftp = repository.add_service(self.conn, "opencanary-ftp", "ftp", 21)
        ip = "10.0.0.12"
        for svc in (self.svc, http, ftp):
            sid = repository.start_session(self.conn, svc, ip)
            record_event(self.conn, sid, ip, "login_attempt", rules=rules)
        self.assertTrue(
            any("port scan" in a["message"] for a in repository.recent_alerts(self.conn))
        )

    def test_acknowledge_alert(self):
        sid = repository.start_session(self.conn, self.svc, "10.0.0.13")
        record_event(self.conn, sid, "10.0.0.13", "download")
        alert_id = repository.recent_alerts(self.conn)[0]["id"]
        repository.acknowledge_alert(self.conn, alert_id)
        row = self.conn.execute(
            "SELECT acknowledged FROM alert WHERE id = ?", (alert_id,)
        ).fetchone()
        self.assertEqual(row["acknowledged"], 1)


if __name__ == "__main__":
    unittest.main()
