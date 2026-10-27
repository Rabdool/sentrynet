"""Tests for the SentryNet data / alerting layer.

Runs against an in-memory SQLite database; no external services required.
Run: python -m unittest discover -s tests
"""
import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

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

    # --- Chapter Four, Listing 4.2 / test case TC03 ---------------------

    def _alerts_of(self, alert_type):
        return [a for a in repository.recent_alerts(self.conn) if a["alert_type"] == alert_type]

    def test_default_threshold_is_four_in_sixty_seconds(self):
        rules = AlertRules()
        self.assertEqual((rules.brute_force_threshold, rules.window_seconds), (4, 60))
        sid = repository.start_session(self.conn, self.svc, "10.0.1.1")
        for _ in range(3):
            record_event(self.conn, sid, "10.0.1.1", "login_attempt")
        self.assertEqual(self._alerts_of("brute_force"), [])
        record_event(self.conn, sid, "10.0.1.1", "login_attempt")
        self.assertEqual(len(self._alerts_of("brute_force")), 1)

    def test_brute_force_duplicates_suppressed_until_acknowledged(self):
        sid = repository.start_session(self.conn, self.svc, "10.0.1.2")
        for _ in range(50):
            record_event(self.conn, sid, "10.0.1.2", "login_attempt")
        self.assertEqual(len(self._alerts_of("brute_force")), 1)
        log_count = self.conn.execute("SELECT COUNT(*) AS n FROM attack_log").fetchone()["n"]
        self.assertEqual(log_count, 50, "suppressed events must still be logged")

        repository.acknowledge_alert(self.conn, self._alerts_of("brute_force")[0]["id"])
        for _ in range(4):
            record_event(self.conn, sid, "10.0.1.2", "login_attempt")
        self.assertEqual(len(self._alerts_of("brute_force")), 2)

    def test_attempts_outside_window_do_not_count(self):
        sid = repository.start_session(self.conn, self.svc, "10.0.1.3")
        start = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
        # one slow attempt every 30 s: never 4 inside any 60 s window
        for i in range(10):
            record_event(self.conn, sid, "10.0.1.3", "login_attempt",
                         occurred_at=start + timedelta(seconds=30 * i))
        self.assertEqual(self._alerts_of("brute_force"), [])

    def test_successful_login_raises_unauthorized_access(self):
        sid = repository.start_session(self.conn, self.svc, "10.0.1.4")
        record_event(self.conn, sid, "10.0.1.4", "login_success", detail="root/toor")
        alerts = self._alerts_of("unauthorized_access")
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["severity"], "high")

    def test_port_scan_alert_raised_once(self):
        ip = "10.0.1.5"
        for port in range(8000, 8010):
            svc = repository.add_service(self.conn, f"decoy-{port}", "tcp", port)
            sid = repository.start_session(self.conn, svc, ip)
            record_event(self.conn, sid, ip, "connection")
        self.assertEqual(len(self._alerts_of("port_scan")), 1)

    def test_alerts_are_per_ip(self):
        for ip in ("10.0.2.1", "10.0.2.2"):
            sid = repository.start_session(self.conn, self.svc, ip)
            for _ in range(4):
                record_event(self.conn, sid, ip, "login_attempt")
        self.assertEqual(len(self._alerts_of("brute_force")), 2)


if __name__ == "__main__":
    unittest.main()
