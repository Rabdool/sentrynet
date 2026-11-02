"""Tests for the reporting module (Objective 4, FR10/FR11).

Covers the summary query in the data layer, the Reports page and CSV export
in the dashboard, and the REPORT audit trail. Run: python -m unittest discover -s tests
"""
import csv
import io
import os
import re
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from data import db, repository  # noqa: E402
from data.auth import hash_password  # noqa: E402
from dashboard.app import _csv_safe, create_app  # noqa: E402

ADMIN, PASSWORD = "admin", "correct horse battery staple"
NOW = datetime.now(timezone.utc)


def _seed(conn):
    """Two attackers in the period and one event well outside it."""
    ssh = repository.add_service(conn, "cowrie-ssh", "ssh", 22)
    http = repository.add_service(conn, "decoy-http", "http", 80)

    s1 = repository.start_session(conn, ssh, "10.0.0.5", NOW)
    for _ in range(4):
        repository.log_event(conn, s1, "login_attempt", "root/123456", NOW)
    dl = repository.log_event(conn, s1, "download", "x.sh", NOW)
    repository.create_alert(conn, dl, "high", "download from 10.0.0.5", "malware_download")
    bf = repository.log_event(conn, s1, "login_attempt", "root/root", NOW)
    a = repository.create_alert(conn, bf, "high", "brute force from 10.0.0.5", "brute_force")
    repository.acknowledge_alert(conn, a)

    s2 = repository.start_session(conn, http, "10.0.0.9", NOW)
    repository.log_event(conn, s2, "connect", None, NOW)

    old = NOW - timedelta(days=60)
    s3 = repository.start_session(conn, ssh, "10.0.0.77", old)
    repository.log_event(conn, s3, "login_attempt", "old", old)


class ReportSummaryTest(unittest.TestCase):
    def setUp(self):
        self.conn = db.init_db(db.get_connection())
        _seed(self.conn)

    def tearDown(self):
        self.conn.close()

    def summary(self, days=1):
        return repository.report_summary(self.conn, NOW - timedelta(days=days), NOW + timedelta(minutes=1))

    def test_counts_events_attackers_and_alerts_in_period(self):
        s = self.summary()
        self.assertEqual(s["events"], 7)
        self.assertEqual(s["attackers"], 2)
        self.assertEqual(s["alerts"], 2)
        self.assertEqual(s["acknowledged"], 1)
        self.assertEqual(s["by_severity"], {"high": 2, "medium": 0, "low": 0})
        self.assertEqual(dict(s["by_type"]), {"brute_force": 1, "malware_download": 1})

    def test_period_excludes_older_activity(self):
        ips = [t["ip"] for t in self.summary()["top_sources"]]
        self.assertNotIn("10.0.0.77", ips)
        self.assertIn("10.0.0.77", [t["ip"] for t in self.summary(days=90)["top_sources"]])

    def test_top_sources_and_services_are_ranked(self):
        s = self.summary()
        top = s["top_sources"][0]
        self.assertEqual((top["ip"], top["events"], top["alerts"]), ("10.0.0.5", 6, 2))
        self.assertEqual([v["name"] for v in s["services"]], ["cowrie-ssh", "decoy-http"])

    def test_empty_period_is_all_zero(self):
        far = NOW - timedelta(days=400)
        s = repository.report_summary(self.conn, far, far + timedelta(days=1))
        self.assertEqual((s["events"], s["alerts"], s["top_sources"]), (0, 0, []))

    def test_report_is_recorded_against_user(self):
        uid = repository.create_user(self.conn, ADMIN, "x")
        repository.record_report(self.conn, uid, NOW - timedelta(days=7), NOW, "csv")
        row = repository.recent_reports(self.conn)[0]
        self.assertEqual((row["username"], row["format"]), (ADMIN, "csv"))

    def test_report_requires_existing_user(self):
        with self.assertRaises(Exception):
            repository.record_report(self.conn, 999, NOW, NOW)


class ReportPageTest(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        conn = db.init_db(db.get_connection(self.path))
        repository.create_user(conn, ADMIN, hash_password(PASSWORD))
        _seed(conn)
        conn.close()
        self.client = create_app(self.path, secret_key="test").test_client()

    def tearDown(self):
        os.unlink(self.path)

    def _login(self):
        page = self.client.get("/login").data.decode()
        token = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
        self.client.post("/login", data={"username": ADMIN, "password": PASSWORD, "csrf_token": token})

    def _period(self):
        today = datetime.now().date()
        return {"start": (today - timedelta(days=6)).isoformat(), "end": today.isoformat()}

    def _report_count(self):
        conn = db.get_connection(self.path)
        n = conn.execute("SELECT COUNT(*) FROM report").fetchone()[0]
        conn.close()
        return n

    def test_reports_require_login(self):
        for url in ("/reports", "/reports/export.csv"):
            r = self.client.get(url)
            self.assertEqual(r.status_code, 302)
            self.assertIn("/login", r.headers["Location"])
        self.assertEqual(self._report_count(), 0)

    def test_form_alone_does_not_record_a_report(self):
        self._login()
        r = self.client.get("/reports")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"Generate report", r.data)
        self.assertEqual(self._report_count(), 0)

    def test_generate_shows_summary_and_records_it(self):
        self._login()
        r = self.client.get("/reports", query_string=self._period())
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"10.0.0.5", r.data)
        self.assertIn(b"brute force", r.data)
        self.assertNotIn(b"10.0.0.77", r.data)
        self.assertEqual(self._report_count(), 1)
        # history shows the inclusive dates that were chosen
        period = self._period()
        history = self.client.get("/reports").data.decode()
        self.assertIn(period["start"], history)
        self.assertIn(period["end"], history)

    def test_csv_export(self):
        self._login()
        r = self.client.get("/reports/export.csv", query_string=self._period())
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.mimetype, "text/csv")
        self.assertIn("attachment", r.headers["Content-Disposition"])
        rows = list(csv.reader(io.StringIO(r.data.decode())))
        self.assertIn(["Events logged", "7"], rows)
        self.assertIn(["Alerts raised", "2"], rows)
        self.assertTrue(any(row and row[0] == "10.0.0.5" for row in rows))
        conn = db.get_connection(self.path)
        self.assertEqual(conn.execute("SELECT format FROM report").fetchone()[0], "csv")
        conn.close()

    def test_bad_dates_fall_back_to_default_period(self):
        self._login()
        r = self.client.get("/reports", query_string={"start": "nonsense", "end": "2026-13-45"})
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"10.0.0.5", r.data)

    def test_csv_cells_cannot_start_formulas(self):
        self.assertEqual(_csv_safe("=HYPERLINK(1)"), "'=HYPERLINK(1)")
        self.assertEqual(_csv_safe("@SUM(A1)"), "'@SUM(A1)")
        self.assertEqual(_csv_safe("10.0.0.5"), "10.0.0.5")
        self.assertEqual(_csv_safe(7), "7")


if __name__ == "__main__":
    unittest.main()
