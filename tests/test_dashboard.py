"""Tests for the SentryNet dashboard (presentation layer).

Drives the Flask app factory with a throwaway file database so the request
handlers and the data layer share state. Run: python -m unittest discover -s tests
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from data import db, repository  # noqa: E402
from dashboard.app import create_app  # noqa: E402


def _seed(path):
    conn = db.init_db(db.get_connection(path))
    svc = repository.add_service(conn, "cowrie-ssh", "ssh", 22)
    sid = repository.start_session(conn, svc, "10.0.0.5")
    log_id = repository.log_event(conn, sid, "download", "x.sh")
    repository.create_alert(conn, log_id, "high", "download observed from 10.0.0.5")
    conn.close()


class DashboardTest(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        _seed(self.path)
        self.client = create_app(self.path).test_client()

    def tearDown(self):
        os.unlink(self.path)

    def test_index_renders_and_lists_alert(self):
        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"download observed from 10.0.0.5", r.data)
        self.assertIn(b"high", r.data)

    def test_acknowledge_marks_alert(self):
        conn = db.get_connection(self.path)
        alert_id = repository.recent_alerts(conn)[0]["id"]
        conn.close()

        r = self.client.post(f"/alerts/{alert_id}/ack")
        self.assertIn(r.status_code, (302, 303))

        conn = db.get_connection(self.path)
        row = conn.execute("SELECT acknowledged FROM alert WHERE id = ?", (alert_id,)).fetchone()
        conn.close()
        self.assertEqual(row["acknowledged"], 1)

    def test_empty_database_renders_gracefully(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        db.init_db(db.get_connection(path)).close()
        try:
            r = create_app(path).test_client().get("/")
            self.assertEqual(r.status_code, 200)
            self.assertIn(b"No alerts yet", r.data)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
