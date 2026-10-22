"""Tests for the SentryNet dashboard (presentation layer).

Drives the Flask app factory with a throwaway file database so the request
handlers and the data layer share state. Run: python -m unittest discover -s tests
"""
import os
import re
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from data import db, repository  # noqa: E402
from data.auth import hash_password, verify_password  # noqa: E402
from dashboard.app import create_app  # noqa: E402

ADMIN, PASSWORD = "admin", "correct horse battery staple"


def _seed(path):
    conn = db.init_db(db.get_connection(path))
    repository.create_user(conn, ADMIN, hash_password(PASSWORD))
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
        self.client = create_app(self.path, secret_key="test").test_client()

    def tearDown(self):
        os.unlink(self.path)

    def _csrf(self, url="/login"):
        page = self.client.get(url).data.decode()
        return re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)

    def _login(self, username=ADMIN, password=PASSWORD):
        token = self._csrf()
        return self.client.post(
            "/login", data={"username": username, "password": password, "csrf_token": token}
        )

    def test_index_renders_and_lists_alert(self):
        self._login()
        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"download observed from 10.0.0.5", r.data)
        self.assertIn(b"high", r.data)

    def test_acknowledge_marks_alert(self):
        conn = db.get_connection(self.path)
        alert_id = repository.recent_alerts(conn)[0]["id"]
        conn.close()

        self._login()
        r = self.client.post(f"/alerts/{alert_id}/ack", data={"csrf_token": self._csrf("/")})
        self.assertIn(r.status_code, (302, 303))

        conn = db.get_connection(self.path)
        row = conn.execute("SELECT acknowledged FROM alert WHERE id = ?", (alert_id,)).fetchone()
        conn.close()
        self.assertEqual(row["acknowledged"], 1)

    def test_empty_database_renders_gracefully(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        conn = db.init_db(db.get_connection(path))
        repository.create_user(conn, ADMIN, hash_password(PASSWORD))
        conn.close()
        try:
            self.client = create_app(path, secret_key="test").test_client()
            self._login()
            r = self.client.get("/")
            self.assertEqual(r.status_code, 200)
            self.assertIn(b"No alerts yet", r.data)
        finally:
            os.unlink(path)

    # --- authentication (FR1 / NFR2, test case TC01) ---------------------

    def test_feed_requires_login(self):
        r = self.client.get("/")
        self.assertEqual(r.status_code, 302)
        self.assertIn("/login", r.headers["Location"])
        self.assertNotIn(b"download observed", r.data)

    def test_valid_login_creates_session_and_records_last_login(self):
        r = self._login()
        self.assertEqual(r.status_code, 302)
        self.assertEqual(self.client.get("/").status_code, 200)

        conn = db.get_connection(self.path)
        row = repository.get_user_by_username(conn, ADMIN)
        conn.close()
        self.assertIsNotNone(row["last_login"])

    def test_wrong_password_is_rejected(self):
        r = self._login(password="wrong")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"Invalid username or password", r.data)
        self.assertEqual(self.client.get("/").status_code, 302)

    def test_unknown_user_gets_same_error(self):
        r = self._login(username="nobody")
        self.assertIn(b"Invalid username or password", r.data)

    def test_ack_requires_login(self):
        token = self._csrf()
        r = self.client.post("/alerts/1/ack", data={"csrf_token": token})
        self.assertEqual(r.status_code, 302)
        self.assertIn("/login", r.headers["Location"])

    def test_post_without_csrf_token_is_rejected(self):
        self._login()
        r = self.client.post("/alerts/1/ack")
        self.assertEqual(r.status_code, 400)

    def test_logout_ends_session(self):
        self._login()
        self.client.post("/logout", data={"csrf_token": self._csrf("/")})
        self.assertEqual(self.client.get("/").status_code, 302)

    def test_passwords_are_stored_as_bcrypt_hashes(self):
        conn = db.get_connection(self.path)
        stored = repository.get_user_by_username(conn, ADMIN)["password_hash"]
        conn.close()
        self.assertNotEqual(stored, PASSWORD)
        self.assertTrue(stored.startswith("$2"))
        self.assertTrue(verify_password(PASSWORD, stored))
        self.assertFalse(verify_password("wrong", stored))

    def test_create_admin_cli(self):
        app = create_app(self.path, secret_key="test")
        result = app.test_cli_runner().invoke(
            args=["create-admin", "analyst", "--password", "s3cret!"]
        )
        self.assertEqual(result.exit_code, 0, result.output)
        conn = db.get_connection(self.path)
        row = repository.get_user_by_username(conn, "analyst")
        conn.close()
        self.assertTrue(verify_password("s3cret!", row["password_hash"]))

        again = app.test_cli_runner().invoke(
            args=["create-admin", "analyst", "--password", "x"]
        )
        self.assertNotEqual(again.exit_code, 0)


if __name__ == "__main__":
    unittest.main()
