"""SentryNet admin dashboard (presentation layer).

A minimal Flask app that renders the alert feed from the data layer and lets
an authenticated administrator acknowledge alerts. Built with an app factory
so it can be driven by tests against a throwaway database.

Create the first administrator (prompts for a password):
    SENTRYNET_DB=sentrynet.db flask --app "dashboard.app:create_app" create-admin admin

Run directly:   SENTRYNET_DB=sentrynet.db python dashboard/app.py
With flask CLI: flask --app "dashboard.app:create_app" run

Set SENTRYNET_SECRET_KEY to keep sessions valid across restarts; without it a
random key is generated and administrators must sign in again after a restart.
"""
from __future__ import annotations

import csv
import functools
import hmac
import io
import os
import secrets
from datetime import date, datetime, time, timedelta, timezone

import click
from flask import (
    Flask, Response, abort, flash, g, redirect, render_template, request, session, url_for,
)

from data import db, repository
from data.auth import hash_password, verify_password

# Compared against when the username is unknown, so a failed lookup costs the
# same bcrypt work as a wrong password and does not reveal which usernames exist.
_DUMMY_HASH = hash_password(secrets.token_urlsafe(16))

REPORT_DEFAULT_DAYS = 7


def _report_period(args) -> tuple[date, date, datetime, datetime]:
    """Read the inclusive local-date range from the query string.

    Returns the two dates as chosen plus the half-open UTC period
    [start of first day, start of the day after the last day) used to query.
    Missing or malformed dates fall back to the last seven days.
    """
    today = datetime.now().date()
    try:
        first = date.fromisoformat(args.get("start", ""))
        last = date.fromisoformat(args.get("end", ""))
    except ValueError:
        first, last = today - timedelta(days=REPORT_DEFAULT_DAYS - 1), today
    if last < first:
        first, last = last, first
    start = datetime.combine(first, time.min).astimezone(timezone.utc)
    end = datetime.combine(last + timedelta(days=1), time.min).astimezone(timezone.utc)
    return first, last, start, end


def _csv_safe(value) -> str:
    """Neutralise spreadsheet formulas (CSV injection) in exported cells."""
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def create_app(db_path: str | None = None, secret_key: str | None = None) -> Flask:
    app = Flask(__name__)
    app.config["DB_PATH"] = db_path or os.environ.get("SENTRYNET_DB", "sentrynet.db")
    app.config["SECRET_KEY"] = (
        secret_key or os.environ.get("SENTRYNET_SECRET_KEY") or secrets.token_hex(32)
    )
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

    # Ensure the schema exists so a fresh database renders instead of erroring.
    db.init_db(db.get_connection(app.config["DB_PATH"])).close()

    def get_conn():
        if "conn" not in g:
            g.conn = db.get_connection(app.config["DB_PATH"])
        return g.conn

    @app.teardown_appcontext
    def _close_conn(_exc):
        conn = g.pop("conn", None)
        if conn is not None:
            conn.close()

    # --- authentication -------------------------------------------------

    def login_required(view):
        @functools.wraps(view)
        def wrapped(*args, **kwargs):
            if g.user is None:
                return redirect(url_for("login"))
            return view(*args, **kwargs)

        return wrapped

    @app.before_request
    def _load_user_and_check_csrf():
        user_id = session.get("user_id")
        g.user = repository.get_user(get_conn(), user_id) if user_id else None

        if request.method == "POST":
            sent = request.form.get("csrf_token", "")
            expected = session.get("csrf_token")
            if not expected or not hmac.compare_digest(sent, expected):
                abort(400)

    @app.template_filter("localtime")
    def _localtime(value) -> str:
        """Render a stored UTC timestamp in the server's local time zone."""
        try:
            moment = datetime.fromisoformat(str(value))
        except ValueError:
            return value
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        return moment.astimezone().strftime("%Y-%m-%d %H:%M:%S")

    @app.template_filter("localdate")
    def _localdate(value, exclusive_end: bool = False) -> str:
        """Render a stored UTC timestamp as a local date; for the exclusive end
        of a report period, show the last day the period actually includes."""
        try:
            moment = datetime.fromisoformat(str(value))
        except ValueError:
            return value
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        if exclusive_end:
            moment -= timedelta(microseconds=1)
        return moment.astimezone().strftime("%Y-%m-%d")

    @app.context_processor
    def _csrf_token():
        def csrf_token():
            if "csrf_token" not in session:
                session["csrf_token"] = secrets.token_urlsafe(32)
            return session["csrf_token"]

        return {"csrf_token": csrf_token, "current_user": g.get("user")}

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if g.user is not None:
            return redirect(url_for("index"))
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            user = repository.get_user_by_username(get_conn(), username)
            stored = user["password_hash"] if user else _DUMMY_HASH
            if verify_password(password, stored) and user is not None:
                # Start a fresh session on sign-in to prevent session fixation.
                session.clear()
                session["user_id"] = user["id"]
                repository.record_login(get_conn(), user["id"])
                return redirect(url_for("index"))
            flash("Invalid username or password.")
        return render_template("login.html")

    @app.route("/logout", methods=["POST"])
    def logout():
        session.clear()
        return redirect(url_for("login"))

    # --- alert feed -----------------------------------------------------

    @app.route("/")
    @login_required
    def index():
        alerts = repository.recent_alerts(get_conn(), limit=100)
        counts = {"high": 0, "medium": 0, "low": 0, "unacknowledged": 0}
        for a in alerts:
            counts[a["severity"]] = counts.get(a["severity"], 0) + 1
            if not a["acknowledged"]:
                counts["unacknowledged"] += 1
        return render_template("index.html", alerts=alerts, counts=counts)

    @app.route("/alerts/<int:alert_id>/ack", methods=["POST"])
    @login_required
    def acknowledge(alert_id: int):
        repository.acknowledge_alert(get_conn(), alert_id)
        return redirect(url_for("index"))

    # --- reports --------------------------------------------------------

    @app.route("/reports")
    @login_required
    def reports():
        first, last, start, end = _report_period(request.args)
        summary = None
        if "start" in request.args:
            summary = repository.report_summary(get_conn(), start, end)
            repository.record_report(get_conn(), g.user["id"], start, end, "html")
        return render_template(
            "reports.html",
            first=first,
            last=last,
            summary=summary,
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            history=repository.recent_reports(get_conn()),
        )

    @app.route("/reports/export.csv")
    @login_required
    def export_report():
        first, last, start, end = _report_period(request.args)
        summary = repository.report_summary(get_conn(), start, end)
        repository.record_report(get_conn(), g.user["id"], start, end, "csv")

        buf = io.StringIO()
        w = csv.writer(buf)
        rows = [
            ["SentryNet activity report"],
            ["Period", first.isoformat(), last.isoformat()],
            ["Generated by", g.user["username"]],
            ["Generated at", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
            [],
            ["Summary", "Value"],
            ["Events logged", summary["events"]],
            ["Distinct attacker IPs", summary["attackers"]],
            ["Alerts raised", summary["alerts"]],
            ["Alerts acknowledged", summary["acknowledged"]],
            *[[f"Alerts ({sev})", n] for sev, n in summary["by_severity"].items()],
            [],
            ["Alert type", "Count"],
            *[[t, n] for t, n in summary["by_type"]],
            [],
            ["Event type", "Count"],
            *[[e["name"], e["n"]] for e in summary["events_by_type"]],
            [],
            ["Source IP", "Events", "Services", "Alerts", "First seen (UTC)", "Last seen (UTC)"],
            *[[s["ip"], s["events"], s["services"], s["alerts"], s["first_seen"], s["last_seen"]]
              for s in summary["top_sources"]],
            [],
            ["Service", "Protocol", "Port", "Sessions", "Events"],
            *[[s["name"], s["protocol"], s["port"], s["sessions"], s["events"]]
              for s in summary["services"]],
        ]
        for row in rows:
            w.writerow([_csv_safe(c) for c in row])

        name = f"sentrynet-report-{first.isoformat()}-to-{last.isoformat()}.csv"
        return Response(
            buf.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{name}"'},
        )

    # --- admin CLI ------------------------------------------------------

    @app.cli.command("create-admin")
    @click.argument("username")
    @click.password_option()
    def create_admin(username: str, password: str):
        """Create a dashboard administrator account."""
        conn = db.get_connection(app.config["DB_PATH"])
        try:
            if repository.get_user_by_username(conn, username):
                raise click.ClickException(f"user '{username}' already exists")
            repository.create_user(conn, username, hash_password(password))
        finally:
            conn.close()
        click.echo(f"Created administrator '{username}'.")

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000, debug=True)
