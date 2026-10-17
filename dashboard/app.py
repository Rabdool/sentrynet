"""SentryNet admin dashboard (presentation layer).

A minimal Flask app that renders the alert feed from the data layer and lets
an administrator acknowledge alerts. Built with an app factory so it can be
driven by tests against a throwaway database.

Run directly:   SENTRYNET_DB=sentrynet.db python dashboard/app.py
With flask CLI: flask --app "dashboard.app:create_app" run
"""
from __future__ import annotations

import os

from flask import Flask, g, redirect, render_template, url_for

from data import db, repository

_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def create_app(db_path: str | None = None) -> Flask:
    app = Flask(__name__)
    app.config["DB_PATH"] = db_path or os.environ.get("SENTRYNET_DB", "sentrynet.db")

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

    @app.route("/")
    def index():
        alerts = repository.recent_alerts(get_conn(), limit=100)
        counts = {"high": 0, "medium": 0, "low": 0, "unacknowledged": 0}
        for a in alerts:
            counts[a["severity"]] = counts.get(a["severity"], 0) + 1
            if not a["acknowledged"]:
                counts["unacknowledged"] += 1
        return render_template("index.html", alerts=alerts, counts=counts)

    @app.route("/alerts/<int:alert_id>/ack", methods=["POST"])
    def acknowledge(alert_id: int):
        repository.acknowledge_alert(get_conn(), alert_id)
        return redirect(url_for("index"))

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000, debug=True)
