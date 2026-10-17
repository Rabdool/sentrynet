"""SentryNet admin dashboard — minimal stub (presentation layer).

Serves a placeholder index until the alert-feed views are implemented.
Run: python dashboard/app.py
"""
from flask import Flask

app = Flask(__name__)


@app.route("/")
def index():
    return "SentryNet dashboard — scaffold. Alert feed coming soon."


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
