"""SentryNet data / alerting layer.

Centralises captured honeypot activity in a single store (SQLite by default,
MySQL-compatible schema) and evaluates it against configurable alert rules.
"""
from . import db, repository, alert_engine
from .ingest import record_event

__all__ = ["db", "repository", "alert_engine", "record_event"]
