"""End-to-end detection evaluation for SentryNet (Objective 6).

Drives the real detection pipeline — the Cowrie adapter, the decoy-port
sensor and the alert engine — with representative attack traffic and records,
for each scenario, whether the expected alert was raised, how many alerts it
produced, the detection latency, and how completely the events were logged.
It also runs a benign control to confirm ordinary low-volume activity does
not raise a false alert.

This measures the same detection behaviour that live Nmap/Hydra traffic would
exercise, without running external attack tools; it is fully reproducible and
needs no network setup. The formal lab User Acceptance Test using Nmap and
Hydra against honeypot VMs is documented separately in evaluation/UAT_RUNBOOK.md.

Run:  python -m evaluation.run_evaluation
"""
from __future__ import annotations

import asyncio
import json
import socket
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from data import db, repository
from honeypot.cowrie_adapter import ingest_cowrie_events
from honeypot.decoy_ports import serve


@dataclass
class Result:
    scenario: str
    attack_class: str
    expect_alert: bool
    events_sent: int
    events_logged: int
    alert_raised: bool
    alert_types: list[str] = field(default_factory=list)
    alert_count: int = 0
    detection_latency_s: float | None = None

    @property
    def logging_completeness(self) -> float:
        return 1.0 if self.events_sent == 0 else self.events_logged / self.events_sent

    @property
    def outcome(self) -> str:
        # Confusion-matrix cell for this scenario.
        if self.expect_alert:
            return "TP" if self.alert_raised else "FN"
        return "FP" if self.alert_raised else "TN"


def _fresh_conn():
    return db.init_db(db.get_connection(":memory:"))


def _detection_latency(conn, alert_type: str) -> float | None:
    """Seconds between the attacker's first logged event and the event that
    first raised an alert of this type."""
    row = conn.execute(
        """SELECT l.logged_at AS trigger_ts, s.src_ip AS ip
             FROM alert a
             JOIN attack_log l ON l.id = a.log_id
             JOIN attack_session s ON s.id = l.session_id
            WHERE a.alert_type = ?
            ORDER BY a.id ASC LIMIT 1""",
        (alert_type,),
    ).fetchone()
    if row is None:
        return None
    first = conn.execute(
        """SELECT MIN(l.logged_at) AS first_ts
             FROM attack_log l JOIN attack_session s ON s.id = l.session_id
            WHERE s.src_ip = ?""",
        (row["ip"],),
    ).fetchone()["first_ts"]
    fmt = "%Y-%m-%d %H:%M:%S.%f"
    return (datetime.strptime(row["trigger_ts"], fmt) - datetime.strptime(first, fmt)).total_seconds()


# --- scenarios --------------------------------------------------------------

def scenario_brute_force() -> Result:
    """A dictionary attack: 20 failed SSH logins from one IP in ~10 s."""
    conn = _fresh_conn()
    svc = repository.get_or_create_service(conn, "cowrie-ssh", "ssh", 22)
    ip = "198.51.100.23"
    t0 = datetime(2026, 5, 10, 2, 0, 0, tzinfo=timezone.utc)
    passwords = [
        "123456", "password", "root", "admin", "toor", "12345678", "qwerty",
        "111111", "letmein", "welcome", "monkey", "dragon", "123123", "abc123",
        "iloveyou", "000000", "password1", "root123", "admin123", "pass",
    ]
    events = [{"eventid": "cowrie.session.connect", "session": "bf", "src_ip": ip,
               "timestamp": t0.isoformat()}]
    for i, pw in enumerate(passwords):
        ts = (t0 + timedelta(seconds=0.5 * (i + 1))).isoformat()
        events.append({"eventid": "cowrie.login.failed", "session": "bf", "src_ip": ip,
                       "username": "root", "password": pw, "timestamp": ts})
    events.append({"eventid": "cowrie.session.closed", "session": "bf", "src_ip": ip,
                   "timestamp": (t0 + timedelta(seconds=11)).isoformat()})
    logged = ingest_cowrie_events(conn, svc, events)
    alerts = repository.recent_alerts(conn)
    bf = [a for a in alerts if a["alert_type"] == "brute_force"]
    r = Result("Brute-force login (dictionary attack)", "brute_force", True,
               events_sent=len(passwords), events_logged=logged,
               alert_raised=bool(bf), alert_types=sorted({a["alert_type"] for a in alerts}),
               alert_count=len(bf), detection_latency_s=_detection_latency(conn, "brute_force"))
    conn.close()
    return r


def scenario_unauthorized_access() -> Result:
    """A guessed credential succeeds — no legitimate user exists on a decoy."""
    conn = _fresh_conn()
    svc = repository.get_or_create_service(conn, "cowrie-ssh", "ssh", 22)
    ip = "198.51.100.77"
    t0 = datetime(2026, 5, 10, 3, 0, 0, tzinfo=timezone.utc)
    events = [
        {"eventid": "cowrie.session.connect", "session": "ua", "src_ip": ip,
         "timestamp": t0.isoformat()},
        {"eventid": "cowrie.login.success", "session": "ua", "src_ip": ip,
         "username": "root", "password": "root", "timestamp": (t0 + timedelta(seconds=1)).isoformat()},
        {"eventid": "cowrie.command.input", "session": "ua", "src_ip": ip,
         "input": "uname -a", "timestamp": (t0 + timedelta(seconds=2)).isoformat()},
        {"eventid": "cowrie.session.closed", "session": "ua", "src_ip": ip,
         "timestamp": (t0 + timedelta(seconds=3)).isoformat()},
    ]
    logged = ingest_cowrie_events(conn, svc, events)
    alerts = repository.recent_alerts(conn)
    ua = [a for a in alerts if a["alert_type"] == "unauthorized_access"]
    r = Result("Unauthorized access (successful login)", "unauthorized_access", True,
               events_sent=2, events_logged=logged,
               alert_raised=bool(ua), alert_types=sorted({a["alert_type"] for a in alerts}),
               alert_count=len(ua), detection_latency_s=_detection_latency(conn, "unauthorized_access"))
    conn.close()
    return r


def scenario_port_scan() -> Result:
    """A connect scan across 12 decoy ports from one IP (real loopback sockets)."""
    conn = _fresh_conn()
    socks = [socket.socket() for _ in range(12)]
    for s in socks:
        s.bind(("127.0.0.1", 0))
    ports = [s.getsockname()[1] for s in socks]
    for s in socks:
        s.close()

    async def run():
        servers = await serve(conn, ports, host="127.0.0.1")
        for p in ports:
            _, w = await asyncio.open_connection("127.0.0.1", p)
            await asyncio.sleep(0.02)
            w.close()
        await asyncio.sleep(0.1)
        for sv in servers:
            sv.close()
            await sv.wait_closed()

    asyncio.run(run())
    alerts = repository.recent_alerts(conn)
    ps = [a for a in alerts if a["alert_type"] == "port_scan"]
    logged = conn.execute("SELECT COUNT(*) AS n FROM attack_log").fetchone()["n"]
    r = Result("Port scan (multi-port sweep)", "port_scan", True,
               events_sent=len(ports), events_logged=logged,
               alert_raised=bool(ps), alert_types=sorted({a["alert_type"] for a in alerts}),
               alert_count=len(ps), detection_latency_s=_detection_latency(conn, "port_scan"))
    conn.close()
    return r


def scenario_benign_control() -> Result:
    """Low-volume activity below every threshold: must not raise an alert."""
    conn = _fresh_conn()
    svc = repository.get_or_create_service(conn, "cowrie-ssh", "ssh", 22)
    ip = "203.0.113.200"
    t0 = datetime(2026, 5, 10, 4, 0, 0, tzinfo=timezone.utc)
    # 3 failed logins (below the 4 threshold), one service only.
    events = [{"eventid": "cowrie.session.connect", "session": "ok", "src_ip": ip,
               "timestamp": t0.isoformat()}]
    for i in range(3):
        events.append({"eventid": "cowrie.login.failed", "session": "ok", "src_ip": ip,
                       "username": "admin", "password": f"try{i}",
                       "timestamp": (t0 + timedelta(seconds=5 * (i + 1))).isoformat()})
    events.append({"eventid": "cowrie.session.closed", "session": "ok", "src_ip": ip,
                   "timestamp": (t0 + timedelta(seconds=20)).isoformat()})
    logged = ingest_cowrie_events(conn, svc, events)
    alerts = repository.recent_alerts(conn)
    r = Result("Benign control (below thresholds)", "benign", False,
               events_sent=3, events_logged=logged,
               alert_raised=bool(alerts), alert_types=sorted({a["alert_type"] for a in alerts}),
               alert_count=len(alerts), detection_latency_s=None)
    conn.close()
    return r


SCENARIOS = [
    scenario_brute_force,
    scenario_port_scan,
    scenario_unauthorized_access,
    scenario_benign_control,
]


def run() -> list[Result]:
    return [s() for s in SCENARIOS]


def _fmt(v) -> str:
    return "—" if v is None else f"{v:.2f}s"


def main() -> int:
    results = run()
    w = 42
    print("\nSentryNet detection evaluation (Objective 6)")
    print("=" * 78)
    print(f"{'Scenario':<{w}}{'Expect':<8}{'Alert':<7}{'#':<4}{'Latency':<9}{'Logged':<8}{'Result'}")
    print("-" * 78)
    for r in results:
        print(f"{r.scenario:<{w}}{'yes' if r.expect_alert else 'no':<8}"
              f"{'yes' if r.alert_raised else 'no':<7}{r.alert_count:<4}"
              f"{_fmt(r.detection_latency_s):<9}"
              f"{r.events_logged}/{r.events_sent:<5} {r.outcome}")
    print("-" * 78)

    tp = sum(r.outcome == "TP" for r in results)
    tn = sum(r.outcome == "TN" for r in results)
    fp = sum(r.outcome == "FP" for r in results)
    fn = sum(r.outcome == "FN" for r in results)
    detected = [r for r in results if r.expect_alert]
    completeness = sum(r.events_logged for r in results) / max(1, sum(r.events_sent for r in results))
    print(f"True positives:  {tp}/{len(detected)} attack scenarios detected")
    print(f"False positives: {fp}    False negatives: {fn}    True negatives: {tn}")
    print(f"Logging completeness: {completeness * 100:.0f}% of events recorded")
    all_pass = fp == 0 and fn == 0
    print(f"\nOverall: {'PASS — every attack detected, no false alarms' if all_pass else 'REVIEW — see table'}")

    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "scenarios": [
            {"scenario": r.scenario, "attack_class": r.attack_class,
             "expect_alert": r.expect_alert, "alert_raised": r.alert_raised,
             "alert_types": r.alert_types, "alert_count": r.alert_count,
             "detection_latency_s": r.detection_latency_s,
             "events_sent": r.events_sent, "events_logged": r.events_logged,
             "logging_completeness": r.logging_completeness, "outcome": r.outcome}
            for r in results
        ],
        "confusion": {"TP": tp, "TN": tn, "FP": fp, "FN": fn},
        "logging_completeness": completeness,
    }
    with open("evaluation/results.json", "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
    print("Machine-readable summary written to evaluation/results.json")
    return 0 if all_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
