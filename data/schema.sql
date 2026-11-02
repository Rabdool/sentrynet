-- SentryNet data layer schema (realises the ERD in Chapter Three, Figure 3.2)
CREATE TABLE IF NOT EXISTS honeypot_service (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL,          -- e.g. 'cowrie-ssh', 'opencanary-http'
    protocol    TEXT NOT NULL,
    port        INTEGER NOT NULL,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS attack_session (
    id          INTEGER PRIMARY KEY,
    service_id  INTEGER NOT NULL REFERENCES honeypot_service(id),
    src_ip      TEXT NOT NULL,
    started_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ended_at    TIMESTAMP
);

CREATE TABLE IF NOT EXISTS attack_log (
    id          INTEGER PRIMARY KEY,
    session_id  INTEGER NOT NULL REFERENCES attack_session(id),
    event_type  TEXT NOT NULL,          -- login_attempt, command, download, ...
    detail      TEXT,
    logged_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS alert (
    id          INTEGER PRIMARY KEY,
    log_id      INTEGER NOT NULL REFERENCES attack_log(id),
    alert_type  TEXT NOT NULL DEFAULT 'event',  -- brute_force, port_scan, unauthorized_access, ...
    severity    TEXT NOT NULL,          -- low | medium | high
    message     TEXT NOT NULL,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    acknowledged INTEGER DEFAULT 0
);

-- Dashboard administrators (Chapter Four, Table 4.1). Passwords are bcrypt hashes.
CREATE TABLE IF NOT EXISTS user (
    id            INTEGER PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'admin',
    last_login    TIMESTAMP
);

-- Audit trail of generated reports (Chapter Three, Table 3.3). The figures in a
-- report are always computed live from attack_log and alert, so only the request
-- itself is stored: who generated it, the period covered, the format and when.
CREATE TABLE IF NOT EXISTS report (
    id            INTEGER PRIMARY KEY,
    user_id       INTEGER NOT NULL REFERENCES user(id),
    period_start  TIMESTAMP NOT NULL,
    period_end    TIMESTAMP NOT NULL,
    format        TEXT NOT NULL DEFAULT 'html',  -- html | csv
    generated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
