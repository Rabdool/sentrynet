# Honeypot layer

Decoy services that capture attacker interaction and forward events to the
data layer. Planned backends:

- **Cowrie** — medium-interaction SSH/Telnet
- **OpenCanary** — multi-protocol low-interaction (HTTP, FTP, SMB, ...)

Each service writes events into `attack_log` via the data layer (see
`../data/schema.sql`).
