# SentryNet

A honeypot-based threat-detection platform for SMEs and under-resourced
organizations, built on a Defense-in-Depth strategy.

## Layers
- `honeypot/`  — decoy services (Cowrie / OpenCanary) that capture attacker interaction
- `data/`      — centralized logging + alert engine (SQLite/MySQL)
- `dashboard/` — authenticated Flask admin dashboard (presentation layer)

Status: scaffold. Implementation in progress (see Chapter Four).
