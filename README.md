# SentryNet

A honeypot-based threat-detection platform for SMEs and under-resourced
organizations, built on a Defense-in-Depth strategy.

## Layers
- `honeypot/`  — decoy services (Cowrie / OpenCanary) that capture attacker interaction
- `data/`      — centralized logging + alert engine (SQLite/MySQL)
- `dashboard/` — authenticated Flask admin dashboard (presentation layer)

Status: all three layers implemented with tests; see Chapter Four.

## Running the dashboard
```
pip install -r requirements.txt
export SENTRYNET_DB=sentrynet.db SENTRYNET_SECRET_KEY=change-me
flask --app "dashboard.app:create_app" create-admin admin   # prompts for a password
flask --app "dashboard.app:create_app" run
```
Then sign in at http://127.0.0.1:5000/login.

## Tests
```
python -m unittest discover -s tests
```

## Evaluation (Objective 6)
```
python -m evaluation.run_evaluation
```
Drives the detection pipeline with brute-force, port-scan, unauthorized-access
and benign-control traffic and reports detection accuracy, latency and logging
completeness. See `evaluation/UAT_RUNBOOK.md` for the formal Nmap/Hydra lab test.
