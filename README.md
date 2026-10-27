# SentryNet

A honeypot-based threat-detection platform for SMEs and under-resourced
organizations, built on a Defense-in-Depth strategy.

## Layers
- `honeypot/`  — decoy services (Cowrie / OpenCanary) that capture attacker interaction
- `data/`      — centralized logging + alert engine (SQLite/MySQL)
- `dashboard/` — authenticated Flask admin dashboard (presentation layer)

Status: all three layers implemented with tests; see Chapter Four.

## Running the dashboard
Requires Python 3.10 or newer. Run every command from the `sentrynet/` folder.

### Ubuntu
Ubuntu blocks `pip install` into the system Python, so use a virtual
environment. Install the venv module once if it is missing:
```
sudo apt install python3-venv
```
Then:
```
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export SENTRYNET_DB=sentrynet.db SENTRYNET_SECRET_KEY=change-me
flask --app "dashboard.app:create_app" create-admin admin   # prompts for a password
flask --app "dashboard.app:create_app" run
```
In the fish shell, use `source .venv/bin/activate.fish` and set the variables
with `set -x SENTRYNET_DB sentrynet.db; set -x SENTRYNET_SECRET_KEY change-me`.

### Windows (PowerShell)
Install Python from python.org and tick "Add python.exe to PATH". Then:
```
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:SENTRYNET_DB = "sentrynet.db"
$env:SENTRYNET_SECRET_KEY = "change-me"
flask --app "dashboard.app:create_app" create-admin admin   # prompts for a password
flask --app "dashboard.app:create_app" run
```
If PowerShell refuses to run `Activate.ps1`, allow local scripts once with
`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`. In Command Prompt
instead of PowerShell, activate with `.venv\Scripts\activate.bat` and set the
variables with `set SENTRYNET_DB=sentrynet.db` and
`set SENTRYNET_SECRET_KEY=change-me`.

### Signing in
Open http://127.0.0.1:5000/login and sign in with the administrator account
created above. `create-admin` is only needed the first time; the account is
stored in `sentrynet.db`. On later runs, activate the virtual environment, set
the two variables and run the last command again.

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
