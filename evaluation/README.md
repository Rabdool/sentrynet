# Evaluation

Measures SentryNet's effectiveness at detecting the three attack classes in
**Objective 6** — port-scanning, brute-force and unauthorized-access attempts —
by driving the real detection pipeline (Cowrie adapter, decoy-port sensor,
alert engine) with representative attack traffic.

- `run_evaluation.py` — runs four scenarios and reports detection, alert
  counts, detection latency, logging completeness and false positives.
  `python -m evaluation.run_evaluation`
- `results.json` — machine-readable summary from the last run.
- `UAT_RUNBOOK.md` — the equivalent formal lab procedure using Nmap and Hydra
  against honeypot VMs, for the final report's evaluation chapter.

It needs no network setup and runs no external attack tools, so the results
are reproducible on any machine with `python -m evaluation.run_evaluation`.
