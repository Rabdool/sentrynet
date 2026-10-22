# SentryNet — User Acceptance Test Runbook

This runbook describes the formal lab User Acceptance Test (UAT) for SentryNet,
following the attack-simulation methodology in Chapter Two (§2.2.7) and the
deployment topology in Chapter Four (Figure 3.5). It is carried out on an
**isolated lab network** that the operator owns and controls — never against
systems you are not authorised to test.

The automated harness in `run_evaluation.py` already exercises the detection
pipeline end to end and records the metrics below; this runbook is the
equivalent procedure driven by real attacker tooling (Nmap, Hydra) against the
live honeypot, for the final report's evaluation chapter.

## Topology (isolated lab segment)

| Role          | Host                | Notes                                   |
|---------------|---------------------|-----------------------------------------|
| Honeypot      | Honeypot Server VM  | Cowrie (SSH/Telnet) + SentryNet adapter |
| Monitoring    | SentryNet host      | data layer + dashboard                  |
| Attacker      | Attacker VM         | Nmap + Hydra, on the same private subnet |

Use a host-only / internal network with no route to the internet or any
production system.

## Preparation

1. Deploy Cowrie on the Honeypot Server VM and enable JSON logging
   (`output_jsonlog` → `var/log/cowrie/cowrie.json`).
2. On the SentryNet host, start the live log follower so Cowrie events flow
   into the data layer and alert engine as they happen:
   ```
   python -m honeypot.cowrie_adapter --db sentrynet.db --log /path/to/cowrie.json --follow
   ```
3. For the port-scan test, run the decoy-port sensor on the Honeypot Server VM:
   ```
   python -m honeypot.decoy_ports --db sentrynet.db --ports 21,23,80,110,143,445,3306,3389
   ```
4. Start the dashboard and sign in as an administrator:
   ```
   flask --app "dashboard.app:create_app" create-admin admin
   flask --app "dashboard.app:create_app" run
   ```

## Test procedure

Record the wall-clock time each attack starts and the time the corresponding
alert appears on the dashboard (detection latency).

### UAT-1 — Port scan (Objective 6: port-scanning)
From the Attacker VM:
```
nmap -sT -p 21,23,80,110,143,445,3306,3389 <honeypot-ip>
```
**Expected:** one `port_scan` alert naming the attacker IP; every probed port
recorded in the attack log.

### UAT-2 — Brute-force login (Objective 6: brute-force)
From the Attacker VM, a dictionary attack against the emulated SSH service:
```
hydra -l root -P wordlist.txt ssh://<honeypot-ip>
```
**Expected:** one `brute_force` alert once ≥ 4 attempts arrive within 60 s;
further attempts are logged but do not raise duplicate alerts until the alert
is acknowledged.

### UAT-3 — Unauthorized access (Objective 6: unauthorized access)
Let the brute-force run until Cowrie accepts one of its configured credentials
(or connect manually with a credential in Cowrie's `userdb`).
**Expected:** one `unauthorized_access` alert; the successful login and any
subsequent commands recorded against the session.

### UAT-4 — Benign control (false-positive check)
Make two or three failed SSH logins by hand, well spaced in time.
**Expected:** **no** alert (activity stays below the thresholds).

## Metrics to record (against Tables 3.1 / 3.2)

| Metric                | How measured                                              |
|-----------------------|-----------------------------------------------------------|
| Detection accuracy    | attacks detected vs. launched; false positives on control |
| Logging completeness  | events in `attack_log` vs. events generated               |
| Alert timeliness      | time from attack start to alert on dashboard (NFR1)       |
| Dashboard usability    | administrator can read and acknowledge alerts (NFR3)      |

## Reference result (automated harness)

`python -m evaluation.run_evaluation` on the detection pipeline produced:

| Scenario              | Expected | Alert | Alerts | Latency | Logged | Result |
|-----------------------|----------|-------|--------|---------|--------|--------|
| Brute-force (20 tries) | yes      | yes   | 1      | ~1.5 s  | 20/20  | TP     |
| Port scan (12 ports)   | yes      | yes   | 1      | ~0.05 s | 12/12  | TP     |
| Unauthorized access    | yes      | yes   | 1      | ~0 s    | 2/2    | TP     |
| Benign control         | no       | no    | 0      | —       | 3/3    | TN     |

3/3 attacks detected, 0 false positives, 100 % logging completeness.
