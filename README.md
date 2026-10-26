# Cyberion Defense Labs
## Detection Engineering & Threat Hunting Dashboard

A local cybersecurity project for Sigma-style detection engineering,
MITRE ATT&CK coverage tracking, threat hunting, incident investigation,
and reviewing security telemetry from Windows EVTX sample logs.

## Project Components

- Flask-based detection engineering dashboard.
- YAML detection rules with title, logsource, and detection fields.
- MITRE ATT&CK technique coverage reports and Navigator layer.
- Threat hunt reports based on sample telemetry.
- Incident investigation case reports.
- Local scan history and file-analysis functionality in the dashboard.
- Python test scripts and documented validation evidence.

## Verified Project Evidence

The existing Phase 5 reports document the following results:

- 278 EVTX files scanned.
- 37,364 events scanned.
- 16 primary detection rules produced matching telemetry in the
  recorded baseline and final retest.
- 0 EVTX parser errors were reported in the final retest.
- ATT&CK coverage: 24 techniques assessed, 16 covered,
  4 partially covered, and 4 not covered.
- 2 threat hunt reports.
- 2 incident investigation case reports.
- 0 playbook files currently present.

These are recorded project results, not a claim that every rule
has been independently retested in every environment.

## Repository Structure

- `dashboard/` - Flask dashboard and alternate FastAPI entry point.
- `rules/` - YAML detection rules used by the project.
- `hunts/` - Threat hunt reports.
- `incidents/` - Incident investigation reports.
- `playbooks/` - Reserved for response playbooks; currently empty.
- `reports/` - Coverage, testing, validation, and phase reports.
- `tests/` - Python validation and retest scripts.
- `test_uploads/` - Harmless local test fixtures; temporary test rules are kept out of the public repository.
- `data/` - Local datasets and generated data; private scan data is
  excluded from version control.
- `backups/` - Local backups; excluded from version control.

## Requirements

- Python 3
- pip

Install the project dependencies from the repository root:

```bash
python -m pip install -r requirements.txt
```

The dependency list includes Flask, PyYAML, Werkzeug, python-evtx, and FastAPI.

## Run Locally

From the project root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python dashboard/app.py
```

Open `http://127.0.0.1:5000/` in your browser.

If port 5000 is already occupied, stop the existing dashboard process
before starting another instance.

## Testing

Check Python syntax:

```bash
python -m py_compile dashboard/app.py dashboard/main.py tests/*.py
```

The existing reports under `reports/` document the recorded rule
retest, false-positive review, correlation validation, ATT&CK mapping,
threat hunts, and incident investigations.

## Security and Privacy

- `data/private_scans/` is intended for local scan uploads, reports,
  and scan-history storage and is excluded from Git.
- Local backups and the raw EVTX sample dataset are excluded from Git.
- Do not commit secrets, credentials, private uploads, or sensitive logs.
- Review all files and Git changes before publishing this repository.

## Limitations

- Findings are based on sample telemetry and should be treated as
  investigation leads, not confirmed malicious incidents.
- Some event identity and host context is incomplete.
- The failed-logon burst correlation was implemented but was not
  demonstrated in the recorded validation run.
- Four ATT&CK-assessed techniques remain partially covered or
  uncovered as documented in the coverage matrix.
- Incident response playbooks have not yet been added.
- The documented test results reflect the existing evidence reports;
  rerun tests when the dataset, rules, or code changes.

## Project Status

Final QA and repository preparation are in progress.
GitHub publication will occur only after local verification and review.
