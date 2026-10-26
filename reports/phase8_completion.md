# Phase 8 — Incident Investigation

## Status
COMPLETE — Both investigation case reports passed structural and evidence-marker validation.

## Case Reports
1. `incidents/incident_case_01_powershell_lsass.md` — PowerShell-to-LSASS correlation.
2. `incidents/incident_case_02_failed_logon_success.md` — Failed logon followed by successful-logon records.

## Investigation Findings
- Case 1 documents three observed PowerShell-to-LSASS correlations at 76.6, 126.4 and 327.4 seconds.
- Case 2 documents one failed logon for `IEUser` followed by two successful-logon records approximately 4.1 seconds later.
- Reused correlation events are not counted as independent incidents.
- Both cases remain investigation leads, not confirmed incidents.

## Limitations
Host identity and additional event context are incomplete. Root cause and impact remain undetermined. No live containment, eradication or recovery actions were performed.

## Scope
This phase documents retrospective investigations of sample telemetry. Findings are limited to the available evidence.
