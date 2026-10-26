# Phase 5 — Final Evidence Report

## Scope

- Dataset: `EVTX-ATTACK-SAMPLES`
- EVTX files: 278
- Events scanned during primary testing: 37,364
- Primary Sigma rules: 16

## Primary Rule Testing

- Baseline testing: **16/16 rules produced matches**
- False-positive review: **16/16 rules reviewed**
- Final retest: **16/16 rules produced matches**
- EVTX parser errors: **0**
- Tuning applied: **None justified by available evidence**

## Correlation Validation

- Event ID 4625 failed logons observed: **1**
- Event ID 4624 successful logons observed: **87**
- Failed-logon burst >=5 demonstrated: **0**
- Failed-logon → successful sequences demonstrated: **2**
- PowerShell events observed: **16**
- LSASS access events observed: **28**
- PowerShell → LSASS correlations within 10 minutes: **3**

### Correlation Rule Status

| Correlation | Implementation | Dataset Demonstration |
|---|---|---|
| Failed Logon Burst | Implemented | Not demonstrated |
| Failed Logon → Successful | Implemented | Demonstrated |
| PowerShell → LSASS | Implemented | Demonstrated |

## Evidence Interpretation

A rule match demonstrates that the detection logic identifies matching telemetry in the test dataset. A match alone does not establish malicious intent.

False-positive review was performed using representative telemetry. No tuning change was applied where the available evidence did not justify a safe exclusion.

## Phase 5 Status

**COMPLETE — primary rule testing, false-positive review, final retest, and correlation validation documented.**