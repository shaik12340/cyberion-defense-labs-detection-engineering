# Cyberion Defense Labs
# Detection Engineering & Threat Hunting
## MITRE ATT&CK Technique Mapping

---

## Purpose

This document maps observed Windows telemetry to MITRE ATT&CK
techniques that can be investigated and detected using the available
dataset.

The mapping is based on telemetry fields actually observed during
dataset analysis.

---

## Mapping Method

Each technique is evaluated using:

1. ATT&CK Technique ID
2. ATT&CK Technique Name
3. Tactic
4. Relevant telemetry source
5. Relevant Event ID
6. Observed fields
7. Detection / hunting use case
8. Sigma detection potential

---

# Validated Technique Mapping

The initial technique candidates have been assessed against the
`EVTX-ATTACK-SAMPLES` dataset and the project's detection-engineering
test evidence.

The finalized 24-technique mapping, including ATT&CK ID, technique,
tactic, telemetry, supporting Sigma rule, coverage classification,
and evidence notes, is maintained in:

- `reports/coverage_matrix.md` — human-readable coverage matrix.
- `reports/coverage_matrix.json` — machine-readable coverage data.
- `reports/attack_navigator_layer.json` — ATT&CK Navigator visualization layer.
- `reports/phase3_attack_mapping.md` — technique-mapping methodology and assessment.

## Final Coverage Summary

| Classification | Techniques |
|---|---:|
| Covered | 16 |
| Partially Covered | 4 |
| Not Covered | 4 |
| **Total assessed** | **24** |

## Evidence and Limitations

A covered classification means a supporting detection rule matched telemetry
in the tested dataset. It does not independently prove that an event was
malicious or that a technique will always be detected.

Partially covered techniques have supporting telemetry or detection concepts
but lack equivalent demonstrated dedicated coverage. Not-covered techniques
remain gaps for future telemetry collection, hunting, and detection development.

Correlation validation results are recorded in
`reports/phase5_final_evidence.md`. The failed-logon burst was implemented
but not demonstrated; failed-logon-to-successful-logon and PowerShell-to-LSASS
correlations were demonstrated by the validation script.

The ATT&CK Navigator scores are project-defined visualization values:
100 for Covered, 50 for Partially Covered, and 0 for Not Covered.
They are not official MITRE ATT&CK ratings.
