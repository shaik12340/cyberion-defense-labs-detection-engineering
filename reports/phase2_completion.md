# Phase 2 — Detection Engineering Validation

## Project
Cyberion Defense Labs — Detection Engineering & Threat Hunting

## Phase 2 Scope

Phase 2 focused on Sigma detection engineering, ATT&CK mapping, correlation logic, and validation against the locally analyzed EVTX-ATTACK-SAMPLES telemetry.

## Telemetry Dataset

- Dataset: EVTX-ATTACK-SAMPLES
- Total events analyzed: 37,364
- EVTX files analyzed: 278
- Parsing errors during dataset inventory: 0

## Sigma Detection Rules

A total of 16 primary Sigma detection rules were implemented.

| # | Rule | ATT&CK Technique | Matches | Status |
|---:|---|---|---:|---|
| 1 | proc_powershell_obfuscated.yml | T1059.001 | 3 | PASS |
| 2 | proc_cmd_shell.yml | T1059.003 | 305 | PASS |
| 3 | lsass_memory_access.yml | T1003.001 | 28 | PASS |
| 4 | process_injection.yml | T1055 | 104 | PASS |
| 5 | registry_run_keys.yml | T1547.001 | 12 | PASS |
| 6 | service_creation.yml | T1543.003 | 4 | PASS |
| 7 | scheduled_task_creation.yml | T1053.005 | 8 | PASS |
| 8 | valid_accounts_admin_logon.yml | T1078 | 14 | PASS |
| 9 | rdp_remote_service.yml | T1021.001 | 11 | PASS |
| 10 | smb_admin_share.yml | T1021.002 | 44 | PASS |
| 11 | system_information_discovery.yml | T1082 | 2 | PASS |
| 12 | bits_ingress_tool_transfer.yml | T1105 | 16 | PASS |
| 13 | web_protocol_activity.yml | T1071.001 | 43 | PASS |
| 14 | modify_registry_portproxy.yml | T1112 | 3 | PASS |
| 15 | file_deletion.yml | T1070.004 | 3 | PASS |

### Primary Rule Testing Summary

- Primary Sigma rules tested: 16
- Rules with matching telemetry: 16
- Rules without matching telemetry: 0
- Rule YAML structural validation errors: 0

The testing harness confirmed matching telemetry for all 15 primary rules.

## Correlation Rules

Five correlation/base rule files were implemented:

1. base_failed_logon.yml
2. base_successful_logon.yml
3. mr_failed_logon_burst.yml
4. mr_failed_then_success.yml
5. mr_lsass_plus_powershell.yml

All five files passed structural YAML validation.

### PowerShell + LSASS Correlation

The dataset contained:

- PowerShell process events: 16
- LSASS access events: 28
- Same-host PowerShell and LSASS events within 10 minutes: 3

Observed examples:

| Host | PowerShell Time | LSASS Time | Difference |
|---|---|---|---:|
| MSEDGEWIN10 | 2019-07-19 15:10:52.700901 | 2019-07-19 15:11:16.986675 | 24.29 seconds |
| IEWIN7 | 2019-04-18 16:56:24.893827 | 2019-04-18 16:58:14.871967 | 109.98 seconds |
| IEWIN7 | 2019-04-18 16:56:24.893827 | 2019-04-18 17:01:49.961250 | 325.07 seconds |

This provides dataset-backed evidence for the PowerShell-to-LSASS temporal correlation.

### Failed Logon Correlations

The dataset contained:

- Event ID 4625 (failed logon): 1
- Event ID 4624 (successful logon): 87

Because only one failed-logon event was available, the following correlations were not demonstrated by the available telemetry:

- Failed logon burst requiring five or more failures within five minutes.
- Failed logons followed by a successful logon within the defined correlation window.

These correlations remain implemented detection logic but are not marked as dataset-validated.

## Validation Method

The primary rules were tested against locally parsed EVTX telemetry using the project's Python testing harness.

The testing harness checks detection-relevant fields and records:

- Rule filename
- ATT&CK tag
- Matching event count
- Example telemetry source
- Event ID

The harness is an evidence-testing utility and is not a replacement for full production SIEM/Sigma backend semantic validation.

## Quality and Limitations

- Matching telemetry does not by itself establish malicious intent.
- Some rules may require tuning in a production environment.
- Broad process or network indicators can generate legitimate administrative activity.
- Correlation rules require sufficient event volume and temporal relationships in the available dataset.
- Production deployment and live SIEM validation are outside the current project scope.

## Phase 2 Completion Status

### Completed

- [x] 16 primary Sigma rules implemented
- [x] Sigma YAML structural validation
- [x] 16/16 primary rules matched available telemetry
- [x] 3 correlation detections implemented
- [x] 2 correlation base rules implemented
- [x] Correlation YAML validation
- [x] PowerShell + LSASS temporal correlation validated
- [x] Correlation limitations documented
- [x] Rule testing evidence report generated

### Phase 2 Evidence

Primary rule test results:

`reports/rule_test_results.md`

ATT&CK coverage matrix:

`reports/coverage_matrix.md`

Data dictionary:

`reports/data_dictionary.md`

ATT&CK technique mapping:

`reports/attack_technique_mapping.md`

## Conclusion

Phase 2 detection engineering and telemetry validation activities have been completed based on the available EVTX-ATTACK-SAMPLES dataset. The project contains 16 primary Sigma rules with matching telemetry, three correlation detections, two correlation base rules, and documented evidence and limitations.
