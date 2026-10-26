# Hunt 02 — Failed Logon Followed by Successful Logon

## Objective
Identify accounts with a failed logon followed by a successful logon within a short time window, which may warrant investigation when combined with other suspicious activity.

## Hypothesis
A failed logon followed by a successful logon for the same user within 15 minutes may indicate a successful retry, password guessing, or other suspicious authentication activity.

## Data Sources
- Windows Security Event ID 4625: failed logon.
- Windows Security Event ID 4624: successful logon.
## Status
Two initial threat-hunting reports have been documented using existing Phase 5 correlation-validation evidence.

## Hunt Reports
1. `hunts/hunt_01_powershell_lsass_correlation.md`
2. `hunts/hunt_02_failed_logon_followed_by_success.md`

## Evidence

Event-level evidence for the failed-logon-to-success sequence is documented in the Event-Level Evidence Review section below. The matching records come from the same source EVTX file; the failed event is paired with two successful-logon records approximately 4.1 seconds later. These matches are investigative leads and do not independently establish malicious activity.

## Evidence Summary
- PowerShell-to-LSASS correlation: 3 matching sequences within 10 minutes.
- Failed-logon-to-successful-logon correlation: 2 matching sequences within 15 minutes.
- Failed-logon burst: implemented but not demonstrated in the available validation run.

## Interpretation
These results represent matches in a sample dataset. They do not establish confirmed malicious activity or a real-world incident. The failed-logon correlation may pair one failed event with multiple successful events, so sequence counts must not be treated as independent attack counts.

## Remaining Validation
- Review individual event timestamps, host and user context, process details, and source addresses where available.
- Confirm that each hunt's evidence can be traced to the underlying events or validation output.
- Add further hunts only when supported by available telemetry.

## Scope
No live environment was queried, and no dataset or detection rule was modified as part of documenting these hunts.

## Findings

One failed logon event for `IEUser` was followed by two successful-logon records approximately 4.1 seconds later. Both matches reuse the same failed event, so they do not represent two independent failed attempts. The available evidence does not establish malicious activity.

## Event-Level Evidence Review

The existing Phase 5 correlation logic identified two matching records for the same account in the same EVTX file.

| Record | Event ID | Timestamp | Account | EVTX source |
|---|---:|---|---|---|
| Failed logon | 4625 | 2020-09-09 13:18:23.627951 | `IEUser` | `Credential Access/CA_4624_4625_LogonType2_LogonProc_chrome.evtx` |
| Successful logon A | 4624 | 2020-09-09 13:18:27.714613 | `IEUser` | Same file |
| Successful logon B | 4624 | 2020-09-09 13:18:27.714758 | `IEUser` | Same file |

Both successful logons occurred approximately 4.1 seconds after the failed logon. The two matches share one failed-logon event and must not be counted as two independent failed attempts.

### Evidence Limitations
The extracted host field was empty. Source IP address, logon type and other authentication context were not captured in the displayed evidence. The sequence alone does not prove password guessing, account compromise or malicious activity.

## Conclusion

The hypothesis is supported as a candidate authentication sequence in the sample dataset. Host and additional authentication context remain unavailable in the extracted evidence. Further investigation is required before determining whether the activity was malicious.

## Detection Improvement
Extract the System `Computer` field and relevant Security event fields, including source IP, logon type and status/substatus where available. Enrich alerts with nearby authentication activity and investigate repeated failures, unusual source addresses and subsequent account activity before assigning severity.
