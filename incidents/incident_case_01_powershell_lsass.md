# Incident Case 01 — PowerShell-to-LSASS Correlation

## Case Status
INVESTIGATION LEAD — NOT A CONFIRMED INCIDENT

## 1. Objective
Investigate observed PowerShell activity followed by LSASS memory-access events in the EVTX-ATTACK-SAMPLES dataset.

## 2. Evidence Sources
- `AutomatedTestingTools/PanacheSysmon_vs_AtomicRedTeam01.evtx`
- `Credential Access/babyshark_mimikatz_powershell.evtx`
- `reports/phase5_final_evidence.md`
- `reports/phase5_final_retest.md`
- `hunts/hunt_01_powershell_lsass_correlation.md`

## 3. Observed Timeline

| Match | PowerShell timestamp | LSASS access timestamp | Interval | Source |
|---|---|---|---:|---|
| 1 | 2019-07-19 15:09:59.931135 | 2019-07-19 15:11:16.487989 | 76.6 seconds | PanacheSysmon_vs_AtomicRedTeam01.evtx |
| 2 | 2019-04-18 16:56:08.370066 | 2019-04-18 16:58:14.811880 | 126.4 seconds | babyshark_mimikatz_powershell.evtx |
| 3 | 2019-04-18 16:56:08.370066 | 2019-04-18 17:01:35.720774 | 327.4 seconds | babyshark_mimikatz_powershell.evtx |

The second and third matches reuse the same PowerShell event and pair it with two LSASS events. They are not three independent incidents.

## 4. Evidence and Findings
- Three PowerShell-to-LSASS correlations were observed within the configured 10-minute window.
- The LSASS access records identify PowerShell as the source image.
- The existing parser did not populate host or username for these records.
- The evidence does not establish credential theft, successful compromise, or malicious intent.

## 5. ATT&CK Mapping
- Candidate technique: T1059.001 — PowerShell.
- Candidate technique: T1003.001 — LSASS Memory.
- These are investigative mappings based on the observed behavior, not confirmation that either technique was successfully used maliciously.

## 6. Root-Cause Assessment
Undetermined. Available records show a process-access correlation but do not provide sufficient host, user, process lineage, access-rights, or surrounding-event context to determine why the access occurred.

## 7. Impact Assessment
Unknown. No confirmed credential disclosure, account compromise, lateral movement, or business impact is established by the available evidence.

## 8. Recommended Response
1. Retrieve the original event records and preserve their integrity.
2. Recover the System `Computer` field and relevant event data.
3. Correlate process IDs, parent process, user, access details, and nearby telemetry.
4. Check for corroborating credential-access indicators and suspicious authentication activity.
5. If validated in a real environment, follow the organization's incident-response process before isolating a host or taking containment action.

## 9. Closure Assessment
Status: OPEN — PENDING CONTEXTUAL VALIDATION.

The case remains an investigation lead. Do not declare a confirmed incident or close it as benign without additional evidence.

## 10. Limitations
This is a retrospective investigation of a sample dataset, not a live environment. Host identity and user context remain unverified. No containment, eradication, or recovery action was performed.
