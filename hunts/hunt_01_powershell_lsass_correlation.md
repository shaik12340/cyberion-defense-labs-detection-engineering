# Hunt 01 — PowerShell Activity Followed by LSASS Access

## Objective
Investigate whether PowerShell process activity is followed by access to the Local Security Authority Subsystem Service (LSASS), which can be relevant to credential-access investigations.

## Hypothesis
PowerShell activity followed by LSASS access on the same host within 10 minutes may indicate suspicious credential-access behavior and deserves further investigation.

## Data Sources
- Windows Security telemetry: Event ID 10, process access to LSASS where available in the dataset.
- Sysmon telemetry: Event ID 1, process creation including PowerShell activity.
- Dataset: `data/raw/EVTX-ATTACK-SAMPLES/`

## Hunting Method
1. Identify PowerShell-related process creation events.
2. Identify LSASS process-access events.
3. Correlate events on the same host within a 10-minute window.
4. Review process details, user context, timestamps, access details, and surrounding activity before determining whether activity is malicious.

## Evidence
The Phase 5 correlation validation reported:
- PowerShell Event ID 1 events: 16.
- LSASS Event ID 10 events: 28.
- Matching PowerShell-to-LSASS sequences within 10 minutes: 3.
- Correlation validation: structural checks passed for the relevant correlation rule.

Supporting validation artifacts:
- `reports/phase5_final_evidence.md`
- `reports/phase5_final_retest.md`
- `tests/phase5_correlation_validation.py`

## Findings
Three matching sequences were identified by the validation script. These are candidate investigation leads, not confirmed malicious incidents. The current summary evidence does not provide the individual timestamps, process identifiers, usernames, or LSASS access details needed to determine intent.

## Conclusion
The hypothesis is supported at the correlation level: the dataset contains three matching sequences. Additional event-level investigation is required before assigning a malicious verdict.

## Detection Improvement
- Preserve host, timestamp, process ID, parent process, user, and LSASS access details in alert evidence.
- Enrich alerts with process command lines and related process-creation events.
- Add allowlisting only after validating known legitimate software and administrative activity.
- Test the rule against benign administrative activity to assess false positives.

## Limitations
This is a retrospective hunt against a sample dataset, not a live enterprise environment. A correlation match alone does not prove credential theft or compromise.

## Event-Level Evidence Review

The existing Phase 5 correlation logic was reused to inspect the matching records.

| Match | PowerShell timestamp | LSASS access timestamp | Delta | EVTX source |
|---|---|---|---:|---|
| 1 | 2019-07-19 15:09:59.931135 | 2019-07-19 15:11:16.487989 | 76.6 seconds | `AutomatedTestingTools/PanacheSysmon_vs_AtomicRedTeam01.evtx` |
| 2 | 2019-04-18 16:56:08.370066 | 2019-04-18 16:58:14.811880 | 126.4 seconds | `Credential Access/babyshark_mimikatz_powershell.evtx` |
| 3 | 2019-04-18 16:56:08.370066 | 2019-04-18 17:01:35.720774 | 327.4 seconds | `Credential Access/babyshark_mimikatz_powershell.evtx` |

The LSASS access records identify PowerShell as the source image. The same PowerShell event is associated with two LSASS events in the second source file.

### Evidence Limitations
The existing parser did not populate host or username values for these records. Host-level identity and user context therefore remain unverified. These matches support further investigation but do not establish malicious intent.

### Detection Improvement
Preserve the Windows System `Computer` field and relevant event data fields during extraction. Include process identifiers, user context, access details and surrounding events in future hunt evidence.
