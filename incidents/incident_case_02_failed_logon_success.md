# Incident Case 02 — Failed Logon Followed by Successful Logons

## Case Status
INVESTIGATION LEAD — NOT A CONFIRMED INCIDENT

## 1. Objective
Review a failed Windows logon followed shortly by successful-logon records for the same account in the sample dataset.

## 2. Evidence Source
- `Credential Access/CA_4624_4625_LogonType2_LogonProc_chrome.evtx`
- `reports/phase5_final_evidence.md`
- `hunts/hunt_02_failed_logon_followed_by_success.md`

## 3. Observed Timeline

| Record | Event ID | Timestamp | Account |
|---|---:|---|---|
| Failed logon | 4625 | 2020-09-09 13:18:23.627951 | `IEUser` |
| Successful logon A | 4624 | 2020-09-09 13:18:27.714613 | `IEUser` |
| Successful logon B | 4624 | 2020-09-09 13:18:27.714758 | `IEUser` |

Both successful-logon records occurred approximately 4.1 seconds after the failed event. Both correlation matches reuse the same failed-logon event; they must not be interpreted as two independent failed attempts.

## 4. Evidence and Findings
- One Event ID 4625 record and two Event ID 4624 records were identified for `IEUser`.
- The records came from the same EVTX file.
- The extracted host field was empty.
- Source IP, logon type, status/substatus, and additional authentication context were not captured in the reviewed evidence.
- The sequence alone does not prove password guessing, account compromise, or malicious activity.

## 5. ATT&CK Mapping
No ATT&CK technique is confirmed from this sequence alone. Authentication-related techniques may be considered only if additional evidence establishes suspicious behavior.

## 6. Root-Cause Assessment
Undetermined. The records may reflect an ordinary authentication sequence or suspicious activity. Available evidence is insufficient to distinguish these possibilities.

## 7. Impact Assessment
Unknown. No unauthorized access, account takeover, data access, or business impact has been demonstrated.

## 8. Recommended Response
1. Inspect the original Windows Security event records.
2. Recover the host, source IP, logon type, status/substatus, and available account context.
3. Correlate nearby failed and successful logons without double-counting reused events.
4. Review subsequent account activity and other corroborating security events.
5. If the sequence is validated in a real environment as suspicious, follow the organization's authentication-incident response process.

## 9. Closure Assessment
Status: OPEN — PENDING AUTHENTICATION-CONTEXT VALIDATION.

Keep the case as an investigation lead until the source and legitimacy of the logons can be assessed. Do not label the account compromised based only on these records.

## 10. Limitations
This is a retrospective analysis of sample telemetry. Host and authentication context are incomplete. No account changes, containment, or other live response actions were performed.
