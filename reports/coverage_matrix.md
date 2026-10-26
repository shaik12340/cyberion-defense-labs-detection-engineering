# ATT&CK Detection Coverage Matrix

## Project

Cyberion Defense Labs — Detection Engineering & Threat Hunting

## Dataset

- **Dataset:** EVTX-ATTACK-SAMPLES
- **Events analyzed:** 37,364
- **EVTX files analyzed:** 278

## Coverage Classification

- **Covered:** Dedicated detection rule exists and matching telemetry was observed.
- **Partially Covered:** Supporting telemetry or detection logic exists, but dedicated/complete coverage was not demonstrated.
- **Not Covered:** Sufficient confirmed telemetry was not available to establish detection coverage.

---

## ATT&CK Coverage Matrix

| ATT&CK ID | Technique | Tactic | Log Source / Event | Supporting Rule | Status |
|---|---|---|---|---|---|
| T1059.001 | PowerShell | Execution | Sysmon Event ID 1 / PowerShell telemetry | proc_powershell_obfuscated.yml | Covered |
| T1059.003 | Windows Command Shell | Execution | Sysmon Event ID 1 | proc_cmd_shell.yml | Covered |
| T1003.001 | LSASS Memory | Credential Access | Sysmon Event ID 10 | lsass_memory_access.yml | Covered |
| T1110.001 | Password Guessing | Credential Access | Security Event ID 4625 | base_failed_logon.yml | Partially Covered |
| T1078 | Valid Accounts | Credential Access | Security Event ID 4624 | valid_accounts_admin_logon.yml | Covered |
| T1547.001 | Registry Run Keys / Startup Folder | Persistence | Sysmon Event ID 12/13 | registry_run_keys.yml | Covered |
| T1543.003 | Windows Service | Persistence | Security Event ID 7045 | service_creation.yml | Covered |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Persistence | Security Event ID 4698/4702 | scheduled_task_creation.yml | Covered |
| T1087 | Account Discovery | Discovery | Sysmon Event ID 1 | account_discovery.yml | Covered |
| T1082 | System Information Discovery | Discovery | Sysmon Event ID 1 | system_information_discovery.yml | Covered |
| T1021.001 | Remote Services: RDP | Lateral Movement | Event ID 1149 | rdp_remote_service.yml | Covered |
| T1021.002 | SMB/Windows Admin Shares | Lateral Movement | Security Event ID 5145 | smb_admin_share.yml | Covered |
| T1055 | Process Injection | Defense Evasion | Sysmon Event ID 8 | process_injection.yml | Covered |
| T1112 | Modify Registry | Defense Evasion | Sysmon Event ID 12/13 | modify_registry_portproxy.yml | Covered |
| T1027 | Obfuscated/Compressed Files or Information | Defense Evasion | PowerShell Event ID 4104 / Sysmon | — | Partially Covered |
| T1070.004 | File Deletion | Defense Evasion | Sysmon Event ID 23 | file_deletion.yml | Covered |
| T1070.001 | Clear Windows Event Logs | Defense Evasion | Security Event ID 1102 | — | Partially Covered |
| T1105 | Ingress Tool Transfer | Command and Control | Sysmon Event ID 1 | bits_ingress_tool_transfer.yml | Covered |
| T1071.001 | Web Protocols | Command and Control | Sysmon Event ID 1 | web_protocol_activity.yml | Covered |
| T1005 | Data from Local System | Collection | Sysmon/process telemetry | — | Partially Covered |
| T1048 | Exfiltration Over Alternative Protocol | Exfiltration | Insufficient confirmed evidence | — | Not Covered |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Defense Evasion | No confirmed dataset evidence | — | Not Covered |
| T1486 | Data Encrypted for Impact | Impact | No confirmed dataset evidence | — | Not Covered |
| T1490 | Inhibit System Recovery | Impact | No confirmed dataset evidence | — | Not Covered |

---

## Coverage Summary

### Covered

**16 techniques** currently have dedicated Sigma detection rules with matching telemetry.

- T1059.001 — PowerShell
- T1059.003 — Windows Command Shell
- T1003.001 — LSASS Memory
- T1055 — Process Injection
- T1547.001 — Registry Run Keys / Startup Folder
- T1543.003 — Windows Service
- T1053.005 — Scheduled Task
- T1078 — Valid Accounts
- T1087 — Account Discovery
- T1082 — System Information Discovery
- T1021.001 — RDP
- T1021.002 — SMB/Windows Admin Shares
- T1112 — Modify Registry
- T1070.004 — File Deletion
- T1105 — Ingress Tool Transfer
- T1071.001 — Web Protocols

### Partially Covered

**4 techniques** have supporting telemetry or detection concepts but do not currently have equivalent dedicated validated detection coverage.

- T1110.001 — Password Guessing
- T1070.001 — Clear Windows Event Logs
- T1027 — Obfuscated/Compressed Files or Information
- T1005 — Data from Local System

### Not Covered

**4 techniques** were assessed but did not have sufficient confirmed telemetry for detection coverage.

- T1048 — Exfiltration Over Alternative Protocol
- T1562.001 — Impair Defenses
- T1486 — Data Encrypted for Impact
- T1490 — Inhibit System Recovery

---

## Correlation Coverage

| Correlation Detection | ATT&CK Technique(s) | Status | Evidence |
|---|---|---|---|
| Failed Logon Burst | T1110.001 | Implemented but not demonstrated | Only one Event ID 4625 event available |
| Failed Logon → Successful Logon | T1110.001 / T1078 | Implemented and demonstrated | Phase 5 validation found 2 matching sequences involving 1 Event ID 4625 event and 87 Event ID 4624 events within the 15-minute window; matching sequences do not prove malicious activity |
| PowerShell → LSASS Access | T1059.001 / T1003.001 | Validated | Three same-host sequences within 10 minutes |

---

## Coverage Planning

The matrix provides the baseline for subsequent threat hunting and incident investigation.

Priority areas include:

1. Credential Access
2. Persistence
3. Lateral Movement
4. Defense Evasion
5. Command and Control
6. Discovery

Techniques marked **Partially Covered** or **Not Covered** provide candidates for subsequent threat-hunting analysis where suitable telemetry exists.

At least one threat hunt should target a technique that is not already covered by a dedicated detection rule.

---

## Evidence Standard

A technique is classified as **Covered** only when:

1. A dedicated detection rule exists.
2. Matching telemetry was observed in the selected dataset.

Where evidence is insufficient, the technique remains **Partially Covered** or **Not Covered**.

---

## Phase 3 Assessment

| Metric | Result |
|---|---:|
| Techniques assessed | 24 |
| Covered | 16 |
| Partially Covered | 4 |
| Not Covered | 4 |
| Tactics represented | 10 |
| Dedicated Sigma rules supporting coverage | 16 |

**Phase 3 ATT&CK mapping baseline completed.**
