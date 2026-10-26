# Phase 3 — MITRE ATT&CK Technique Mapping & Coverage Assessment

## 1. Objective

This document defines the MITRE ATT&CK technique mapping and detection coverage plan for the Cyberion Defense Labs Detection Engineering & Threat Hunting engagement.

The objective is to identify attacker behaviors observable in the selected telemetry, map those behaviors to MITRE ATT&CK techniques, identify the relevant log sources and fields, and define the corresponding detection approach.

Coverage classification:

- **Covered** — Dedicated detection rule exists and matching telemetry was observed.
- **Partially Covered** — Supporting telemetry or detection logic exists, but coverage is incomplete or not independently demonstrated.
- **Not Covered** — Sufficient evidence was not available to establish reliable detection coverage.

---

## 2. ATT&CK Coverage Summary

| Tactic | Techniques Assessed |
|---|---:|
| Execution | 2 |
| Credential Access | 3 |
| Persistence | 3 |
| Discovery | 2 |
| Lateral Movement | 2 |
| Defense Evasion | 6 |
| Command and Control | 2 |
| Collection | 1 |
| Exfiltration | 1 |
| Impact | 2 |
| **Total** | **24** |

The assessment spans more than four MITRE ATT&CK tactics and evaluates more than 20 techniques.

---

## 3. Technique-to-Log-Source Mapping

| ATT&CK ID | Technique | Tactic | Log Source / Event | Detection Idea | Status |
|---|---|---|---|---|---|
| T1059.001 | PowerShell | Execution | Sysmon Event ID 1 / PowerShell telemetry | Detect suspicious PowerShell execution and encoded/obfuscated command activity | Covered |
| T1059.003 | Windows Command Shell | Execution | Sysmon Event ID 1 | Detect execution of cmd.exe and suspicious command-line activity | Covered |
| T1003.001 | LSASS Memory | Credential Access | Sysmon Event ID 10 | Detect processes accessing lsass.exe memory | Covered |
| T1110.001 | Password Guessing | Credential Access | Windows Security Event ID 4625 | Detect repeated failed authentication attempts | Partially Covered |
| T1078 | Valid Accounts | Credential Access | Windows Security Event ID 4624 | Detect suspicious successful authentication involving privileged accounts | Covered |
| T1547.001 | Registry Run Keys / Startup Folder | Persistence | Sysmon Event ID 12/13 | Detect modification of Registry Run/RunOnce persistence locations | Covered |
| T1543.003 | Windows Service | Persistence | Windows Security Event ID 7045 | Detect creation of new Windows services | Covered |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Persistence | Windows Security Event ID 4698/4702 | Detect creation or modification of scheduled tasks | Covered |
| T1087 | Account Discovery | Discovery | Sysmon Event ID 1 | Detect execution of whoami.exe and account discovery commands | Covered |
| T1082 | System Information Discovery | Discovery | Sysmon Event ID 1 | Detect systeminfo.exe and hostname.exe execution | Covered |
| T1021.001 | Remote Services: RDP | Lateral Movement | Terminal Services Event ID 1149 | Detect RDP authentication activity | Covered |
| T1021.002 | Remote Services: SMB/Windows Admin Shares | Lateral Movement | Windows Security Event ID 5145 | Detect access to administrative SMB shares such as IPC$ | Covered |
| T1055 | Process Injection | Defense Evasion | Sysmon Event ID 8 | Detect remote thread creation/injection between processes | Covered |
| T1112 | Modify Registry | Defense Evasion | Sysmon Event ID 12/13 | Detect suspicious registry modification | Covered |
| T1027 | Obfuscated/Compressed Files or Information | Defense Evasion | PowerShell Event ID 4104 / Sysmon | Detect Base64 decoding, Gzip decompression and encoded PowerShell | Partially Covered |
| T1070.004 | File Deletion | Defense Evasion | Sysmon Event ID 23 | Detect deletion of files after suspicious activity | Covered |
| T1070.001 | Clear Windows Event Logs | Defense Evasion | Windows Security Event ID 1102 | Detect clearing of the Windows Security event log | Partially Covered |
| T1105 | Ingress Tool Transfer | Command and Control | Sysmon Event ID 1 | Detect BITS/bitsadmin or similar mechanisms downloading tools | Covered |
| T1071.001 | Web Protocols | Command and Control | Sysmon Event ID 1 | Detect suspicious HTTP/HTTPS activity from command-line tools | Covered |
| T1005 | Data from Local System | Collection | Sysmon Event ID 1 | Identify suspicious local file collection/copy activity | Partially Covered |
| T1048 | Exfiltration Over Alternative Protocol | Exfiltration | Process/network-related telemetry | Detect suspicious data transfer using alternative protocols | Not Covered |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Defense Evasion | Windows/Sysmon telemetry | Detect security-tool or logging configuration changes | Not Covered |
| T1486 | Data Encrypted for Impact | Impact | File/process telemetry | Detect ransomware-style mass file encryption | Not Covered |
| T1490 | Inhibit System Recovery | Impact | Windows process telemetry | Detect deletion or modification of recovery mechanisms | Not Covered |

---

## 4. Detailed Detection Mapping

### T1059.001 — PowerShell

- **Tactic:** Execution
- **Log Source:** Sysmon Event ID 1 / PowerShell telemetry
- **Detection Idea:** Identify PowerShell execution involving encoded or obfuscated content.
- **Supporting Rule:** `rules/proc_powershell_obfuscated.yml`
- **Coverage:** Covered

### T1059.003 — Windows Command Shell

- **Tactic:** Execution
- **Log Source:** Sysmon Event ID 1
- **Detection Idea:** Detect execution of cmd.exe and suspicious command-line parameters.
- **Supporting Rule:** `rules/proc_cmd_shell.yml`
- **Coverage:** Covered

### T1003.001 — LSASS Memory

- **Tactic:** Credential Access
- **Log Source:** Sysmon Event ID 10
- **Detection Idea:** Detect processes requesting access to lsass.exe memory.
- **Supporting Rule:** `rules/lsass_memory_access.yml`
- **Coverage:** Covered

### T1110.001 — Password Guessing

- **Tactic:** Credential Access
- **Log Source:** Windows Security Event ID 4625
- **Detection Idea:** Detect repeated failed authentication attempts.
- **Supporting Rule:** `rules/base_failed_logon.yml`
- **Coverage:** Partially Covered
- **Limitation:** Only one Event ID 4625 event was available, so a repeated failed-logon pattern could not be demonstrated.

### T1078 — Valid Accounts

- **Tactic:** Credential Access
- **Log Source:** Windows Security Event ID 4624
- **Detection Idea:** Detect successful authentication involving privileged or sensitive accounts.
- **Supporting Rule:** `rules/valid_accounts_admin_logon.yml`
- **Coverage:** Covered

### T1547.001 — Registry Run Keys / Startup Folder

- **Tactic:** Persistence
- **Log Source:** Sysmon Event ID 12/13
- **Detection Idea:** Detect modifications to Registry Run and RunOnce persistence locations.
- **Supporting Rule:** `rules/registry_run_keys.yml`
- **Coverage:** Covered

### T1543.003 — Windows Service

- **Tactic:** Persistence
- **Log Source:** Windows Security Event ID 7045
- **Detection Idea:** Detect creation of new Windows services.
- **Supporting Rule:** `rules/service_creation.yml`
- **Coverage:** Covered

### T1053.005 — Scheduled Task

- **Tactic:** Persistence
- **Log Source:** Windows Security Event ID 4698/4702
- **Detection Idea:** Detect creation or modification of scheduled tasks.
- **Supporting Rule:** `rules/scheduled_task_creation.yml`
- **Coverage:** Covered

### T1087 — Account Discovery

- **Tactic:** Discovery
- **Log Source:** Sysmon Event ID 1
- **Detection Idea:** Detect whoami.exe and account enumeration commands.
- **Supporting Rule:** `rules/account_discovery.yml`
- **Coverage:** Covered

### T1082 — System Information Discovery

- **Tactic:** Discovery
- **Log Source:** Sysmon Event ID 1
- **Detection Idea:** Detect systeminfo.exe and hostname.exe execution.
- **Supporting Rule:** `rules/system_information_discovery.yml`
- **Coverage:** Covered

### T1021.001 — Remote Services: RDP

- **Tactic:** Lateral Movement
- **Log Source:** Terminal Services Event ID 1149
- **Detection Idea:** Detect RDP authentication activity and investigate source/user context.
- **Supporting Rule:** `rules/rdp_remote_service.yml`
- **Coverage:** Covered

### T1021.002 — Remote Services: SMB/Windows Admin Shares

- **Tactic:** Lateral Movement
- **Log Source:** Windows Security Event ID 5145
- **Detection Idea:** Detect access to administrative SMB shares.
- **Supporting Rule:** `rules/smb_admin_share.yml`
- **Coverage:** Covered

### T1055 — Process Injection

- **Tactic:** Defense Evasion
- **Log Source:** Sysmon Event ID 8
- **Detection Idea:** Detect remote thread creation/injection between processes.
- **Supporting Rule:** `rules/process_injection.yml`
- **Coverage:** Covered

### T1112 — Modify Registry

- **Tactic:** Defense Evasion
- **Log Source:** Sysmon Event ID 12/13
- **Detection Idea:** Detect suspicious registry modifications.
- **Supporting Rule:** `rules/modify_registry_portproxy.yml`
- **Coverage:** Covered

### T1027 — Obfuscated/Compressed Files or Information

- **Tactic:** Defense Evasion
- **Log Source:** PowerShell Event ID 4104 / Sysmon
- **Detection Idea:** Detect Base64 decoding, Gzip decompression and encoded PowerShell.
- **Coverage:** Partially Covered
- **Limitation:** Supporting telemetry exists, but no dedicated Phase 2 rule was implemented.

### T1070.004 — File Deletion

- **Tactic:** Defense Evasion
- **Log Source:** Sysmon Event ID 23
- **Detection Idea:** Detect file deletion activity and correlate with suspicious process activity.
- **Supporting Rule:** `rules/file_deletion.yml`
- **Coverage:** Covered

### T1070.001 — Clear Windows Event Logs

- **Tactic:** Defense Evasion
- **Log Source:** Windows Security Event ID 1102
- **Detection Idea:** Detect clearing of the Windows Security event log.
- **Coverage:** Partially Covered
- **Limitation:** Event ID 1102 telemetry was observed, but no dedicated Phase 2 Sigma rule was implemented.

### T1105 — Ingress Tool Transfer

- **Tactic:** Command and Control
- **Log Source:** Sysmon Event ID 1
- **Detection Idea:** Detect BITS/bitsadmin or similar utilities downloading files.
- **Supporting Rule:** `rules/bits_ingress_tool_transfer.yml`
- **Coverage:** Covered

### T1071.001 — Web Protocols

- **Tactic:** Command and Control
- **Log Source:** Sysmon Event ID 1
- **Detection Idea:** Identify HTTP/HTTPS activity from command-line tools.
- **Supporting Rule:** `rules/web_protocol_activity.yml`
- **Coverage:** Covered

### T1005 — Data from Local System

- **Tactic:** Collection
- **Log Source:** Sysmon Event ID 1
- **Detection Idea:** Identify suspicious local file-copy operations.
- **Coverage:** Partially Covered
- **Limitation:** Relevant process telemetry exists, but malicious collection intent cannot be established for every matching event.

### T1048 — Exfiltration Over Alternative Protocol

- **Tactic:** Exfiltration
- **Log Source:** Process/network-related telemetry
- **Detection Idea:** Identify suspicious data transfer using alternative protocols.
- **Coverage:** Not Covered
- **Reason:** Available keyword matches were insufficient to establish confirmed exfiltration behavior.

### T1562.001 — Impair Defenses

- **Tactic:** Defense Evasion
- **Log Source:** Windows/Sysmon telemetry
- **Detection Idea:** Detect modification or disabling of security controls or logging.
- **Coverage:** Not Covered
- **Reason:** No sufficiently confirmed telemetry was identified.

### T1486 — Data Encrypted for Impact

- **Tactic:** Impact
- **Log Source:** File/process telemetry
- **Detection Idea:** Detect suspicious mass file encryption.
- **Coverage:** Not Covered
- **Reason:** No sufficiently confirmed ransomware encryption telemetry was identified.

### T1490 — Inhibit System Recovery

- **Tactic:** Impact
- **Log Source:** Windows process telemetry
- **Detection Idea:** Detect deletion or modification of recovery mechanisms.
- **Coverage:** Not Covered
- **Reason:** No sufficiently confirmed telemetry was identified.

---

## 5. Coverage Classification

### Covered

16 techniques currently have dedicated detection rules with matching telemetry:

- T1059.001
- T1059.003
- T1003.001
- T1055
- T1547.001
- T1543.003
- T1053.005
- T1078
- T1087
- T1082
- T1021.001
- T1021.002
- T1112
- T1070.004
- T1105
- T1071.001

### Partially Covered

- T1110.001
- T1027
- T1070.001
- T1005

### Not Covered

- T1048
- T1562.001
- T1486
- T1490

---

## 6. Correlation Detection Coverage

### Failed Logon Burst

- **Technique:** T1110.001
- **Status:** Implemented but not demonstrated
- **Reason:** Only one Event ID 4625 event was available.

### Failed Logon Followed by Successful Logon

- **Techniques:** T1110.001 / T1078
- **Status:** Implemented and demonstrated
- **Evidence:** The Phase 5 correlation validation identified 2 matching failed-logon-to-successful-logon sequences. The dataset contained 1 Event ID 4625 event and 87 Event ID 4624 events; one failed-logon event can match multiple successful-logon events within the configured 15-minute window.
- **Limitation:** This demonstrates matching event sequences in the dataset, not confirmed malicious activity.

### PowerShell Followed by LSASS Access

- **Techniques:** T1059.001 / T1003.001
- **Status:** Validated
- **Result:** Three same-host PowerShell-to-LSASS sequences occurred within the 10-minute analysis window.

---

## 7. ATT&CK Coverage Planning

Priority areas for subsequent threat hunting and investigation include:

1. Credential Access
2. Persistence
3. Lateral Movement
4. Defense Evasion
5. Command and Control
6. Discovery

Techniques marked Partially Covered or Not Covered provide candidates for future threat-hunting analysis where suitable telemetry exists.

At least one threat hunt should target a technique that is not already covered by a dedicated detection rule.

---

## 8. Evidence and Reproducibility

Coverage classifications are based on the selected EVTX-ATTACK-SAMPLES telemetry and the detection testing performed during the detection-engineering phase.

A technique is classified as Covered only when:

1. A dedicated detection rule exists.
2. Matching telemetry was observed in the selected dataset.

Where evidence is insufficient, the technique remains Partially Covered or Not Covered.

---

## 9. Phase 3 Conclusion

The ATT&CK mapping establishes a documented technique-level coverage baseline across more than four tactics and more than 20 assessed techniques.

Current assessment:

- **16 Covered**
- **4 Partially Covered**
- **4 Not Covered**
- **24 techniques assessed**

This mapping will serve as the reference baseline for the threat-hunting, incident-investigation, playbook and final reporting phases.
