# Phase 5 — False Positive Review and Rule Tuning

## Purpose

This review evaluates representative matches from the Phase 5 baseline against the EVTX-ATTACK-SAMPLES dataset. The objective is to identify obvious false-positive patterns, document false-positive considerations, and determine whether tuning is justified by the available evidence.

A rule match is treated as detection evidence and not automatically as proof of malicious activity.

---

## Rule 01 — Windows Command Shell Execution

**Rule:** `rules/proc_cmd_shell.yml`
**ATT&CK:** T1059.003 — Windows Command Shell
**Baseline matches:** 305

### Representative evidence reviewed

Two representative Event ID 1 matches were manually inspected from:

`AutomatedTestingTools/Malware/DE_timestomp_and_dll_sideloading_and_RunPersist.evtx`

Observed examples included:

1. `cmd.exe /A`
2. `cmd.exe /c del /q "C:\Users\IEUser\Downloads\Flash_update.exe"`

The events contained process, command-line, parent-process, and user information.

### False-positive consideration

Command shell execution can occur during normal administrative activity, troubleshooting, automation, and software maintenance.

### Tuning decision

**RETAIN — No tuning applied.**

The current rule intentionally detects command-shell execution broadly because the rule objective is to identify Windows Command Shell activity. The available representative evidence did not provide a sufficiently justified exclusion that could be applied without potentially reducing useful coverage.

A match alone must not be interpreted as malicious activity.

---

## Rule 02 — Process Injection

**Rule:** `rules/process_injection.yml`
**ATT&CK:** T1055 — Process Injection
**Baseline matches:** 104

### Representative evidence reviewed

Ten Event ID 8 events were reviewed.

Observed process relationships included:

- `WINWORD.exe` → `explorer.exe`
- `WINWORD.exe` → `WINWORD.exe`
- `KeeFarce.exe` → `KeePass.exe`
- PowerShell → `KeePass.exe`
- `voice_mail.msg.exe` → `lsass.exe`
- `rdrleakdiag.exe` → `lsass.exe`
- `jjs.exe` → `svchost.exe`

### False-positive consideration

Security, monitoring, diagnostic, and other specialized software can legitimately generate process injection telemetry.

### Tuning decision

**RETAIN — No tuning applied.**

The reviewed events contained process relationships relevant to the detection objective. The available evidence did not justify a specific exclusion.

A Sysmon Event ID 8 match should be investigated using the source process, target process, user, command line, and surrounding telemetry.

---

## Rule 03 — Suspicious Web Protocol Activity

**Rule:** `rules/web_protocol_activity.yml`
**ATT&CK:** T1071.001 — Web Protocols
**Baseline matches:** 43

### Representative evidence reviewed

Ten representative Event ID 1 matches were inspected.

Observed examples included:

- `bitsadmin.exe` downloading from an HTTPS URL
- `cscript.exe` executing a script referenced through an HTTPS URL
- `msxsl.exe` using HTTPS resources
- `wmic.exe` using an HTTPS XSL resource
- `regsvr32.exe` using an HTTPS scriptlet URL

Several events showed a process chain involving PowerShell, `cmd.exe`, and the executing utility.

### False-positive consideration

HTTP/HTTPS URLs can also occur in legitimate administrative scripts, software updates, installers, and other normal software activity.

The current dataset samples, however, showed the URL activity occurring within process execution command lines and involving utilities that can be relevant to ATT&CK-based investigations.

### Tuning decision

**RETAIN — No tuning applied at this stage.**

The rule remains intentionally broad because narrowing it to a small list of utilities or URL patterns could reduce coverage of other web-protocol-based activity.

The 43 matches must not be interpreted as 43 confirmed malicious events. Further contextual investigation is required.

---

## Phase 5 Tuning Summary

| Rule | Baseline Matches | Representative Review | Tuning |
|---|---:|---:|---|
| Windows Command Shell Execution | 305 | 2 events | None |
| Process Injection | 104 | 10 events | None |
| Suspicious Web Protocol Activity | 43 | 10 events | None |

### Current conclusion

The first three reviewed rules did not produce sufficient evidence for a justified tuning exclusion.

The rules are therefore retained in their current form. False-positive considerations are documented for analyst investigation rather than introducing unsupported exclusions.

Further rules will be reviewed using the same evidence-based process before Phase 5 is finalized.

---

## Rule 04 — BITS Ingress Tool Transfer

**Rule:** `rules/bits_ingress_tool_transfer.yml`
**ATT&CK:** T1105 — Ingress Tool Transfer
**Baseline matches:** 16

### Representative evidence reviewed

Ten representative Event ID 1 matches were inspected from:

`AutomatedTestingTools/PanacheSysmon_vs_AtomicRedTeam01.evtx`

Observed activity included:

- `bitsadmin.exe /transfer`
- `bitsadmin.exe /create`
- `bitsadmin.exe /addfile`
- `bitsadmin.exe /setnotifycmdline`
- `bitsadmin.exe /complete`
- HTTPS retrieval from a public repository
- Process chains involving PowerShell, `cmd.exe`, and `bitsadmin.exe`

### False-positive consideration

BITS is a legitimate Windows transfer mechanism and can be used by software updates, administration, and other normal system activity.

### Tuning decision

**RETAIN — No tuning applied.**

The reviewed telemetry demonstrates the rule's ability to identify BITS-related transfer activity. However, the available evidence does not establish a sufficiently specific benign pattern that would justify an exclusion.

The 16 matches are detection evidence and should not automatically be classified as malicious.

---

## Updated Phase 5 Review Summary

| Rule | Baseline Matches | Representative Review | Tuning |
|---|---:|---:|---|
| Windows Command Shell Execution | 305 | 2 events | None |
| Process Injection | 104 | 10 events | None |
| Suspicious Web Protocol Activity | 43 | 10 events | None |
| BITS Ingress Tool Transfer | 16 | 10 events | None |

---

## Rule 05 — LSASS Memory Access

**Rule:** `rules/lsass_memory_access.yml`
**ATT&CK:** T1003.001 — LSASS Memory
**Baseline matches:** 28

### Representative evidence reviewed

Ten representative Sysmon Event ID 10 matches were inspected.

Observed source processes accessing `lsass.exe` included:

- `powershell.exe`
- `voice_mail.msg.exe`
- `PPLdump.exe`
- `services.exe`
- `procdump.exe`
- `taskmgr.exe`

Observed `GrantedAccess` values included:

- `0x00001010`
- `0x001f1fff`
- `0x00001000`
- `0x00001410`
- `0x001fffff`

Several representative events originated from files located under the dataset's `Credential Access` samples.

### False-positive consideration

LSASS access can also be generated by legitimate Windows components, diagnostic utilities, administrative tools, and security software.

A Sysmon Event ID 10 match targeting `lsass.exe` should therefore not automatically be classified as credential theft.

### Tuning decision

**RETAIN — No tuning applied.**

The reviewed telemetry did not provide a sufficiently specific benign pattern that would justify an exclusion or source-process allowlist.

For investigation, analysts should correlate `SourceImage`, `TargetImage`, `GrantedAccess`, parent process, user/context, and surrounding events.

---

## Updated Phase 5 Review Summary

| Rule | Baseline Matches | Representative Review | Tuning |
|---|---:|---:|---|
| Windows Command Shell Execution | 305 | 2 events | None |
| Process Injection | 104 | 10 events | None |
| Suspicious Web Protocol Activity | 43 | 10 events | None |
| BITS Ingress Tool Transfer | 16 | 10 events | None |
| LSASS Memory Access | 28 | 10 events | None |

---

## Rule 06 — Windows PortProxy Registry Modification

**Rule:** `rules/modify_registry_portproxy.yml`
**ATT&CK:** T1112 — Modify Registry
**Baseline matches:** 3

### Representative evidence reviewed

All three baseline matches were inspected.

Observed events included:

1. `netsh.exe` modifying a PortProxy entry for `0.0.0.0/8080` with destination `192.168.1.1/8000`.
2. `netsh.exe` creating/modifying the corresponding PortProxy registry entry.
3. `netsh.exe` modifying a PortProxy entry involving `1.2.3.4/8001` and `1.2.3.5/3389`.

The third event originated from:

`Defense Evasion/de_portforward_netsh_rdp_sysmon_13_1.evtx`

### False-positive consideration

Legitimate network configuration can modify Windows PortProxy settings.

### Tuning decision

**RETAIN — No tuning applied.**

All available baseline matches were reviewed, and the evidence did not establish a sufficiently specific benign pattern that would justify an exclusion.

The detection identifies registry modification activity associated with PortProxy configuration. A match should be investigated together with the modifying process, registry values, network context, and surrounding telemetry.

---

## Updated Phase 5 Review Summary

| Rule | Baseline Matches | Representative Review | Tuning |
|---|---:|---:|---|
| Windows Command Shell Execution | 305 | 2 events | None |
| Process Injection | 104 | 10 events | None |
| Suspicious Web Protocol Activity | 43 | 10 events | None |
| BITS Ingress Tool Transfer | 16 | 10 events | None |
| LSASS Memory Access | 28 | 10 events | None |
| Windows PortProxy Registry Modification | 3 | 3 events | None |

---

## Rule 07 — Registry Run Key Modification

**Rule:** `rules/registry_run_keys.yml`
**ATT&CK:** T1547.001 — Registry Run Keys / Startup Folder
**Baseline matches:** 12

### Representative evidence reviewed

Representative Sysmon Event ID 12/13 telemetry was inspected for Registry Run/RunOnce activity.

Observed examples included:

- `NvSmart.exe` creating a Run entry pointing to `svchost.exe`.
- `tendyron.exe` creating a Run entry pointing to itself.
- `reg.exe` creating an Atomic Red Team Run entry.
- PowerShell modifying a `RunOnce` entry containing a `DownloadString(...)` command.
- `svchost.exe` creating a Run entry invoking `Rundll32.exe`.
- `wmiprvse.exe` creating a Run entry invoking `rundll32.exe`.

### False-positive consideration

Legitimate software installation, updates, and configuration activity can modify Registry Run/RunOnce keys.

### Tuning decision

**RETAIN — No tuning applied.**

The reviewed telemetry did not establish a sufficiently specific benign pattern that would justify an exclusion or executable allowlist.

The detection should be investigated using the modifying process, registry path, value/details, user context, and surrounding process/network telemetry.

### Evidence reconciliation note

The baseline test recorded 12 matches. The current manual review script identified 11 matching events because its matching logic included additional RunOnceEx patterns while the rule definition itself specifically matches `CurrentVersion\Run` and `CurrentVersion\RunOnce`.

The baseline result and rule semantics should be reconciled during the final Phase 5 retest before the final report is marked complete.

---

## Rule 08 — Scheduled Task Creation

**Rule:** `rules/scheduled_task_creation.yml`
**ATT&CK:** T1053.005 — Scheduled Task/Job: Scheduled Task
**Baseline matches:** 8

### Representative evidence reviewed

All eight baseline Event ID 4698/4702 events were inspected.

Observed task names and account contexts included:

- `\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask` — four Event ID 4702 events under `DC1$`.
- `\CYAlyNSS` — Event ID 4698 events associated with `Administrator`.
- `\LMST` — Event ID 4702 associated with `a-jbrown`.
- `\FullPowersTask` — Event ID 4698 associated with `LOCAL SERVICE`.

### False-positive consideration

Legitimate scheduled task creation or modification is common in Windows administration and system maintenance.

The `SvcRestartTask` events demonstrate that legitimate scheduled-task management can produce matching telemetry.

### Tuning decision

**RETAIN — No tuning applied.**

The available evidence does not justify a specific task-name or account exclusion. A scheduled-task detection should be investigated using task name, account context, task configuration, creation/modification telemetry, and surrounding activity.

The matches are detection evidence and should not automatically be classified as malicious.

---

## Updated Phase 5 Review Summary

| Rule | Baseline Matches | Representative Review | Tuning |
|---|---:|---:|---|
| Windows Command Shell Execution | 305 | 2 events | None |
| Process Injection | 104 | 10 events | None |
| Suspicious Web Protocol Activity | 43 | 10 events | None |
| BITS Ingress Tool Transfer | 16 | 10 events | None |
| LSASS Memory Access | 28 | 10 events | None |
| Windows PortProxy Registry Modification | 3 | 3 events | None |
| Registry Run Key Modification | 12 | Representative events | None |
| Scheduled Task Creation | 8 | 8 events | None |

---

## Rule 09 — Windows Service Creation

**Rule:** `rules/service_creation.yml`
**ATT&CK:** T1543.003 — Windows Service
**Baseline matches:** 4

### Representative evidence reviewed

All four baseline Windows Security Event ID 7045 events were inspected.

Observed services included:

- `spoolfool` with `cmd.exe` as the image path.
- `spoolsv` with `cmd.exe` as the image path.
- `remotesvc` with `calc.exe` as the image path.
- `WinPwnage` with `%COMSPEC% /c` and a named-pipe command.

All four events used `LocalSystem` as the service account.

### False-positive consideration

Legitimate software installation and system administration can create Windows services.

### Tuning decision

**RETAIN — No tuning applied.**

The available evidence did not establish a sufficiently specific benign pattern that would justify an exclusion.

Service creation should be investigated using the service name, image path, start type, account context, process relationships, and surrounding telemetry.

The presence of Event ID 7045 alone should not be treated as proof of malicious activity.

---

## Updated Phase 5 Review Summary

| Rule | Baseline Matches | Representative Review | Tuning |
|---|---:|---:|---|
| Windows Command Shell Execution | 305 | 2 events | None |
| Process Injection | 104 | 10 events | None |
| Suspicious Web Protocol Activity | 43 | 10 events | None |
| BITS Ingress Tool Transfer | 16 | 10 events | None |
| LSASS Memory Access | 28 | 10 events | None |
| Windows PortProxy Registry Modification | 3 | 3 events | None |
| Registry Run Key Modification | 12 | Representative events | None |
| Scheduled Task Creation | 8 | 8 events | None |
| Windows Service Creation | 4 | 4 events | None |

---

## Rule 10 — RDP Remote Connection

**Rule:** `rules/rdp_remote_service.yml`
**ATT&CK:** T1021.001 — Remote Services: Remote Desktop Protocol
**Baseline matches:** 11

### Representative evidence reviewed

Eleven Sysmon/Windows RDP-related Event ID 1149 matches were identified.

All baseline matches originated from:

`Command and Control/DE_RDP_Tunneling_TerminalServices-RemoteConnectionManagerOperational_1149.evtx`

The rule currently detects Event ID 1149 without additional field constraints.

### Telemetry limitation

The inspected Event ID 1149 records did not expose populated `User`, `Domain`, `Address`, `SessionID`, or named `<Data>` fields through the available EVTX XML representation.

Therefore, the available dataset does not provide sufficient contextual fields to establish a more specific benign or suspicious pattern for tuning.

### False-positive consideration

Legitimate remote administration can generate RDP authentication/connection telemetry.

### Tuning decision

**RETAIN — No tuning applied.**

No exclusion was introduced because the available telemetry does not provide enough contextual evidence to justify one.

The 11 matches should not automatically be classified as malicious. In a production environment, analysts should correlate RDP events with source address, account, authentication events, process activity, and other surrounding telemetry where available.

---

## Updated Phase 5 Review Summary

| Rule | Baseline Matches | Representative Review | Tuning |
|---|---:|---:|---|
| Windows Command Shell Execution | 305 | 2 events | None |
| Process Injection | 104 | 10 events | None |
| Suspicious Web Protocol Activity | 43 | 10 events | None |
| BITS Ingress Tool Transfer | 16 | 10 events | None |
| LSASS Memory Access | 28 | 10 events | None |
| Windows PortProxy Registry Modification | 3 | 3 events | None |
| Registry Run Key Modification | 12 | Representative events | None |
| Scheduled Task Creation | 8 | 8 events | None |
| Windows Service Creation | 4 | 4 events | None |
| RDP Remote Connection | 11 | 11 events identified; contextual fields unavailable | None |

---

## Rule 11 — SMB Admin Share Access

**Rule:** `rules/smb_admin_share.yml`
**ATT&CK:** T1021.002 — SMB/Windows Admin Shares
**Baseline matches:** 44

### Representative evidence reviewed

Ten representative Windows Security Event ID 5145 matches were inspected.

Observed telemetry included:

- `ShareName`: `\\*\IPC$`
- `RelativeTargetName`: `protected_storage`, `samr`, `lsarpc`, `winreg`, and `eventlog`
- Source IP addresses were populated.
- Subject usernames were populated.
- Access masks were populated.

Observed account contexts included `backdoor`, `Administrator`, `samir`, `user01`, and `admin01`.

### False-positive consideration

IPC$ access can be generated by normal Windows administrative and RPC activity.

Therefore, an Event ID 5145 match to IPC$ should not automatically be classified as malicious.

### Tuning decision

**RETAIN — No tuning applied.**

The reviewed telemetry contains useful contextual fields, but the available evidence does not justify universally excluding a particular account, source IP, or IPC$ target.

For investigation, analysts should correlate `IpAddress`, `SubjectUserName`, `RelativeTargetName`, `AccessMask`, authentication events, and surrounding lateral-movement telemetry.

---

## Updated Phase 5 Review Summary

| Rule | Baseline Matches | Representative Review | Tuning |
|---|---:|---:|---|
| Windows Command Shell Execution | 305 | 2 events | None |
| Process Injection | 104 | 10 events | None |
| Suspicious Web Protocol Activity | 43 | 10 events | None |
| BITS Ingress Tool Transfer | 16 | 10 events | None |
| LSASS Memory Access | 28 | 10 events | None |
| Windows PortProxy Registry Modification | 3 | 3 events | None |
| Registry Run Key Modification | 12 | Representative events | None |
| Scheduled Task Creation | 8 | 8 events | None |
| Windows Service Creation | 4 | 4 events | None |
| RDP Remote Connection | 11 | 11 events identified; contextual fields unavailable | None |
| SMB Admin Share Access | 44 | 10 events | None |

---

## Rule 12 — System Information Discovery

**Rule:** `rules/system_information_discovery.yml`
**ATT&CK:** T1082 — System Information Discovery
**Baseline matches:** 2

### Representative evidence reviewed

Both baseline Event ID 1 matches were inspected.

Observed activity included:

1. `HOSTNAME.EXE`
   - Parent process: `wsmprovhost.exe`
   - User: `insecurebank\Administrator`
   - Source: `Lateral Movement/LM_PowershellRemoting_sysmon_1_wsmprovhost.evtx`

2. `systeminfo.exe`
   - Command line: `systeminfo`
   - Parent process: `cmd.exe`
   - User: `IEWIN7\IEUser`
   - Source: `Lateral Movement/powercat_revShell_sysmon_1_3.evtx`

### False-positive consideration

System information commands such as `hostname.exe` and `systeminfo.exe` can be used by legitimate administrative inventory scripts and troubleshooting activity.

### Tuning decision

**RETAIN — No tuning applied.**

The two available matches did not establish a sufficiently specific benign pattern that would justify an exclusion.

Analysts should correlate the discovery command with the parent process, user context, session type, and surrounding activity.

---

## Updated Phase 5 Review Summary

| Rule | Baseline Matches | Representative Review | Tuning |
|---|---:|---:|---|
| Windows Command Shell Execution | 305 | 2 events | None |
| Process Injection | 104 | 10 events | None |
| Suspicious Web Protocol Activity | 43 | 10 events | None |
| BITS Ingress Tool Transfer | 16 | 10 events | None |
| LSASS Memory Access | 28 | 10 events | None |
| Windows PortProxy Registry Modification | 3 | 3 events | None |
| Registry Run Key Modification | 12 | Representative events | None |
| Scheduled Task Creation | 8 | 8 events | None |
| Windows Service Creation | 4 | 4 events | None |
| RDP Remote Connection | 11 | 11 events identified; contextual fields unavailable | None |
| SMB Admin Share Access | 44 | 10 events | None |
| System Information Discovery | 2 | 2 events | None |

### Rule 13 — Windows Account Discovery (`account_discovery.yml`)

- **Technique:** T1087 — Account Discovery
- **Baseline matches:** 22
- **Representative events reviewed:** 10
- **Observed behavior:** `whoami.exe` executed with `/user`, `/groups`, and `/all`, launched by PowerShell and `cmd.exe`.
- **False-positive considerations:** Legitimate administrative account discovery and system inventory scripts.
- **Decision:** RETAIN
- **Tuning:** None applied.
- **Reason:** The dataset contains both administrative-style and attack-scenario context. No safe exclusion was justified from the available evidence.

| Rule | Baseline Matches | Review | Tuning |
|---|---:|---|---|
| Windows Account Discovery | 22 | 10 representative events | None |

### Rule 14 — BITS Ingress Tool Transfer (`bits_ingress_tool_transfer.yml`)

- **Technique:** T1105 — Ingress Tool Transfer
- **Baseline matches:** 16
- **Representative events reviewed:** 10
- **Observed behavior:** `bitsadmin.exe` activity including `/transfer`, `/create`, `/addfile`, `/setnotifycmdline`, and `/complete`. Several events involved remote HTTPS resources and PowerShell-to-cmd-to-BITS execution chains.
- **Dataset context:** Reviewed matches are present in Atomic Red Team testing telemetry.
- **False-positive considerations:** Legitimate software deployment and administrative BITS transfers.
- **Decision:** RETAIN
- **Tuning:** None applied.
- **Reason:** The observed activity demonstrates the detection logic correctly identifies BITS-based transfer behavior, but the available evidence does not justify a safe exclusion.

| Rule | Baseline Matches | Review | Tuning |
|---|---:|---|---|
| BITS Ingress Tool Transfer | 16 | 10 representative events | None |

### Rule 15 — Suspicious Web Protocol Activity (`web_protocol_activity.yml`)

- **Technique:** T1071.001 — Web Protocols
- **Baseline matches:** 43
- **Representative events reviewed:** 10
- **Observed behavior:** Process execution containing HTTP/HTTPS URLs, including BITS transfers, `cscript.exe` script URLs, `msxsl.exe` remote resources, WMIC format URLs, and `regsvr32.exe` remote script references.
- **Dataset context:** Several reviewed events originate from Atomic Red Team testing telemetry.
- **False-positive considerations:** Legitimate administrative scripts and software updates may contain HTTP/HTTPS URLs.
- **Decision:** RETAIN
- **Tuning:** None applied.
- **Reason:** URL presence alone does not establish malicious activity, and the reviewed evidence does not justify a safe exclusion or narrower condition.

| Rule | Baseline Matches | Review | Tuning |
|---|---:|---|---|
| Suspicious Web Protocol Activity | 43 | 10 representative events | None |

### Rule 16 — File Deletion Activity (`file_deletion.yml`)

- **Technique:** T1070.004 — File and Directory Discovery?
- **Baseline matches:** 3
- **Representative events reviewed:** 3
- **Observed behavior:** Sysmon Event ID 23 recorded deletion of temporary files including `consent.exe.dat` and `[1]consent.exe`.
- **False-positive considerations:** Normal temporary-file cleanup may generate file deletion events.
- **Decision:** RETAIN
- **Tuning:** None applied.
- **Reason:** The reviewed events occur in temporary-file paths, demonstrating that legitimate cleanup can match the rule. However, the available evidence does not justify excluding temporary directories because such an exclusion could hide relevant deletion activity.

| Rule | Baseline Matches | Review | Tuning |
|---|---:|---|---|
| File Deletion Activity | 3 | 3 events | None |
