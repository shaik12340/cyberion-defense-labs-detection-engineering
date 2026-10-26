# Cyberion Defense Labs
# Detection Engineering & Threat Hunting
## Data Dictionary

## 1. Dataset Overview

The EVTX-ATTACK-SAMPLES dataset was analyzed locally using Python and
python-evtx.

- EVTX files analyzed: 278
- Events analyzed: 37,364
- Parsing errors: 0

The data contains multiple Windows telemetry sources. The primary
sources selected for detection engineering are:

1. Microsoft-Windows-Sysmon
2. Microsoft-Windows-Security-Auditing
3. Microsoft-Windows-PowerShell

Additional useful sources include BITS Client, RDP, WinRM,
Windows Defender and Service Control Manager.

---

# 2. Common System Fields

The following System-level fields were observed across multiple
providers:

| Field | Description |
|---|---|
| System.Provider | Event provider name |
| System.EventID | Windows event identifier |
| System.Channel | Windows event channel |
| System.Computer | Computer associated with the event |
| System.TimeCreated | Event creation timestamp |
| System.EventRecordID | Event record identifier |
| System.Level | Event severity/level |
| System.Task | Event task |
| System.Opcode | Event opcode |
| System.Keywords | Event keywords |
| System.Correlation | Correlation information when present |
| System.Execution | Execution metadata when present |
| System.Security | Security metadata when present |
| System.Version | Event version when present |

---

# 3. Microsoft-Windows-Sysmon

Sysmon provides detailed endpoint telemetry useful for process,
network, file, registry and process-access detections.

## Important observed fields

| Field | Detection Use |
|---|---|
| EventData.RuleName | Sysmon detection/configuration rule |
| EventData.UtcTime | Event timestamp |
| EventData.Image | Process executable path |
| EventData.CommandLine | Process command line |
| EventData.ParentImage | Parent process |
| EventData.ParentCommandLine | Parent process command line |
| EventData.ParentProcessId | Parent process ID |
| EventData.ProcessId | Process ID |
| EventData.ProcessGuid | Unique process identifier |
| EventData.User | User associated with process |
| EventData.IntegrityLevel | Process integrity level |
| EventData.CurrentDirectory | Process working directory |
| EventData.Hashes | File/process hashes |
| EventData.Company | File company metadata |
| EventData.Description | File description |
| EventData.Product | Product metadata |
| EventData.OriginalFileName | Original executable name |
| EventData.ParentUser | Parent process user |
| EventData.DestinationIp | Network destination IP |
| EventData.DestinationHostname | Network destination hostname |
| EventData.DestinationPort | Network destination port |
| EventData.SourceIp | Network source IP |
| EventData.SourcePort | Network source port |
| EventData.Protocol | Network protocol |
| EventData.TargetFilename | Target file for file operations |
| EventData.TargetObject | Registry/object target |
| EventData.TargetImage | Target process image |
| EventData.GrantedAccess | Process access rights |
| EventData.SourceImage | Source process image |
| EventData.QueryName | DNS query name |
| EventData.QueryResults | DNS query results |
| EventData.ImageLoaded | Loaded image/DLL |
| EventData.Signature | File signature information |
| EventData.Signed | Signature status |
| EventData.SignatureStatus | Signature verification status |

## Detection relevance

Sysmon fields can support detections for:

- Suspicious process execution
- Command-line abuse
- LOLBin activity
- Network connections
- File creation
- Registry modification
- Process injection
- Credential access
- Suspicious parent-child process relationships
- DNS activity

---

# 4. Microsoft-Windows-Security-Auditing

Windows Security Auditing provides authentication, account,
process, service, object-access and policy-related telemetry.

## Important observed fields

| Field | Detection Use |
|---|---|
| EventData.SubjectUserName | Account performing an action |
| EventData.SubjectDomainName | Domain of the initiating account |
| EventData.SubjectUserSid | SID of initiating account |
| EventData.TargetUserName | Target account |
| EventData.TargetDomainName | Target account domain |
| EventData.TargetUserSid | Target account SID |
| EventData.LogonType | Type of logon |
| EventData.IpAddress | Source IP for authentication events |
| EventData.IpPort | Source port |
| EventData.WorkstationName | Source workstation |
| EventData.Workstation | Workstation information |
| EventData.AuthenticationPackageName | Authentication mechanism |
| EventData.LogonProcessName | Logon process |
| EventData.LogonId | Logon identifier |
| EventData.TargetLogonId | Target logon identifier |
| EventData.ProcessName | Process involved in event |
| EventData.ProcessID | Process ID |
| EventData.NewProcessId | New process identifier |
| EventData.NewProcessName | New process name |
| EventData.ParentProcessName | Parent process |
| EventData.CommandLine | Process command line |
| EventData.ServiceName | Service name |
| EventData.Service | Service information |
| EventData.ObjectName | Accessed object |
| EventData.ObjectType | Object type |
| EventData.AccessMask | Requested access |
| EventData.AccessList | Access requested |
| EventData.SourceAddress | Source network address |
| EventData.SourcePort | Source network port |
| EventData.DestAddress | Destination address |
| EventData.DestPort | Destination port |
| EventData.Status | Event status |
| EventData.SubStatus | Detailed status |
| EventData.TaskName | Scheduled task name |
| EventData.TaskContent | Scheduled task configuration |
| EventData.ScriptPath | Script path |
| EventData.ServiceName | Service involved |
| EventData.UserAccountControl | Account-control information |
| EventData.PrivilegeList | Privileges involved |

## Detection relevance

Security Auditing fields can support detections for:

- Account compromise
- Successful and failed authentication
- Brute-force activity
- Privilege escalation
- Process creation
- Scheduled task creation
- Service creation
- Account creation
- Remote authentication
- Object access
- Security policy modification

---

# 5. Microsoft-Windows-PowerShell

PowerShell telemetry was observed with fields that provide
visibility into PowerShell script execution.

## Important observed fields

| Field | Detection Use |
|---|---|
| EventData.ScriptBlockText | PowerShell script content |
| EventData.ScriptBlockId | Script block identifier |
| EventData.Path | PowerShell-related path |
| EventData.MessageNumber | Message sequence number |
| EventData.MessageTotal | Total messages |
| EventData.param1 | Provider-specific parameter |
| EventData.param2 | Provider-specific parameter |

## Detection relevance

PowerShell telemetry can support detections for:

- Suspicious PowerShell execution
- Encoded commands
- Download activity
- Script execution
- Command and control behavior
- Defense evasion
- PowerShell-based payload execution

---

# 6. Microsoft-Windows-Bits-Client

BITS telemetry was also observed in the dataset.

Important observed fields include:

- EventData.jobId
- EventData.jobName
- EventData.jobOwner
- EventData.url
- EventData.processPath
- EventData.processId
- EventData.bytesTotal
- EventData.bytesTransferred
- EventData.fileCount
- EventData.fileLength
- EventData.transferId
- EventData.peer
- EventData.proxy
- EventData.User

These fields may support investigation of suspicious file transfers
and BITS-based activity.

---

# 7. Remote Desktop Services

RDP telemetry was observed through:

`Microsoft-Windows-RemoteDesktopServices-RdpCoreTS`

Important fields include:

- EventData.ClientIP
- EventData.ServerName
- EventData.Port
- EventData.SessionID
- EventData.ConnectionName
- EventData.TransportProtocolName
- EventData.TransportType
- EventData.StateTransition
- EventData.PreviousState
- EventData.NewState
- EventData.NewStateName
- EventData.ReasonCode
- EventData.ReasonString

These fields can support investigation of remote-access activity.

---

# 8. Windows Defender

Windows Defender telemetry was also present.

Important observed fields include:

- EventData.ThreatName
- EventData.ThreatID
- EventData.DetectionID
- EventData.DetectionTime
- EventData.DetectionUser
- EventData.Path
- EventData.ProcessName
- EventData.SeverityName
- EventData.CategoryName
- EventData.ActionName
- EventData.StatusDescription
- EventData.ProductName
- EventData.SignatureVersion

These fields can support corroboration of malware detections and
incident investigations.

---

# 9. Service Control Manager

Service Control Manager telemetry contains:

- EventData.ServiceName
- EventData.ImagePath
- EventData.ServiceType
- EventData.StartType
- EventData.AccountName

These fields may support detections involving suspicious service
creation or modification.

---

# 10. Data Quality Notes

The inventory was generated from the actual EVTX XML structures in
the dataset.

Fields are therefore documented only where they were observed.

Some events contain provider-specific fields and not every field is
present in every event from the same provider.

The dataset also contains events where the Channel value is empty.
This should be preserved as an observed dataset characteristic rather
than replaced with an assumed value.

---

# 11. Detection Engineering Priority

For the initial Sigma development phase, priority will be given to:

1. Sysmon process telemetry
2. Windows Security authentication telemetry
3. PowerShell telemetry
4. Sysmon network telemetry
5. Security Auditing process/service/account telemetry
6. BITS and RDP telemetry for supporting detections and hunts

These sources provide the primary fields required for the planned
ATT&CK mapping, Sigma rules, threat hunts and incident investigations.
