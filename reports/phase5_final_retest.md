# Phase 5 — Final Rule Retest

## Test Scope

- Dataset: `EVTX-ATTACK-SAMPLES`
- EVTX files scanned: 278
- Events scanned: 37364
- Primary Sigma rules tested: 16
- Files with parser errors: 0

## Final Retest Results

| Rule | Matches | Evidence |
|---|---:|---|
| Windows Account Discovery | 22 | 1 — `AutomatedTestingTools/PanacheSysmon_vs_AtomicRedTeam01.evtx` |
| BITS Ingress Tool Transfer | 16 | 1 — `AutomatedTestingTools/PanacheSysmon_vs_AtomicRedTeam01.evtx` |
| File Deletion Activity | 3 | 23 — `Privilege Escalation/Sysmon_UACME_64.evtx` |
| LSASS Memory Access | 28 | 10 — `AutomatedTestingTools/PanacheSysmon_vs_AtomicRedTeam01.evtx` |
| Windows PortProxy Registry Modification | 3 | 13 — `AutomatedTestingTools/panache_sysmon_vs_EDRTestingScript.evtx` |
| Windows Command Shell Execution | 305 | 1 — `AutomatedTestingTools/Malware/DE_timestomp_and_dll_sideloading_and_RunPersist.evtx` |
| Suspicious PowerShell Obfuscation | 3 | 1 — `Credential Access/discovery_sysmon_1_iis_pwd_and_config_discovery_appcmd.evtx` |
| Process Injection | 104 | 8 — `AutomatedTestingTools/Malware/sideloading_uacbypass_rundll32_injection_c2.evtx` |
| RDP Remote Connection | 11 | 1149 — `Command and Control/DE_RDP_Tunneling_TerminalServices-RemoteConnectionManagerOperational_1149.evtx` |
| Registry Run Key Modification | 12 | 13 — `AutomatedTestingTools/Malware/DE_timestomp_and_dll_sideloading_and_RunPersist.evtx` |
| Scheduled Task Creation | 8 | 4702 — `Credential Access/ACL_ForcePwd_SPNAdd_User_Computer_Accounts.evtx` |
| Windows Service Creation | 4 | 7045 — `Lateral Movement/LM_Remote_Service02_7045.evtx` |
| SMB Admin Share Access | 44 | 5145 — `Credential Access/CA_protectedstorage_5145_rpc_masterkey.evtx` |
| System Information Discovery | 2 | 1 — `Lateral Movement/LM_PowershellRemoting_sysmon_1_wsmprovhost.evtx` |
| Valid Account Administrative Logon | 14 | 4624 — `Credential Access/remote_pwd_reset_rpc_mimikatz_postzerologon_target_DC.evtx` |
| Suspicious Web Protocol Activity | 43 | 1 — `AutomatedTestingTools/PanacheSysmon_vs_AtomicRedTeam01.evtx` |

## Summary

- Rules producing matches: **16/16**
- Rules without matches: **0**
- EVTX parser errors: **0**

## Interpretation

The final retest uses the EVTX EventID field explicitly and re-evaluates the primary Sigma selection logic against the same telemetry dataset used for baseline testing.