# Phase 5 — Rule Testing Baseline

## Dataset

- Dataset: EVTX-ATTACK-SAMPLES
- EVTX files: 278
- Parser: python-evtx
- Purpose: Pre-tuning detection baseline

## Primary Detection Results

| Rule | ATT&CK | Severity | Matches | Evidence Files | Sample Event | Evidence |
|---|---|---|---:|---:|---:|---|
| account_discovery.yml | t1087 | low | 22 | 20 | 1 | `AutomatedTestingTools/PanacheSysmon_vs_AtomicRedTeam01.evtx` |
| bits_ingress_tool_transfer.yml | t1105 | medium | 16 | 2 | 1 | `AutomatedTestingTools/PanacheSysmon_vs_AtomicRedTeam01.evtx` |
| file_deletion.yml | t1070.004 | medium | 3 | 1 | 23 | `Privilege Escalation/Sysmon_UACME_64.evtx` |
| lsass_memory_access.yml | t1003.001 | high | 28 | 14 | 10 | `AutomatedTestingTools/PanacheSysmon_vs_AtomicRedTeam01.evtx` |
| modify_registry_portproxy.yml | t1112 | high | 3 | 2 | 13 | `AutomatedTestingTools/panache_sysmon_vs_EDRTestingScript.evtx` |
| proc_cmd_shell.yml | t1059.003 | low | 305 | 77 | 1 | `AutomatedTestingTools/Malware/DE_timestomp_and_dll_sideloading_and_RunPersist.evtx` |
| proc_powershell_obfuscated.yml | t1059.001 | high | 3 | 2 | 1 | `Credential Access/discovery_sysmon_1_iis_pwd_and_config_discovery_appcmd.evtx` |
| process_injection.yml | t1055 | high | 104 | 10 | 8 | `AutomatedTestingTools/Malware/sideloading_uacbypass_rundll32_injection_c2.evtx` |
| rdp_remote_service.yml | t1021.001 | medium | 11 | 1 | 1149 | `Command and Control/DE_RDP_Tunneling_TerminalServices-RemoteConnectionManagerOperational_1149.evtx` |
| registry_run_keys.yml | t1547.001 | high | 12 | 6 | 13 | `AutomatedTestingTools/Malware/DE_timestomp_and_dll_sideloading_and_RunPersist.evtx` |
| scheduled_task_creation.yml | t1053.005 | medium | 8 | 5 | 4702 | `Credential Access/ACL_ForcePwd_SPNAdd_User_Computer_Accounts.evtx` |
| service_creation.yml | t1543.003 | high | 4 | 2 | 7045 | `Lateral Movement/LM_Remote_Service02_7045.evtx` |
| smb_admin_share.yml | t1021.002 | medium | 44 | 14 | 5145 | `Credential Access/CA_protectedstorage_5145_rpc_masterkey.evtx` |
| system_information_discovery.yml | t1082 | low | 2 | 2 | 1 | `Lateral Movement/LM_PowershellRemoting_sysmon_1_wsmprovhost.evtx` |
| valid_accounts_admin_logon.yml | t1078 | medium | 14 | 6 | 4624 | `Credential Access/remote_pwd_reset_rpc_mimikatz_postzerologon_target_DC.evtx` |
| web_protocol_activity.yml | t1071.001 | low | 43 | 10 | 1 | `AutomatedTestingTools/PanacheSysmon_vs_AtomicRedTeam01.evtx` |

## Baseline Interpretation

This baseline records detection matches against the EVTX-ATTACK-SAMPLES dataset before the Phase 5 false-positive review and tuning process. A match confirms that the rule condition was observed in the selected telemetry; it does not independently establish malicious intent.
