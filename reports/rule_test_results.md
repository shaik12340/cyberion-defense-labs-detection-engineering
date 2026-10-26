# Cyberion Defense Labs
# Sigma Rule Testing Results

Rules were tested against the locally analyzed EVTX-ATTACK-SAMPLES telemetry.

- Total events loaded: 37364
- Detection rules tested: 16

| Rule | ATT&CK Tag | Matches | Status | Evidence |
|---|---|---:|---|---|
| `account_discovery.yml` | attack.discovery, attack.t1087 | 22 | PASS | data/raw/EVTX-ATTACK-SAMPLES/AutomatedTestingTools/PanacheSysmon_vs_AtomicRedTeam01.evtx \| EventID=1 |
| `bits_ingress_tool_transfer.yml` | attack.command_and_control, attack.t1105 | 16 | PASS | data/raw/EVTX-ATTACK-SAMPLES/AutomatedTestingTools/panache_sysmon_vs_EDRTestingScript.evtx \| EventID=1 |
| `file_deletion.yml` | attack.defense_evasion, attack.t1070.004 | 3 | PASS | data/raw/EVTX-ATTACK-SAMPLES/Privilege Escalation/Sysmon_UACME_64.evtx \| EventID=23 |
| `lsass_memory_access.yml` | attack.credential_access, attack.t1003.001 | 28 | PASS | data/raw/EVTX-ATTACK-SAMPLES/AutomatedTestingTools/PanacheSysmon_vs_AtomicRedTeam01.evtx \| EventID=10 |
| `modify_registry_portproxy.yml` | attack.defense_evasion, attack.t1112 | 3 | PASS | data/raw/EVTX-ATTACK-SAMPLES/AutomatedTestingTools/panache_sysmon_vs_EDRTestingScript.evtx \| EventID=13 |
| `proc_cmd_shell.yml` | attack.execution, attack.t1059.003 | 305 | PASS | data/raw/EVTX-ATTACK-SAMPLES/UACME_59_Sysmon.evtx \| EventID=1 |
| `proc_powershell_obfuscated.yml` | attack.execution, attack.t1059.001 | 3 | PASS | data/raw/EVTX-ATTACK-SAMPLES/Credential Access/discovery_sysmon_1_iis_pwd_and_config_discovery_appcmd.evtx \| EventID=1 |
| `process_injection.yml` | attack.defense_evasion, attack.t1055 | 104 | PASS | data/raw/EVTX-ATTACK-SAMPLES/AutomatedTestingTools/Malware/sideloading_uacbypass_rundll32_injection_c2.evtx \| EventID=8 |
| `rdp_remote_service.yml` | attack.lateral_movement, attack.t1021.001 | 11 | PASS | data/raw/EVTX-ATTACK-SAMPLES/Command and Control/DE_RDP_Tunneling_TerminalServices-RemoteConnectionManagerOperational_1149.evtx \| EventID=1149 |
| `registry_run_keys.yml` | attack.persistence, attack.t1547.001 | 12 | PASS | data/raw/EVTX-ATTACK-SAMPLES/AutomatedTestingTools/PanacheSysmon_vs_AtomicRedTeam01.evtx \| EventID=13 |
| `scheduled_task_creation.yml` | attack.persistence, attack.t1053.005 | 8 | PASS | data/raw/EVTX-ATTACK-SAMPLES/Credential Access/ACL_ForcePwd_SPNAdd_User_Computer_Accounts.evtx \| EventID=4702 |
| `service_creation.yml` | attack.persistence, attack.t1543.003 | 4 | PASS | data/raw/EVTX-ATTACK-SAMPLES/Privilege Escalation/System_7045_namedpipe_privesc.evtx \| EventID=7045 |
| `smb_admin_share.yml` | attack.lateral_movement, attack.t1021.002 | 44 | PASS | data/raw/EVTX-ATTACK-SAMPLES/Defense Evasion/DE_suspicious_remote_eventlog_svc_access_5145.evtx \| EventID=5145 |
| `system_information_discovery.yml` | attack.discovery, attack.t1082 | 2 | PASS | data/raw/EVTX-ATTACK-SAMPLES/Lateral Movement/powercat_revShell_sysmon_1_3.evtx \| EventID=1 |
| `valid_accounts_admin_logon.yml` | attack.defense_evasion, attack.persistence, attack.t1078 | 14 | PASS | data/raw/EVTX-ATTACK-SAMPLES/Defense Evasion/DE_suspicious_remote_eventlog_svc_access_5145.evtx \| EventID=4624 |
| `web_protocol_activity.yml` | attack.command_and_control, attack.t1071.001 | 43 | PASS | data/raw/EVTX-ATTACK-SAMPLES/AutomatedTestingTools/panache_sysmon_vs_EDRTestingScript.evtx \| EventID=1 |

## Summary

- Rules with matching telemetry: **16**
- Rules without matching telemetry: **0**
- Total rules tested: **16**
