# Scenario 3 – Persistence Mechanism Established

## Description
Detects common persistence techniques used by adversaries to maintain access to a
compromised system across reboots or credential changes.

## Attack Technique
- **MITRE ATT&CK**: T1547 – Boot or Logon Autostart Execution
- **MITRE ATT&CK**: T1053 – Scheduled Task/Job
- **MITRE ATT&CK**: T1543 – Create or Modify System Process

## Indicators of Compromise
- New registry Run/RunOnce key added (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`)
- New scheduled task created by a non-administrative or unexpected user
- New or modified service pointing to an unsigned or suspicious binary
- Startup folder modification

## Detection Rule
No dedicated query file – combine PowerShell and login rules for correlated hunting.

## Response Steps
1. Identify the persistence artifact (registry key, scheduled task, service, startup item).
2. Remove the artifact and any associated malicious binaries.
3. Review the timeline to determine initial access vector.
4. Scan the environment for similar artifacts on other endpoints.
5. Perform a full credential rotation if domain-level persistence is suspected.

## References
- https://attack.mitre.org/techniques/T1547/
- https://attack.mitre.org/techniques/T1053/
- https://attack.mitre.org/techniques/T1543/
