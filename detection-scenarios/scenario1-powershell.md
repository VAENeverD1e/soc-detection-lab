# Scenario 1 – Suspicious PowerShell Execution

## Description
Detects potentially malicious PowerShell activity commonly used by threat actors for
reconnaissance, lateral movement, or payload delivery.

## Attack Technique
- **MITRE ATT&CK**: T1059.001 – Command and Scripting Interpreter: PowerShell

## Indicators of Compromise
- PowerShell launched with `-EncodedCommand` or `-enc` flags
- PowerShell downloading content from the internet (`Invoke-WebRequest`, `Net.WebClient`)
- PowerShell bypassing execution policy (`-ExecutionPolicy Bypass`)
- PowerShell running from an unusual parent process (e.g. `winword.exe`, `excel.exe`)

## Detection Rule
See `../queries/powershell-rule.txt` for the corresponding SIEM query.

## Response Steps
1. Isolate the affected endpoint immediately.
2. Review process tree and parent process for context.
3. Check network connections made by the PowerShell process.
4. Collect and analyse the decoded command string.
5. Escalate to Tier 2 if encoded commands or external downloads are confirmed.

## References
- https://attack.mitre.org/techniques/T1059/001/
