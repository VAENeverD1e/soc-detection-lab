# SOC Detection Lab

A hands-on Security Operations Centre (SOC) detection lab containing SIEM detection rules,
threat-hunting queries, and documented attack scenarios mapped to the MITRE ATT&CK framework.

## Repository Structure

```
soc-detection-lab
├── README.md                          ← this file
├── architecture.png                   ← lab architecture diagram
├── detection-scenarios
│   ├── scenario1-powershell.md        ← suspicious PowerShell execution
│   ├── scenario2-bruteforce.md        ← brute-force / password-spray attack
│   └── scenario3-persistence.md      ← persistence mechanism established
├── queries
│   ├── powershell-rule.txt            ← KQL rule for PowerShell detection
│   └── login-detection-rule.txt      ← KQL rule for brute-force detection
└── screenshots                        ← evidence screenshots from SIEM / alerts
```
## Lab Objective
Simulate adversary techniques using Atomic Red Team and detect them using ELK SIEM with custom detection rules mapped to MITRE ATT&CK.

## Architecture
Host machine
ELK server (dual-interface)
FLARE VM attacker simulator
Isolated VMnet1 detection subnet

## Detection Scenarios

| MITRE ID | Technique Name | Reference | Environment | Event IDs | Rule Status | Validation |
| :--- | :--- | :---: | :--- | :--- | :--- | :--- |
| T1059.001 | PowerShell fileless | #10 | Offline | ID 1, ID 13 | ✅ Rule written | ✅ Detected |
| T1003.001 | LSASS dump (LOLBin) | #1 | Offline | ID 10 | ✅ Rule written | ✅ Detected |
| T1547.001 | Registry Run key | #1 | Offline | ID 13 | ✅ Rule written | ✅ Detected |
| T1053.005 | Scheduled task startup | #1 | Offline | ID 1 + Event 4698 | ✅ Rule written | ✅ Detected |

## Queries

Detection rules are written in **KQL (Kibana Query Language)** and target **Elastic Security / ELK SIEM**.

| Query file | Purpose |
|---|---|
| [powershell-rule.txt](queries/powershell-rule.txt) | Detect suspicious PowerShell activity |
| [login-detection-rule.txt](queries/login-detection-rule.txt) | Detect brute-force / password-spray |

## Getting Started

1. Clone or fork this repository.
2. Import the KQL queries from the `queries/` folder into your Microsoft Sentinel workspace.
3. Review each detection scenario in `detection-scenarios/` to understand the attack context
   and recommended response steps.
4. Add screenshots of triggered alerts to the `screenshots/` folder for documentation.
