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

## Detection Scenarios

| Scenario | Technique | MITRE ID |
|---|---|---|
| [PowerShell Execution](detection-scenarios/scenario1-powershell.md) | Command & Scripting Interpreter | T1059.001 |
| [Brute-Force Login](detection-scenarios/scenario2-bruteforce.md) | Brute Force | T1110 |
| [Persistence](detection-scenarios/scenario3-persistence.md) | Boot/Logon Autostart Execution | T1547 |

## Queries

Detection rules are written in **KQL (Kusto Query Language)** and target **Microsoft Sentinel**.

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
