# SOC Detection Lab: Endpoint & Network Threat Investigation

![Elastic Stack](https://img.shields.io/badge/Elastic-SIEM-005571?style=for-the-badge&logo=elasticsearch)
![Python](https://img.shields.io/badge/Python-SOAR-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Suricata](https://img.shields.io/badge/Suricata-IDS-EE0000?style=for-the-badge)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT&CK-FF6600?style=for-the-badge)

A hands-on Security Operations Center (SOC) detection laboratory designed to simulate advanced adversary techniques, engineer custom detection rules, and automate incident alerting.

This project demonstrates an end-to-end Blue Team workflow: executing attacks, analyzing telemetry across both the endpoint and network layers, writing custom SIEM rules, building SOAR capabilities, and conducting proactive threat hunts against historical log data.

## 🎯 Project Objective

To build technical competency in **defense-in-depth** threat detection by simulating adversary behaviors using **Atomic Red Team** and engineering behavioral detection rules using **Elastic SIEM (ELK)** and **KQL**. The project focuses on detecting techniques that evade traditional file-based antivirus (LOLBin abuse, fileless execution), capturing network reconnaissance via intrusion detection systems, and proactively hunting for adversary behavior that no existing rule was written to catch.

### Key Skills Demonstrated

* **Detection Engineering:** Creating robust, behavioral-based KQL detection rules mapping to the MITRE ATT&CK framework.
* **Endpoint Log Analysis:** Deep analysis of **Sysmon** (Event IDs 1, 10, 13) and native Windows Security Events to trace attack execution.
* **Network Security Monitoring (NSM):** Utilizing **Suricata IDS** to capture malicious wire-level behavior and map Emerging Threats (ET) signatures.
* **Threat Hunting:** Conducting proactive, hypothesis-driven investigations across historical endpoint and network log data to uncover coverage gaps and validate existing rule efficacy.
* **Threat Simulation:** Utilizing Atomic Red Team and FLARE-VM to safely simulate targeted attacks.
* **Security Automation (SOAR):** Developing a custom Python application to interact with the Elastic API and automate alert triage via Discord webhooks.

---

## 🏗️ Lab Architecture

The environment consists of an isolated detection subnet (VMnet1) designed to safely detonate payloads and capture telemetry across multiple layers:

* **Attacker Simulator:** FLARE-VM (Windows 10) configured with Atomic Red Team and Nmap.
* **Endpoint Telemetry:** Sysmon and Elastic Agent deployed directly on the target host.
* **Network Telemetry:** Suricata IDS monitoring the isolated subnet for malicious traffic patterns.
* **SIEM:** ELK Server (dual-interface) ingesting and indexing both endpoint and network logs.
* **Automation Host:** Runs a custom Python webhook script to parse and forward Kibana alerts.

*(View the complete [Architecture Diagram](./architecture.png))*

---

## 🔍 Threat Detection Scenarios

I engineered detections for seven distinct MITRE ATT&CK techniques, focusing on high-fidelity, low-false-positive behavioral alerts. Detailed documentation, execution proofs, and KQL rule code are in the `detection-scenarios/` directory.

| MITRE ID | Adversary Technique | Primary Telemetry | Severity | Custom Rule Status | Scenario Details |
| :--- | :--- | :--- | :---: | :---: | :--- |
| **T1059.001** | PowerShell Fileless Execution | Sysmon ID 1, 13 | High | ✅ Engineered | [View Scenario](./detection-scenarios/scenario1-T1059.001-powershell/README.md) |
| **T1003.001** | LSASS Dump via `comsvcs.dll` (LOLBin) | Sysmon ID 10 | High | ✅ Engineered | [View Scenario](./detection-scenarios/scenario2-T1003.001-lsass/README.md) |
| **T1547.001** | Registry Run Key Persistence | Sysmon ID 13 | Medium | ✅ Engineered | [View Scenario](./detection-scenarios/scenario3-T1547.001-persistence/README.md) |
| **T1053.005** | Scheduled Task Persistence | Sysmon ID 1, Win 4698 | High | ✅ Engineered | [View Scenario](./detection-scenarios/scenario4-T1053.005-scheduled-task/README.md) |
| **T1055.001** | DLL Injection via `mavinject.exe` | Sysmon ID 1 | High | ✅ Engineered | [View Scenario](./detection-scenarios/scenario5-T1055.001-dll-injection/README.md) |
| **T1046** | Network Service Discovery | Sysmon ID 1, Suricata IDS | Medium | ✅ Engineered | [View Scenario](./detection-scenarios/scenario6-T1046-network-scan/README.md) |
| **T1071.001** | C2 Beaconing via Malicious HTTP User Agents | Sysmon ID 3, Suricata IDS | High | ✅ Engineered | [View Scenario](./detection-scenarios/scenario7-T1071.001-c2-beacon/README.md) |

---

## 🔎 Threat Hunting

Beyond reactive alerting, this lab includes a proactive threat hunting component — hypothesis-driven investigations into historical log data searching for adversary behavior that no existing rule was written to catch.

### What makes this different from detection rules

Most SOC detection is reactive: a rule fires, an alert appears, an analyst investigates. Threat hunting is the opposite — a human analyst forms a hypothesis, then manually searches raw logs looking for evidence, with no alert guiding the investigation. When a hunt finds something a rule missed, a new rule gets written. This is the detection engineering feedback loop.

### Hunts conducted

| # | Hunt | Hypothesis | Finding | Rule Impact |
| :--- | :--- | :--- | :--- | :--- |
| **H1** | [LOLBin Abuse](./threat-hunting/hunt1-lolbin-abuse.md) | Attacker used trusted Windows binaries (LOLBins) to execute malicious actions and evade signature-based detection | **Confirmed** — `rundll32.exe`+`comsvcs.dll` (T1003.001) and `mavinject.exe` (T1055.001) found in historical data | No new rule needed — existing rules already covered both findings |
| **H2** | [LSASS Reconnaissance](./threat-hunting/hunt2-lsass-recon.md) | LSASS was accessed with masks or source processes not covered by the existing T1003.001 rule | **Gap identified** — `svchost.exe`+`0x1410` was generating false positives not excluded by the original rule | T1003.001 rule updated with `svchost+0x1410` and 'wmiprvse.exe ' conditional exclusion |
| **H3** | [Persistence Audit](./threat-hunting/hunt3-persistence-audit.md) | Persistence artifacts (Run keys, scheduled tasks) may still be present in the environment post-cleanup | Clean — full creation-to-deletion lifecycle captured in SIEM; remediation confirmed via VMware snapshot ("Everything_Installed") | No new rule needed — existing rules and telemetry cover both techniques |
| **H4** | [C2 Beaconing](./threat-hunting/hunt4-c2-beaconing.md) | A host may be beaconing to a C2 server via HTTP traffic with anomalous user agents or connection patterns | **Confirmed** — anomalous HTTP user agents and PowerShell-initiated outbound connections to 192.168.75.11:8080 identified; burst communication pattern consistent with simulated C2 activity (T1071.001) | Detection gap identified and resolved — added Sysmon-based rule (`T1071.001-suspicious-script-egress`) to complement existing Suricata detection |

### Hunting methodology

Every hunt follows a five-step loop:

```
1. HYPOTHESISE  →  form a specific, falsifiable hypothesis
2. HUNT         →  write KQL queries in Kibana Discover to search for evidence
3. ANALYSE      →  classify each finding: malicious / benign / absent
4. DOCUMENT     →  write a structured hunt report covering all queries and findings
5. HARDEN       →  if a gap was found, write or update a detection rule
```

> **Key principle:** A hunt query that returns zero results is not a failure — it is a documented conclusion. Logging that you searched and found nothing is the difference between "we don't know" and "we checked and it's clean."

Full methodology documentation: [Threat Hunting README](./threat-hunting/README.md)

---

## 🤖 SOAR: Custom ELK to Discord Alerter

To simulate a modern SOC workflow, I developed a lightweight SOAR (Security Orchestration, Automation, and Response) utility.

Written in Python, `elk_discord_alerter.py` continuously polls the Elastic Security API for new High/Critical alerts. It parses the complex JSON alert payload (extracting hostnames, rule names, and MITRE technique IDs) and pushes formatted incident notifications to a Discord channel via webhooks.

* **Documentation:** [SOAR Implementation Guide](./soar/README.md)
* **Code:** [`elk_discord_alerter.py`](./soar/elk_discord_alerter.py)

---

## 🚀 Repository Structure

```text
soc-detection-lab/
├── README.md                          ← This file
├── architecture.png                   ← Lab network diagram
├── detection-scenarios/               ← Attack execution and detection logic
│   ├── scenario1-T1059.001-powershell/
│   ├── scenario2-T1003.001-lsass/
│   ├── scenario3-T1547.001-persistence/
│   ├── scenario4-T1053.005-scheduled-task/
│   ├── scenario5-T1055.001-dll-injection/
│   ├── scenario6-T1046-network-scan/
│   └── scenario7-T1071.001-c2-beacon/
├── queries/                           ← Exported KQL detection rules (.ndjson)
│   ├── T1003.001-lsass-access.ndjson
│   ├── T1046-network-scan-suricata.ndjson
│   ├── T1047.001-run-key-persistence.ndjson
│   ├── T1053.005-scheduled-task.ndjson
│   ├── T1055.001-dll-injection.ndjson
│   ├── T1059.001-encoded-powershell.ndjson
│   └── T1071.001-malicious-user-agent.ndjson
│   └── T1071.001-suspicious-script-egress.ndjson
├── threat-hunting/                    ← Proactive hunt reports and methodology
│   ├── README.md
│   ├── hunt1-lolbin-abuse.md
│   ├── hunt2-lsass-recon.md
│   ├── hunt3-persistence-audit.md
│   └── hunt4-c2-beaconing.md
├── screenshots/                       ← Evidence of SIEM ingestion and alert firing
└── soar/                              ← Python Discord webhook alerter
    ├── README.md
    └── elk_discord_alerter.py
```