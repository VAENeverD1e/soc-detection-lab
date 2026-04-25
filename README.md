# SOC Detection Lab: Endpoint & Network Threat Investigation

![Elastic Stack](https://img.shields.io/badge/Elastic-SIEM-005571?style=for-the-badge&logo=elasticsearch)
![Python](https://img.shields.io/badge/Python-SOAR-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Suricata](https://img.shields.io/badge/Suricata-IDS-EE0000?style=for-the-badge)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT&CK-FF6600?style=for-the-badge)

A hands-on Security Operations Center (SOC) detection laboratory designed to simulate advanced adversary techniques, engineer custom detection rules, and automate incident alerting. 

This project demonstrates an end-to-end Blue Team workflow: executing attacks, analyzing telemetry across both the endpoint and network layers, writing custom SIEM rules, and building SOAR capabilities.

## 🎯 Project Objective
To build technical competency in **defense-in-depth** threat detection by simulating adversary behaviors using **Atomic Red Team** and engineering behavioral detection rules using **Elastic SIEM (ELK)** and **KQL**. The project focuses on detecting techniques that evade traditional file-based antivirus (LOLBin abuse, fileless execution) and capturing network reconnaissance via intrusion detection systems.

### Key Skills Demonstrated
* **Detection Engineering:** Creating robust, behavioral-based KQL detection rules mapping to the MITRE ATT&CK framework.
* **Endpoint Log Analysis:** Deep analysis of **Sysmon** (Event IDs 1, 10, 13) and native Windows Security Events to trace attack execution.
* **Network Security Monitoring (NSM):** Utilizing **Suricata IDS** to capture malicious wire-level behavior and map Emerging Threats (ET) signatures.
* **Threat Hunting & Simulation:** Utilizing Atomic Red Team and FLARE-VM to safely simulate targeted attacks.
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

I engineered detections for six distinct MITRE ATT&CK techniques, focusing on high-fidelity, low-false-positive behavioral alerts. Detailed documentation, execution proofs, and KQL rule code are located in the `detection-scenarios/` directory.

| MITRE ID | Adversary Technique | Primary Telemetry | Custom Rule Status | Scenario Details |
| :--- | :--- | :--- | :---: | :--- |
| **T1059.001** | PowerShell Fileless Execution | Sysmon ID 1, 13 | ✅ Engineered | [View Scenario](./detection-scenarios/scenario1-T1059.001-powershell/README.md) |
| **T1003.001** | LSASS Dump via `comsvcs.dll` (LOLBin) | Sysmon ID 10 | ✅ Engineered | [View Scenario](./detection-scenarios/scenario2-T1003.001-lsass/README.md) |
| **T1547.001** | Registry Run Key Persistence | Sysmon ID 13 | ✅ Engineered | [View Scenario](./detection-scenarios/scenario3-T1547.001-persistence/README.md) |
| **T1053.005** | Scheduled Task Persistence | Sysmon ID 1, Win 4698 | ✅ Engineered | [View Scenario](./detection-scenarios/scenario4-T1053.005-scheduled-task/README.md) |
| **T1055.001** | DLL Injection via `mavinject.exe` | Sysmon ID 1 | ✅ Engineered | [View Scenario](./detection-scenarios/scenario5-T1055.001-dll-injection/README.md) |
| **T1046** | Network Service Discovery | Sysmon ID 1, Suricata IDS | ✅ Engineered | [View Scenario](./detection-scenarios/scenario6-T1046-network-scan/README.md) |
| **T1071** | C2 malicious UA | Sysmon ID 3, Suricata IDS | ✅ Engineered | [View Scenario](./detection-scenarios/scenario7-T1071.001-c2-beacon/README.md) |
---

## 🤖 SOAR: Custom ELK to Discord Alerter
To simulate a modern SOC workflow, I developed a lightweight SOAR (Security Orchestration, Automation, and Response) utility. 

Written in Python, `elk_discord_alerter.py` continuously polls the Elastic Security API for new High/Critical alerts. It parses the complex JSON alert payload (extracting Hostnames, Rule Names, and MITRE IDs) and pushes formatted incident notifications to a Discord channel via webhooks.

* **Documentation:** [SOAR Implementation Guide](./soar/README.md)
* **Code:** [`elk_discord_alerter.py`](./soar/elk_discord_alerter.py)

---

## 🚀 Repository Structure & Usage

```text
soc-detection-lab
├── README.md                          
├── architecture.png                   
├── detection-scenarios/               ← Attack execution and detection logic breakdowns
├── queries/                           ← Exported KQL detection rules (.ndjson)
├── screenshots/                       ← Evidence of SIEM ingestion and alert firing
└── soar/                              ← Python Discord webhook alerter