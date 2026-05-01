# Threat Hunting

> **Proactive, hypothesis-driven investigation of endpoint and network log data — searching for adversary behavior that no existing detection rule was written to catch.**

---

## What is threat hunting?

Most SOC detection is **reactive** — a rule fires, an alert appears, an analyst investigates. The rule defines what gets found. An attacker who stays below the rule threshold is invisible.

Threat hunting is **proactive**. A human analyst forms a hypothesis about how an attacker might behave, then manually searches through raw log data looking for evidence — with no alert guiding the investigation. The analyst is the detection engine, not the SIEM.

The practical difference:

| | Reactive (alert-driven) | Proactive (hunt-driven) |
|---|---|---|
| **Trigger** | Rule fires | Analyst forms a hypothesis |
| **Coverage** | Only what rules are written for | Anything the analyst can reason about |
| **Output** | Alert in the SIEM queue | Hunt report + potential new rule |
| **Blind spots** | Novel techniques, sub-threshold behavior | Limited by analyst's creativity and data availability |
| **Result if nothing found** | No alert | "Clean" — documented absence of evidence |

Threat hunting does not replace detection rules. It feeds into them. When a hunt finds something a rule missed, the analyst writes a new rule — closing the gap for every future occurrence. This is the detection engineering feedback loop.

---

## Lab context

This lab contains rich endpoint and network telemetry from 7 attack scenarios across 5 MITRE ATT&CK techniques. Rather than requiring new attacks, the hunts in this section investigate **existing log data retroactively** — the same way a real analyst would respond to a tip: "we think there may have been credential access activity on this host last week."

**Data sources available for hunting:**

| Source | Events | Coverage |
|---|---|---|
| Sysmon Event ID 1 | Process creation with full command line | Execution, LOLBin abuse |
| Sysmon Event ID 3 | Network connections by process | C2, lateral movement |
| Sysmon Event ID 8 | CreateRemoteThread | Process injection |
| Sysmon Event ID 10 | ProcessAccess (lsass target) | Credential dumping |
| Sysmon Event ID 13 | Registry value writes | Persistence |
| Windows Event 4698 | Scheduled task creation | Persistence |
| Suricata HTTP flows | Full HTTP metadata including user agents | C2 beaconing |
| Suricata alerts | Emerging Threats IDS signatures | Network scanning, malicious traffic |

---

## Hunting methodology

Every hunt in this section follows the same five-step loop:

```
1. HYPOTHESISE  →  form a specific, falsifiable hypothesis
2. HUNT         →  write KQL queries in Kibana Discover to search for evidence
3. ANALYSE      →  classify each finding: malicious / benign / absent
4. DOCUMENT     →  write a structured hunt report covering all queries and findings
5. HARDEN       →  if a gap was found, write or update a detection rule
```

### Step 1 — Hypothesise
A good hypothesis is specific and falsifiable. Not: "look for suspicious activity." Instead: "An attacker may have used LOLBins to avoid signature detection — specifically rundll32.exe or mavinject.exe with unusual arguments or parent processes."

The hypothesis determines which data sources to query, which fields to filter on, and what a "finding" looks like.

### Step 2 — Hunt
Queries are written in KQL and run manually in Kibana Discover — not as scheduled detection rules. Every query run is recorded in the hunt report, including queries that return zero results. The time range is set to cover all historical lab data.

### Step 3 — Analyse
Each event returned by a hunt query gets a classification:

- **Confirmed malicious** — matches the hypothesis, consistent with attack behavior, no innocent explanation
- **Investigated and benign** — matched the query but has a legitimate explanation (e.g. svchost.exe accessing lsass for credential validation)
- **No evidence** — query returned zero results; absence of evidence documented as a finding

### Step 4 — Document
Every hunt produces a structured markdown report committed to `/threat-hunting/`. The report covers the hypothesis, trigger, data sources queried, every KQL query run (including empty ones), all findings with classification, conclusion, and any detection gaps identified.

Writing empty-result queries into the report is deliberate. Documenting that you looked and found nothing is the difference between "we don't know" and "we checked and it's clean."

### Step 5 — Harden
If a hunt uncovers something a detection rule missed, a new rule is written or an existing rule is updated. The commit message references the hunt: `Hunt 2: update T1003.001 — add svchost+0x1410 conditional exclusion from gap analysis`. This creates a traceable link between the investigation and the rule change.

---

## Hunts in this lab

| # | Hunt | Hypothesis | Data sources | Finding | Rule impact |
|---|------|------------|--------------|---------|-------------|
| H1 | [LOLBin Abuse](hunt1-lolbin-abuse.md) | Attacker used trusted Windows binaries to execute malicious actions | Sysmon ID 1 | **Confirmed** — rundll32+comsvcs (T1003.001) and mavinject (T1055.001) found in historical data | No new rule needed — existing rules covered both findings |
| H2 | [LSASS Reconnaissance](hunt2-lsass-recon.md) | LSASS was accessed with masks or source processes not covered by the existing T1003.001 rule | Sysmon ID 10 | **Gap analysis complete** — svchost+0x1410 identified as benign false positive pattern | T1003.001 rule updated with svchost+0x1410 conditional exclusion |
| H3 | [Persistence Audit](hunt3-persistence-audit.md) | Persistence artifacts (Run keys, scheduled tasks) may still be present post-cleanup | Sysmon ID 13, Windows Event 4698, live system check | **Clean** — full creation-to-deletion lifecycle captured in SIEM; remediation confirmed via snapshot audit trail | None — existing rules and telemetry cover both techniques |
| H4 | [C2 Beaconing](hunt4-c2-beaconing.md) | A host may be beaconing to a C2 server via HTTP traffic with anomalous user agents or connection patterns | Suricata HTTP flows (suricata.eve.event_type: http), Sysmon ID 3 (NetworkConnect) | **Confirmed** — 4 anomalous HTTP user agents identified communicating with 192.168.75.11:8080; correlated with PowerShell outbound connections; burst communication pattern observed consistent with simulated C2 activity (T1071.001) | Detection gap identified and resolved — added Sysmon-based rule (`T1071.001-suspicious-script-egress`) to provide process-level visibility alongside existing Suricata detection |

---

## Key principle: absence of evidence is still a finding

When a hunt query returns zero results, that is not a failure — it is a documented conclusion. Logging that you searched for mshta.exe abuse and found nothing tells a future analyst (or auditor) that:

1. The hunt was performed on this date
2. These specific queries were run
3. No evidence was found in this time range

That documentation has real operational value. An undocumented "we looked and found nothing" is indistinguishable from "we never looked."

---

## References

- [MITRE ATT&CK — Tactics, Techniques and Procedures](https://attack.mitre.org/)
- [ThreatHunting Project — Hunt Catalogue](https://github.com/ThreatHuntingProject/ThreatHunting)
- [PEAK Threat Hunting Framework](https://www.splunk.com/en_us/blog/security/peak-threat-hunting-framework.html)
- [Elastic — Threat Hunting with EQL](https://www.elastic.co/guide/en/security/current/threat-hunting.html)
- [David Bianco — Hunting Maturity Model](https://detect-respond.blogspot.com/2015/10/a-simple-hunting-maturity-model.html)