# 🛡️ Threat Hunt Report – Operation Entropy Gorilla: PHTG HealthCloud Intrusion

---

## 📌 Executive Summary

A cloud engineering employee at PHTG inadvertently exposed critical Azure infrastructure details via a LinkedIn post, including the public IP address of an internet-facing Windows VM (`azwks-phtg-02`). Within hours of the post, automated scanners discovered the exposed RDP port and initiated a sustained brute-force campaign that ultimately succeeded. An attacker identified as **Sarah Chen**, operating from Uruguay, gained persistent access to the compromised machine, deployed a Meterpreter payload disguised within PHTG's newly launched HealthCloud service, and established a Command & Control channel back to infrastructure at `173.244.55.130:4444`. The intrusion demonstrates the real-world consequences of OPSEC failures and highlights critical gaps in credential hygiene, endpoint protection configuration, and network exposure management.

---

## 🎯 Hunt Objectives

- Identify malicious activity across endpoints and network telemetry
- Correlate attacker behavior to MITRE ATT&CK techniques
- Document evidence, detection gaps, and response opportunities

---

## 🧭 Scope & Environment

- **Environment:** Microsoft Azure — PHTG Production Tenant (`law-cyber-range`)
- **Target Host:** `azwks-phtg-02` (Public IP: `74.249.82.162`)
- **Data Sources:** `DeviceNetworkEvents`, `DeviceLogonEvents`, `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceEvents`
- **Platform:** Microsoft Sentinel / Microsoft Defender for Endpoint
- **Timeframe:** 2025-12-09 → 2025-12-23

---

## 📚 Table of Contents

- [🧠 Hunt Overview](#-hunt-overview)
- [🧬 MITRE ATT&CK Summary](#-mitre-attck-summary)
- [🔍 Flag Analysis](#-flag-analysis)
  - [🚩 Flag 1 – Exposed Asset Identification](#-flag-1--exposed-asset-identification)
  - [🚩 Flag 2 – Public IP Exposure](#-flag-2--public-ip-exposure)
  - [🚩 Flag 3 – OSINT Actionability](#-flag-3--osint-actionability)
  - [🚩 Flag 4 – OSINT Activity Classification](#-flag-4--osint-activity-classification)
  - [🚩 Flag 5 – Evidence Source Selection](#-flag-5--evidence-source-selection)
  - [🚩 Flag 6 – RDP Scanning Activity](#-flag-6--rdp-scanning-activity)
  - [🚩 Flag 7 – Scanning Volume](#-flag-7--scanning-volume)
  - [🚩 Flag 8 – Source IP Diversity](#-flag-8--source-ip-diversity)
  - [🚩 Flag 9 – Connection Outcomes](#-flag-9--connection-outcomes)
  - [🚩 Flag 10 – Geographic Scan Distribution](#-flag-10--geographic-scan-distribution)
  - [🚩 Flag 11 – Authentication Volume](#-flag-11--authentication-volume)
  - [🚩 Flag 12 – RDP Auth Volume](#-flag-12--rdp-auth-volume)
  - [🚩 Flag 13 – Dominant Auth Outcome](#-flag-13--dominant-auth-outcome)
  - [🚩 Flag 14 – Failure Reason](#-flag-14--failure-reason)
  - [🚩 Flag 15 – Countries from Auth Activity](#-flag-15--countries-from-auth-activity)
  - [🚩 Flag 16 – Countries with Successful Auth](#-flag-16--countries-with-successful-auth)
  - [🚩 Flag 17 – Successful Countries](#-flag-17--successful-countries)
  - [🚩 Flag 18 – Unexpected Country](#-flag-18--unexpected-country)
  - [🚩 Flag 19 – Compromised Account](#-flag-19--compromised-account)
  - [🚩 Flag 20 – Uruguay Success Count](#-flag-20--uruguay-success-count)
  - [🚩 Flag 21 – First RemoteIP from Uruguay](#-flag-21--first-remoteip-from-uruguay)
  - [🚩 Flag 22 – Second RemoteIP from Uruguay](#-flag-22--second-remoteip-from-uruguay)
  - [🚩 Flag 23 – First Notable Process](#-flag-23--first-notable-process)
  - [🚩 Flag 24 – Sensitive Text File](#-flag-24--sensitive-text-file)
  - [🚩 Flag 25 – First Executable Form](#-flag-25--first-executable-form)
  - [🚩 Flag 26 – Double-Extension Evasion](#-flag-26--double-extension-evasion)
  - [🚩 Flag 27 – File SHA256](#-flag-27--file-sha256)
  - [🚩 Flag 28 – Final File Name](#-flag-28--final-file-name)
  - [🚩 Flag 29 – File Classification](#-flag-29--file-classification)
  - [🚩 Flag 30 – Why Did It Run](#-flag-30--why-did-it-run)
  - [🚩 Flag 31 – First Execution](#-flag-31--first-execution)
  - [🚩 Flag 32 – Parent Process](#-flag-32--parent-process)
  - [🚩 Flag 33 – Batch File Wrapper](#-flag-33--batch-file-wrapper)
  - [🚩 Flag 34 – C2 IP](#-flag-34--c2-ip)
  - [🚩 Flag 35 – C2 Geography](#-flag-35--c2-geography)
  - [🚩 Flag 36 – C2 Remote Port](#-flag-36--c2-remote-port)
  - [🚩 Flag 37 – Repurposed Baseline](#-flag-37--repurposed-baseline)
- [🚨 Detection Gaps & Recommendations](#-detection-gaps--recommendations)
- [🧾 Final Assessment](#-final-assessment)
- [📎 Analyst Notes](#-analyst-notes)

---

## 🧠 Hunt Overview

This hunt was initiated following an OSINT review of employee social media activity. A PHTG cloud engineer posted a photo on LinkedIn celebrating the first day of the internal HealthCloud rollout (December 11, 2025). The photo inadvertently exposed an Azure portal view showing the VM name `azwks-phtg-02` and its associated public IP address `74.249.82.162` with RDP (port 3389) open to the internet.

Within hours of the post, automated scanners from 173 distinct public IPs began probing port 3389. A sustained brute-force campaign produced 675 RDP authentication attempts, the vast majority of which failed with `InvalidUserNameOrPassword`. However, the weak credential `vmadminusername` was eventually cracked, and an attacker — later identified as **Sarah Chen** based on device artifacts — successfully authenticated from Uruguayan IP addresses in the `173.244.55.x/28` subnet.

During active sessions on December 11–13, the attacker read internal PHTG documents, downloaded a Meterpreter payload from an ngrok-hosted URL (`https://unresuscitating-donnette-smothery.ngrok-free.dev/Sarah_Chen_Notes.Txt`), evaded Defender quarantine by switching it to Passive Mode, disguised the payload as `PHTG.exe` inside the legitimate HealthCloud service directory, and modified `Launch.bat` to establish persistent execution. The payload established a C2 channel to `173.244.55.130` on port `4444` — the default Metasploit listener port — completing a full intrusion lifecycle from OSINT exposure to persistent access.

---

## 🧬 MITRE ATT&CK Summary

| Flag | Technique Category | MITRE ID | Priority |
|-----:|-------------------|----------|----------|
| 1 | OSINT / Asset Discovery | T1596 | 🟡 Medium |
| 2 | Public-Facing RDP Exposure | T1133 | 🔴 Critical |
| 3 | OSINT Exploitation | T1589 | 🟡 Medium |
| 4 | OSINT / Social Media | T1593.001 | 🟡 Medium |
| 5 | Evidence Source Selection | T1595 | 🟡 Medium |
| 6 | Network Scanning / Port Scan | T1046 | 🔴 Critical |
| 7 | Automated Scanning Volume | T1595.001 | 🔴 Critical |
| 8 | Distributed Scanning Infrastructure | T1595 | 🟠 High |
| 9 | TCP Handshake Probing | T1595.001 | 🟠 High |
| 10 | Geographic Threat Distribution | T1595 | 🟡 Medium |
| 11 | Brute Force — Total Volume | T1110 | 🔴 Critical |
| 12 | Brute Force — RDP | T1110.001 | 🔴 Critical |
| 13 | Failed Authentication Pattern | T1110.001 | 🔴 Critical |
| 14 | Credential Guessing | T1110.001 | 🔴 Critical |
| 15 | Auth Geographic Distribution | T1078 | 🟠 High |
| 16 | Valid Account Compromise | T1078 | 🔴 Critical |
| 17 | Successful Auth Countries | T1078.003 | 🔴 Critical |
| 18 | Geo-Anomalous Logon | T1078.003 | 🔴 Critical |
| 19 | Local Account Abuse | T1078.003 | 🔴 Critical |
| 20 | Logon Session Frequency | T1078 | 🟠 High |
| 21 | Initial Access IP | T1133 | 🔴 Critical |
| 22 | Secondary Access IP | T1133 | 🔴 Critical |
| 23 | Interactive Session Reconnaissance | T1059.003 | 🟠 High |
| 24 | Sensitive File Discovery | T1083 | 🟠 High |
| 25 | Masquerading — Executable Rename | T1036.003 | 🔴 Critical |
| 26 | Double Extension Evasion | T1036.007 | 🔴 Critical |
| 27 | File Hash / IOC Identification | T1036 | 🟠 High |
| 28 | Final Payload Masquerade | T1036.005 | 🔴 Critical |
| 29 | Malware Classification | T1587.001 | 🔴 Critical |
| 30 | Impair Defenses — Passive Mode | T1562.001 | 🔴 Critical |
| 31 | Execution — Initial Phase | T1204 | 🔴 Critical |
| 32 | Execution — Parent Process | T1059.003 | 🔴 Critical |
| 33 | Persistence via Batch File | T1547 | 🔴 Critical |
| 34 | C2 IP Identification | T1571 | 🔴 Critical |
| 35 | C2 Geographic Attribution | T1571 | 🟠 High |
| 36 | C2 Non-Standard Port | T1571 | 🔴 Critical |
| 37 | Hijack Execution Flow / Living off Land | T1574 | 🔴 Critical |

---

## 🔍 Flag Analysis

_All flags below are collapsible for readability._

---

<details>
<summary id="-flag-1--exposed-asset-identification">🚩 <strong>Flag 1: Exposed Asset Identification</strong></summary>

### 🎯 Objective
Anchor the investigation to a specific Azure VM identified from OSINT evidence in the LinkedIn post.

### 📌 Finding
The Azure portal screenshot visible in the LinkedIn photo identified the target VM as `azwks-phtg-02`.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azwks-phtg-02 |
| Timestamp | 2025-12-11 (LinkedIn post date) |
| Process | N/A — OSINT |
| Parent Process | N/A |
| Command Line | N/A |

### 💡 Why it matters
The VM name is the anchor for every subsequent query in the investigation. Without identifying the correct asset from OSINT, the hunt cannot begin. This also demonstrates how a single social media post can hand an attacker their first target.

### 🔧 KQL Query Used
```
N/A — Derived from OSINT analysis of LinkedIn exhibit
```

### 🖼️ Screenshot
<img width="8423" height="19200" alt="evidence" src="https://github.com/user-attachments/assets/fa9bca45-84e9-45fe-b586-80bfa990eda0" />


### 🛠️ Detection Recommendation
Implement a social media monitoring policy prohibiting screenshots of internal infrastructure. Enforce OPSEC training for all engineering staff, particularly those with access to cloud management consoles.

**Hunting Tip:** Periodically search LinkedIn, Twitter/X, and GitHub for mentions of your organization's internal hostnames, IP ranges, or Azure resource names.

</details>

---

<details>
<summary id="-flag-2--public-ip-exposure">🚩 <strong>Flag 2: Public IP Exposure</strong></summary>

### 🎯 Objective
Identify the public IP address associated with the exposed VM, confirming internet reachability.

### 📌 Finding
The Azure portal networking panel visible in the LinkedIn photo showed public IP `74.249.82.162` associated with `azwks-phtg-02`.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azwks-phtg-02 |
| Public IP | 74.249.82.162 |
| Port | 3389 (RDP) |
| Timestamp | 2025-12-11 |
| Process | N/A — OSINT |

### 💡 Why it matters
A public IP directly associated with an RDP-enabled VM is immediately actionable by any attacker who sees it. The moment this IP appeared in the LinkedIn photo, it became a live attack surface reachable by anyone on the internet.

### 🔧 KQL Query Used
```
N/A — Derived from OSINT analysis of Azure portal exhibit
```

### 🖼️ Screenshot
*Azure portal networking panel showing public IP assignment*

### 🛠️ Detection Recommendation
Remove public IP assignments from all VMs that do not require direct internet access. Use Azure Bastion for remote administration. Enforce NSG rules restricting RDP to known corporate IPs only.

**Hunting Tip:** Query Azure Resource Graph for all VMs with public IPs and open port 3389 — any result is a priority remediation target.

</details>

---

<details>
<summary id="-flag-3--osint-actionability">🚩 <strong>Flag 3: OSINT Actionability</strong></summary>

### 🎯 Objective
Determine what specific element of the LinkedIn post gave an attacker the most actionable intelligence.

### 📌 Finding
**Answer: D** — The public IP address visible in the networking panel was the most actionable piece of information. All other details (OS, VM size, region, tags) are descriptive but not directly exploitable without a connection point.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Answer | D — Public IP address visible and associated with the VM |
| Context | IP provides direct connection point; all other info is contextual only |

### 💡 Why it matters
Knowing an OS version or VM size helps an attacker plan — but a public IP lets them act immediately. The distinction between descriptive intelligence and actionable intelligence is critical in OSINT analysis.

### 🔧 KQL Query Used
```
N/A — Multiple choice analysis
```

### 🖼️ Screenshot
*N/A*

### 🛠️ Detection Recommendation
Before posting any screenshots of cloud consoles, require engineering staff to blur or redact all IP addresses, hostnames, and resource identifiers.

**Hunting Tip:** Train analysts to evaluate OSINT exposure not just by what is visible, but by what is immediately exploitable without additional steps.

</details>

---

<details>
<summary id="-flag-4--osint-activity-classification">🚩 <strong>Flag 4: OSINT Activity Classification</strong></summary>

### 🎯 Objective
Classify the type of activity being performed in the LinkedIn photo based on what is visible on screen.

### 📌 Finding
**Answer: C** — The engineer was managing cloud infrastructure resources. The Azure portal open with VM management details is a clear indicator of cloud infrastructure management activity.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Answer | C — Managing cloud infrastructure resources |
| Visual Evidence | Azure portal VM management view visible on workstation |

### 💡 Why it matters
Understanding what type of activity is being photographed helps assess what information may have been inadvertently exposed. Cloud infrastructure management sessions contain the highest density of sensitive operational details.

### 🔧 KQL Query Used
```
N/A — Multiple choice analysis
```

### 🖼️ Screenshot
*LinkedIn exhibit — workstation showing Azure portal*

### 🛠️ Detection Recommendation
Implement a clear desk/clear screen policy for all remote work environments. Prohibit photography of workstations during active cloud management sessions.

**Hunting Tip:** When assessing OSINT exposure from photos, always classify the activity type first — it determines the category and sensitivity of information likely visible.

</details>

---

<details>
<summary id="-flag-5--evidence-source-selection">🚩 <strong>Flag 5: Evidence Source Selection</strong></summary>

### 🎯 Objective
Identify which telemetry source should be reviewed first to determine whether the exposed public IP was subject to scanning or enumeration.

### 📌 Finding
**Answer: D** — Azure network or platform analytics related to inbound connections. Network-layer events capture scanning activity before any authentication or process execution occurs.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Answer | D — Azure network / platform analytics for inbound connections |
| Rationale | Scanning occurs at the network layer before authentication |

### 💡 Why it matters
Scanning and enumeration are network-layer events. They appear as inbound connection attempts before any authentication occurs. Network flow data captures this earliest in the kill chain — before logon events, before process events, before anything else.

### 🔧 KQL Query Used
```
N/A — Multiple choice analysis
```

### 🖼️ Screenshot
*N/A*

### 🛠️ Detection Recommendation
Ensure `DeviceNetworkEvents` is ingested and retained in Sentinel for all internet-facing VMs. Network telemetry is the earliest detection layer for reconnaissance activity.

**Hunting Tip:** Always start threat hunts on internet-facing assets with network-layer telemetry — it captures attacker activity before they interact with the system itself.

</details>

---

<details>
<summary id="-flag-6--rdp-scanning-activity">🚩 <strong>Flag 6: RDP Scanning Activity</strong></summary>

### 🎯 Objective
Identify which port shows the strongest indicator of broad, automated scanning against the VM.

### 📌 Finding
**Port 3389** — all 194 `InboundConnectionAccepted` events exclusively targeted port 3389, confirming automated RDP scanning began within hours of the LinkedIn post.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azwks-phtg-02 |
| First Hit | 2025-12-11 03:42:25 UTC |
| Target Port | 3389 |
| Action Type | InboundConnectionAccepted |
| Total Events | 194 |

### 💡 Why it matters
Port 3389 is the Windows Remote Desktop Protocol port. Its exposure to the internet is a well-known attack vector targeted by automated botnets constantly scanning the internet. The speed of discovery confirms near-instantaneous detection of newly exposed services.

### 🔧 KQL Query Used
```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where DeviceName == "azwks-phtg-02"
| where RemoteIPType == "Public"
| summarize count() by LocalPort, ActionType
```

### 🖼️ Screenshot
*All 194 events targeting port 3389*

### 🛠️ Detection Recommendation
Create an alert for any `InboundConnectionAccepted` event on port 3389 from a public IP. No legitimate remote access should originate from unknown public IPs.

**Hunting Tip:** Spike detection — if a single port receives more than 10 unique source IPs within 1 hour, treat it as active scanning.

</details>

---

<details>
<summary id="-flag-7--scanning-volume">🚩 <strong>Flag 7: Scanning Volume</strong></summary>

### 🎯 Objective
Quantify the total number of network events targeting the exposed RDP service.

### 📌 Finding
**194** `InboundConnectionAccepted` events were recorded against port 3389 across the hunt window.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azwks-phtg-02 |
| Total Events | 194 |
| Port | 3389 |
| Action Type | InboundConnectionAccepted |
| Date Range | 2025-12-11 → 2025-12-22 |
| Busiest Day | Dec 13 — 65 events |

### 💡 Why it matters
194 inbound connections from 173 unique IPs across 11 days represents a sustained, global scanning campaign. The volume spike on December 13 (65 events) suggests an escalation after initial probing confirmed the port was responsive.

### 🔧 KQL Query Used
```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where DeviceName == "azwks-phtg-02"
| where LocalPort == 3389
| where RemoteIPType == "Public"
| summarize TotalAccepted = countif(ActionType == "InboundConnectionAccepted"),
            TotalAttempts = countif(ActionType == "ConnectionAttempt"),
            UniqueIPs = dcount(RemoteIP)
```

### 🖼️ Screenshot
*194 total accepted connections confirmed*

### 🛠️ Detection Recommendation
Set a threshold alert: if any single device receives more than 20 unique public source IPs on port 3389 within 24 hours, escalate immediately.

**Hunting Tip:** Use `bin(TimeGenerated, 1h)` to visualize scanning bursts over time and identify coordinated attack windows.

</details>

---

<details>
<summary id="-flag-8--source-ip-diversity">🚩 <strong>Flag 8: Source IP Diversity</strong></summary>

### 🎯 Objective
Determine how many unique public source IPs targeted the exposed RDP service.

### 📌 Finding
**173** distinct public IP addresses targeted port 3389 on `azwks-phtg-02`.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azwks-phtg-02 |
| Unique Source IPs | 173 |
| Port | 3389 |
| Notable Subnet | 205.210.31.x/24 — 10 hits, coordinated rotation |

### 💡 Why it matters
173 unique source IPs indicate a distributed scanning infrastructure. The `205.210.31.x` subnet appearing 10 times across multiple days strongly suggests a single actor rotating through their own IP range to avoid IP-based blocking.

### 🔧 KQL Query Used
```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where DeviceName == "azwks-phtg-02"
| where LocalPort == 3389
| where RemoteIPType == "Public"
| summarize UniqueIPs = dcount(RemoteIP)
```

### 🖼️ Screenshot
*173 distinct source IPs confirmed*

### 🛠️ Detection Recommendation
Block entire `/24` subnets when multiple IPs from the same range appear in scanning activity. Add `205.210.31.0/24` to deny rules immediately.

**Hunting Tip:** Use substring grouping on RemoteIP to identify subnet-level clustering in scanner IPs.

</details>

---

<details>
<summary id="-flag-9--connection-outcomes">🚩 <strong>Flag 9: Connection Outcomes</strong></summary>

### 🎯 Objective
Identify IPs that showed both a connection attempt and an accepted connection — confirming TCP-level engagement.

### 📌 Finding
**57** source IPs showed both `ConnectionAttempt` and `InboundConnectionAccepted` events, including 4 internal `10.0.8.x` addresses.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azwks-phtg-02 |
| IPs with Both Actions | 57 |
| Public IPs | 53 |
| Internal IPs | 4 (10.0.8.5, 10.0.8.6, 10.0.8.8, 10.0.8.9) |

### 💡 Why it matters
IPs showing both action types received a real TCP response — they are engaged scanners, not blind probes. The internal `10.0.8.x` addresses represent a significant secondary finding suggesting potential lateral movement interest from within the network.

### 🔧 KQL Query Used
```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where DeviceName == "azwks-phtg-02"
| where LocalPort == 3389
| where ActionType in ("ConnectionAttempt", "InboundConnectionAccepted")
| summarize Actions = make_set(ActionType), connections = count() by RemoteIP
| where Actions has "ConnectionAttempt" and Actions has "InboundConnectionAccepted"
```

### 🖼️ Screenshot
*57 IPs confirmed with both action types*

### 🛠️ Detection Recommendation
Investigate the 4 internal `10.0.8.x` addresses immediately — any internal host probing RDP on another internal machine warrants review as a potential compromised endpoint.

**Hunting Tip:** `make_set(ActionType)` is the key operator for identifying IPs that performed multiple distinct actions against the same target.

</details>

---

<details>
<summary id="-flag-10--geographic-scan-distribution">🚩 <strong>Flag 10: Geographic Scan Distribution</strong></summary>

### 🎯 Objective
Enrich the 57 engaged scanner IPs with geographic data to understand the global distribution of the attack.

### 📌 Finding
The 57 IPs with both connection types spanned **11 distinct countries**.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azwks-phtg-02 |
| Distinct Countries | 11 |
| GeoTable Source | geoip2-ipv4 via GitHub datasets |

### 💡 Why it matters
11 countries confirms globally distributed scanning infrastructure — consistent with botnet activity or a threat actor using VPN/proxy infrastructure across multiple jurisdictions to evade geographic blocking.

### 🔧 KQL Query Used
```kql
let GeoTable =
    externaldata(network:string, geoname_id:long, continent_code:string,
                 continent_name:string, country_iso_code:string, country_name:string)
    [@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/main/data/geoip2-ipv4.csv"]
    with (format="csv");
let TargetIPs = datatable(RemoteIP:string)
["173.244.55.128","212.192.252.175" /* ... full list of 57 IPs ... */];
TargetIPs
| evaluate ipv4_lookup(GeoTable, RemoteIP, network)
| summarize dcount(country_name)
```

### 🖼️ Screenshot
*GeoIP enrichment confirming 11 distinct countries*

### 🛠️ Detection Recommendation
Implement geo-blocking at the NSG level for countries with no legitimate business relationship. At minimum, restrict RDP to known corporate IP ranges only.

**Hunting Tip:** Always enrich threat hunt findings with GeoIP data — geographic anomalies are often the fastest way to separate attacker traffic from legitimate noise.

</details>

---

<details>
<summary id="-flag-11--authentication-volume">🚩 <strong>Flag 11: Authentication Volume</strong></summary>

### 🎯 Objective
Quantify the total number of externally sourced authentication events recorded against the device.

### 📌 Finding
**693** externally sourced authentication events were recorded from public IPs against `azwks-phtg-02`.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azwks-phtg-02 |
| Total Auth Events | 693 |
| Source | Public IPs only |
| Table | DeviceLogonEvents |

### 💡 Why it matters
693 auth events vs 194 network connection events means attackers were firing multiple credential combinations per connection — the definition of brute force. The ratio confirms automated credential stuffing tools were in use.

### 🔧 KQL Query Used
```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where DeviceName == "azwks-phtg-02"
| where RemoteIPType == "Public"
| summarize count()
```

### 🖼️ Screenshot
*693 total external auth events confirmed*

### 🛠️ Detection Recommendation
Alert on any device receiving more than 10 failed authentication attempts from a single external IP within 5 minutes. Implement account lockout policies and MFA on all internet-facing accounts.

**Hunting Tip:** Always pivot from `DeviceNetworkEvents` to `DeviceLogonEvents` when investigating RDP exposure — the two tables together tell the complete story.

</details>

---

<details>
<summary id="-flag-12--rdp-auth-volume">🚩 <strong>Flag 12: RDP Auth Volume</strong></summary>

### 🎯 Objective
Isolate the number of authentication events specifically related to Remote Desktop activity.

### 📌 Finding
**675** of the 693 total external auth events were RDP-related, confirming virtually all attack activity was RDP-focused.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azwks-phtg-02 |
| RDP Auth Events | 675 |
| Non-RDP Events | 18 |

### 💡 Why it matters
675 RDP attempts against a single machine represents a sustained brute-force campaign. The near-total focus on RDP confirms the attacker's strategy was entirely credential-based exploitation of the exposed remote access service.

### 🔧 KQL Query Used
```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where DeviceName == "azwks-phtg-02"
| where RemoteIPType == "Public"
| summarize count() by LogonType
```

### 🖼️ Screenshot
*675 RDP auth events confirmed*

### 🛠️ Detection Recommendation
Any device receiving more than 50 `RemoteInteractive` logon failures from external IPs in a 24-hour period should trigger an automatic isolation response.

**Hunting Tip:** Filter `DeviceLogonEvents` by `LogonType` to isolate RDP-specific activity from other authentication noise.

</details>

---

<details>
<summary id="-flag-13--dominant-auth-outcome">🚩 <strong>Flag 13: Dominant Auth Outcome</strong></summary>

### 🎯 Objective
Determine which authentication outcome was most frequently recorded for RDP activity.

### 📌 Finding
`LogonFailed` was the dominant outcome — the overwhelming majority of 675 RDP attempts were rejected.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azwks-phtg-02 |
| Dominant ActionType | LogonFailed |
| Context | Active brute force campaign |

### 💡 Why it matters
A large volume of `LogonFailed` events followed eventually by `LogonSuccess` is the textbook signature of a successful brute-force attack. The failures are not the end of the story — they are the precursor to compromise.

### 🔧 KQL Query Used
```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where DeviceName == "azwks-phtg-02"
| where RemoteIPType == "Public"
| summarize count() by ActionType
| order by count_ desc
```

### 🖼️ Screenshot
*LogonFailed as the dominant ActionType*

### 🛠️ Detection Recommendation
Configure Sentinel to alert when `LogonFailed` count exceeds 20 from a single source IP within 10 minutes on any device, combined with a subsequent `LogonSuccess` from the same source.

**Hunting Tip:** Always check whether a brute-force campaign eventually produced a `LogonSuccess` — that's the pivot point from noise to incident.

</details>

---

<details>
<summary id="-flag-14--failure-reason">🚩 <strong>Flag 14: Failure Reason</strong></summary>

### 🎯 Objective
Identify the specific reason for RDP authentication failures.

### 📌 Finding
`InvalidUserNameOrPassword` was the most common failure reason — confirming a credential guessing/brute-force campaign.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azwks-phtg-02 |
| Failure Reason | InvalidUserNameOrPassword |
| Implication | Automated credential guessing in progress |

### 💡 Why it matters
`InvalidUserNameOrPassword` confirms the attacker was cycling through username/password combinations using automated tooling — distinct from other failure reasons like expired credentials or locked accounts.

### 🔧 KQL Query Used
```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where DeviceName == "azwks-phtg-02"
| where RemoteIPType == "Public"
| where ActionType == "LogonFailed"
| summarize count() by FailureReason
| order by count_ desc
```

### 🖼️ Screenshot
*InvalidUserNameOrPassword as dominant failure reason*

### 🛠️ Detection Recommendation
Enforce strong password policies and implement MFA. Weak, predictable credentials like `vmadminusername` should be rejected at account creation time.

**Hunting Tip:** The `FailureReason` field in `DeviceLogonEvents` is frequently overlooked — it provides critical context for distinguishing brute force from other authentication issues.

</details>

---

<details>
<summary id="-flag-15--countries-from-auth-activity">🚩 <strong>Flag 15: Countries from Auth Activity</strong></summary>

### 🎯 Objective
Determine how many unique countries were associated with RDP-related authentication events.

### 📌 Finding
**17 distinct countries** were associated with RDP authentication events — more than the 11 from network scanning, reflecting additional IPs that appeared in auth logs but not in the filtered network event set.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azwks-phtg-02 |
| Countries in Auth Logs | 17 |
| Countries in Network Logs | 11 |
| Delta | 6 additional countries in auth layer |

### 💡 Why it matters
The higher country count in auth logs vs network logs shows that not all scanning IPs were captured in the filtered network events. Auth logs provide a wider view of the attack surface and should always be checked independently.

### 🔧 KQL Query Used
```kql
let GeoTable =
    externaldata(network:string, geoname_id:long, continent_code:string,
                 continent_name:string, country_iso_code:string, country_name:string)
    [@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/main/data/geoip2-ipv4.csv"]
    with (format="csv");
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where DeviceName == "azwks-phtg-02"
| where RemoteIPType == "Public"
| where ActionType == "LogonFailed"
| distinct RemoteIP
| evaluate ipv4_lookup(GeoTable, RemoteIP, network)
| summarize dcount(country_name)
```

### 🖼️ Screenshot
*17 countries confirmed from auth activity*

### 🛠️ Detection Recommendation
Combine network and authentication telemetry for complete geographic coverage — neither source alone provides a full picture of the attack surface.

**Hunting Tip:** Network events and logon events capture different moments in the attack chain — always query both when building a complete picture of RDP attack activity.

</details>

---

<details>
<summary id="-flag-16--countries-with-successful-auth">🚩 <strong>Flag 16: Countries with Successful Auth</strong></summary>

### 🎯 Objective
Identify how many of the 17 countries associated with auth activity had at least one successful authentication.

### 📌 Finding
**2 countries** had at least one successful RDP authentication: United States and Uruguay.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azwks-phtg-02 |
| Countries with LogonSuccess | 2 |
| Total Auth Countries | 17 |
| Success Rate by Country | 2 of 17 (11.8%) |

### 💡 Why it matters
Of 17 countries that attempted authentication, only 2 succeeded. This confirms the brute force was eventually effective despite a high failure rate. Both countries warrant investigation — US could be legitimate or proxy infrastructure; Uruguay is immediately anomalous.

### 🔧 KQL Query Used
```kql
let GeoTable =
    externaldata(network:string, geoname_id:long, continent_code:string,
                 continent_name:string, country_iso_code:string, country_name:string)
    [@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/main/data/geoip2-ipv4.csv"]
    with (format="csv");
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where DeviceName == "azwks-phtg-02"
| where RemoteIPType == "Public"
| where ActionType == "LogonSuccess"
| distinct RemoteIP
| evaluate ipv4_lookup(GeoTable, RemoteIP, network)
| summarize dcount(country_name)
```

### 🖼️ Screenshot
*2 countries with LogonSuccess confirmed*

### 🛠️ Detection Recommendation
Implement Conditional Access policies that block or require step-up authentication for logons originating outside the organization's known operating countries.

**Hunting Tip:** Always filter successful auth events by geography immediately — it dramatically narrows the investigation scope.

</details>

---

<details>
<summary id="-flag-17--successful-countries">🚩 <strong>Flag 17: Successful Countries</strong></summary>

### 🎯 Objective
Identify which specific countries were associated with successful RDP authentication events.

### 📌 Finding
**Uruguay** and **United States** — two countries with at least one `LogonSuccess` event against the target device.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azwks-phtg-02 |
| Country 1 | United States |
| Country 2 | Uruguay |
| Uruguay IPs | 173.244.55.128, 173.244.55.131 |
| US IPs | 173.239.218.124, 142.111.152.58 |

### 💡 Why it matters
The United States hits may represent cloud infrastructure used as a relay. Uruguay is immediately suspicious given PHTG's US-only operations, and becomes the primary investigation focus.

### 🔧 KQL Query Used
```kql
let GeoTable =
    externaldata(network:string, geoname_id:long, continent_code:string,
                 continent_name:string, country_iso_code:string, country_name:string)
    [@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/main/data/geoip2-ipv4.csv"]
    with (format="csv");
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where DeviceName == "azwks-phtg-02"
| where RemoteIPType == "Public"
| where ActionType == "LogonSuccess"
| evaluate ipv4_lookup(GeoTable, RemoteIP, network)
| summarize Countries = make_set(country_name)
```

### 🖼️ Screenshot
*Uruguay and United States confirmed as successful auth countries*

### 🛠️ Detection Recommendation
Build a KQL watchlist of authorized countries for your organization and alert on any `LogonSuccess` from outside that list.

**Hunting Tip:** Cross-reference successful auth countries against the organization's known operating regions immediately — any mismatch is a high-priority lead.

</details>

---

<details>
<summary id="-flag-18--unexpected-country">🚩 <strong>Flag 18: Unexpected Country</strong></summary>

### 🎯 Objective
Identify which country associated with successful authentication falls outside PHTG's expected operating region.

### 📌 Finding
**Uruguay** — PHTG operates exclusively in the United States and has no international workforce. Any authentication from Uruguay is by definition unauthorized.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azwks-phtg-02 |
| Unexpected Country | Uruguay |
| Subnet | 173.244.55.128/28 |
| PHTG Operating Region | United States only |

### 💡 Why it matters
Uruguay has no legitimate business relationship with PHTG. Successful RDP authentication from this country represents confirmed unauthorized access and is the key pivot point from investigation to incident response.

### 🔧 KQL Query Used
```kql
-- Same as Flag 17 with country_name == "Uruguay" filter applied
```

### 🖼️ Screenshot
*Uruguay confirmed as unauthorized access origin*

### 🛠️ Detection Recommendation
Immediately block all inbound RDP from the `173.244.55.128/28` subnet. Treat all sessions from this range as attacker-controlled.

**Hunting Tip:** Maintain a geo-allowlist for your organization. Any `LogonSuccess` from outside the allowlist should auto-generate a high-severity incident.

</details>

---

<details>
<summary id="-flag-19--compromised-account">🚩 <strong>Flag 19: Compromised Account</strong></summary>

### 🎯 Objective
Identify the account used in the successful unauthorized RDP authentication from Uruguay.

### 📌 Finding
**`vmadminusername`** — a generic, predictable local administrator account name that was trivially brute-forced. The `RemoteDeviceName` field revealed the attacker's device hostname: `sarah-che`.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azwks-phtg-02 |
| Compromised Account | vmadminusername |
| Source IPs | 173.244.55.128, 173.244.55.131 |
| First Successful Logon | 2025-12-12 00:47:45 UTC |
| Remote Device Name | sarah-che / sarah-cheη |

### 💡 Why it matters
`vmadminusername` is a textbook weak credential — generic, predictable, and exactly what brute-force wordlists target first. The `RemoteDeviceName` artifact provides the attacker's first name: **Sarah Chen**.

### 🔧 KQL Query Used
```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where DeviceName == "azwks-phtg-02"
| where RemoteIPType == "Public"
| where ActionType == "LogonSuccess"
| where RemoteIP startswith "173.244.55"
| project TimeGenerated, AccountName, RemoteIP, LogonType, RemoteDeviceName
```

### 🖼️ Screenshot
*vmadminusername confirmed as compromised account with sarah-che device name*

### 🛠️ Detection Recommendation
Enforce a naming convention policy preventing generic account names. Require all local admin accounts to use complex non-guessable names combined with MFA. Disable or rename the default administrator account on all VMs at provisioning time.

**Hunting Tip:** The `RemoteDeviceName` field in `DeviceLogonEvents` often contains the attacker's machine hostname — a valuable attribution artifact frequently overlooked.

</details>

---

<details>
<summary id="-flag-20--uruguay-success-count">🚩 <strong>Flag 20: Uruguay Success Count</strong></summary>

### 🎯 Objective
Quantify how many successful RDP authentication events originated from Uruguay, excluding local session events.

### 📌 Finding
**23** genuine external logon events from Uruguay — after excluding 4 `IsLocalLogon:true` Unlock events which represent local session actions, not inbound remote connections.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azwks-phtg-02 |
| Total Uruguay Logons | 27 |
| IsLocalLogon:true (Unlock) | 4 (excluded) |
| Genuine External Logons | 23 |
| Breakdown | Network: 16, RemoteInteractive: 7 |

### 💡 Why it matters
The distinction between `IsLocalLogon:true` and `IsLocalLogon:false` is critical for accurate counting. Unlock events are triggered locally when a remote session resumes a locked screen — they are not new inbound connections and should be excluded from external auth counts.

### 🔧 KQL Query Used
```kql
let GeoTable =
    externaldata(network:string, geoname_id:long, continent_code:string,
                 continent_name:string, country_iso_code:string, country_name:string)
    [@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/main/data/geoip2-ipv4.csv"]
    with (format="csv");
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where DeviceName == "azwks-phtg-02"
| where RemoteIPType == "Public"
| where ActionType == "LogonSuccess"
| evaluate ipv4_lookup(GeoTable, RemoteIP, network)
| where country_name == "Uruguay"
| where AdditionalFields has "false"
| count
```

### 🖼️ Screenshot
*23 genuine external Uruguay logons confirmed*

### 🛠️ Detection Recommendation
When counting external authentication events, always filter on `AdditionalFields has "IsLocalLogon\":false"` to exclude locally-initiated session actions.

**Hunting Tip:** The `AdditionalFields` JSON blob in `DeviceLogonEvents` contains `IsLocalLogon` — always parse this when counting true inbound authentication events.

</details>

---

<details>
<summary id="-flag-21--first-remoteip-from-uruguay">🚩 <strong>Flag 21: First RemoteIP from Uruguay</strong></summary>

### 🎯 Objective
Identify the IP address used in the first successful RDP authentication from Uruguay.

### 📌 Finding
**`173.244.55.131`** — first successful logon from Uruguay recorded at 2025-12-12 00:47:45 UTC.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azwks-phtg-02 |
| First Uruguay IP | 173.244.55.131 |
| First Logon | 2025-12-12 00:47:45 UTC |
| Account | vmadminusername |

### 💡 Why it matters
This IP represents the initial foothold — the moment the brute-force campaign succeeded and the attacker first gained interactive access to the machine. All subsequent attacker activity flows from this event.

### 🔧 KQL Query Used
```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where DeviceName == "azwks-phtg-02"
| where RemoteIPType == "Public"
| where ActionType == "LogonSuccess"
| where RemoteIP startswith "173.244.55"
| project TimeGenerated, AccountName, RemoteIP
| order by TimeGenerated asc
| take 1
```

### 🖼️ Screenshot
*173.244.55.131 confirmed as first successful logon IP*

### 🛠️ Detection Recommendation
This IP and all associated subnet IPs should be added to threat intelligence blocklists and NSG deny rules immediately upon discovery.

**Hunting Tip:** Always identify the chronologically first successful auth event — it establishes the initial access timestamp which anchors all subsequent investigation timelines.

</details>

---

<details>
<summary id="-flag-22--second-remoteip-from-uruguay">🚩 <strong>Flag 22: Second RemoteIP from Uruguay</strong></summary>

### 🎯 Objective
Identify the second IP address used for successful authentication from Uruguay.

### 📌 Finding
**`173.244.55.128`** — used for the bulk of the active session activity on December 12–13, with 5 `RemoteInteractive` logons indicating multiple full RDP desktop sessions.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azwks-phtg-02 |
| Second Uruguay IP | 173.244.55.128 |
| Logon Count | 10 events |
| RemoteInteractive Sessions | 5 |
| Subnet | 173.244.55.128/28 (same as first IP) |

### 💡 Why it matters
Both IPs sit in the same `/28` subnet (`173.244.55.128/28`) — almost certainly the same attacker rotating between two IPs within their own infrastructure. This subnet becomes the primary IOC for blocking and attribution.

### 🔧 KQL Query Used
```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where DeviceName == "azwks-phtg-02"
| where RemoteIPType == "Public"
| where ActionType == "LogonSuccess"
| where RemoteIP startswith "173.244.55"
| summarize count() by RemoteIP
```

### 🖼️ Screenshot
*173.244.55.128 confirmed as second Uruguay logon IP*

### 🛠️ Detection Recommendation
Block the entire `173.244.55.128/28` subnet at NSG level. All three attacker IPs (RDP and C2) fall within this range.

**Hunting Tip:** When multiple IPs from the same small subnet appear in an investigation, always block the entire subnet rather than individual IPs.

</details>

---

<details>
<summary id="-flag-23--first-notable-process">🚩 <strong>Flag 23: First Notable Process</strong></summary>

### 🎯 Objective
Identify the first process executed after the successful Uruguay logon that indicates purposeful human interaction.

### 📌 Finding
**`notepad.exe`** — launched at 2025-12-11 23:08:41 UTC by `explorer.exe`, opening `Notes 12122025.txt` in the PHTG documents folder.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azwks-phtg-02 |
| Timestamp | 2025-12-11 23:08:41 UTC |
| Process | notepad.exe |
| Parent Process | explorer.exe |
| Command Line | "NOTEPAD.EXE" C:\Users\vmAdminUsername\Documents\PHTG\Notes 12122025.txt |
| Account | vmadminusername |

### 💡 Why it matters
A human opening Notepad from Explorer is a clear indicator of interactive operator activity. All preceding processes were automated session startup noise. The file opened was created on the HealthCloud rollout date — suggesting the attacker was reading internal documentation about the new service to understand the environment.

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where TimeGenerated >= datetime(2025-12-12T00:47:45Z)
| where DeviceName == "azwks-phtg-02"
| where AccountName == "vmadminusername"
| where FileName !in ("TSTheme.exe","userinit.exe","dllhost.exe","StartMenuExperienceHost.exe",
    "SearchApp.exe","backgroundTaskHost.exe","mobsync.exe","smartscreen.exe",
    "wlrmdr.exe","SecurityHealthSystray.exe","msedge.exe","OneDrive.exe",
    "M365Copilot.exe","msedgewebview2.exe","svchost.exe","conhost.exe",
    "RuntimeBroker.exe","taskhostw.exe","sihost.exe","explorer.exe",
    "ctfmon.exe","rdpclip.exe","rdpinput.exe","fontdrvhost.exe")
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated asc
```

### 🖼️ Screenshot
*notepad.exe confirmed as first interactive process post-logon*

### 🛠️ Detection Recommendation
Alert on text editors opening files in sensitive directories during off-hours or from sessions originating from anomalous geographic locations.

**Hunting Tip:** Filtering session startup noise from `DeviceProcessEvents` requires a maintained exclusion list of known-good session init processes. Build and refine this list as part of your hunt playbooks.

</details>

---

<details>
<summary id="-flag-24--sensitive-text-file">🚩 <strong>Flag 24: Sensitive Text File</strong></summary>

### 🎯 Objective
Identify which text file accessed during the attacker's session contains internal security-relevant content.

### 📌 Finding
**`notes_sarah.txt`** — a file brought onto the machine by the attacker containing operational notes. The filename directly links to the attacker's identity and would contain reconnaissance findings, planned steps, and potentially discovered credentials.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azwks-phtg-02 |
| Timestamp | 2025-12-11 23:15:56 UTC |
| File | notes_sarah.txt |
| Path | C:\Users\vmAdminUsername\Documents\PHTG\notes_sarah.txt |
| Action | FileModified via notepad.exe |

### 💡 Why it matters
An attacker's operational notes are both an IOC and an intelligence source. Reviewing this file's contents could reveal the full scope of the attacker's knowledge about PHTG's environment, planned next steps, and other targets.

### 🔧 KQL Query Used
```kql
DeviceFileEvents
| where TimeGenerated >= datetime(2025-12-12T00:47:45Z)
| where DeviceName == "azwks-phtg-02"
| where InitiatingProcessFileName == "notepad.exe"
| project TimeGenerated, FileName, FolderPath, ActionType, InitiatingProcessAccountName
| order by TimeGenerated asc
```

### 🖼️ Screenshot
*notes_sarah.txt identified as attacker-created file*

### 🛠️ Detection Recommendation
Alert on file creation or modification in user document directories during sessions from anomalous source IPs. Personal name patterns in corporate directories warrant immediate investigation.

**Hunting Tip:** `DeviceFileEvents` filtered by `InitiatingProcessFileName == "notepad.exe"` is a fast way to enumerate all files an attacker read or modified during an interactive session.

</details>

---

<details>
<summary id="-flag-25--first-executable-form">🚩 <strong>Flag 25: First Executable Form</strong></summary>

### 🎯 Objective
Identify the first filename where a rename event turned the payload into a Windows executable.

### 📌 Finding
**`Sarah_Chen_Notes.exe`** — renamed from `Sarah_Chen_Notes.exe.Txt` on 2025-12-12 09:18:38 AM, at `C:\Users\vmAdminUsername\Documents\PHTG\`. This is the first time the payload had an executable extension.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azwks-phtg-02 |
| Timestamp | 2025-12-12 09:18:38 UTC |
| Previous Name | Sarah_Chen_Notes.exe.Txt |
| New Name | Sarah_Chen_Notes.exe |
| Path | C:\Users\vmAdminUsername\Documents\PHTG\ |
| Account | vmadminusername |

### 💡 Why it matters
This rename event transforms the payload from an apparent text file into an executable. It marks the transition from file delivery to weaponization and is the first moment the file could be executed on the system.

### 🔧 KQL Query Used
```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where DeviceName == "azwks-phtg-02"
| where ActionType == "FileRenamed"
| where FileName endswith ".exe" or FileName endswith ".bat" or FileName endswith ".ps1"
| project TimeGenerated, FileName, PreviousFileName, FolderPath, InitiatingProcessAccountName
| order by TimeGenerated asc
```

### 🖼️ Screenshot
*Sarah_Chen_Notes.exe confirmed as first executable form*

### 🛠️ Detection Recommendation
Alert on `FileRenamed` events where the new filename has an executable extension (`.exe`, `.bat`, `.ps1`) and the previous filename had a non-executable extension. This pattern is a strong indicator of double-extension evasion.

**Hunting Tip:** Monitor `DeviceFileEvents` for `ActionType == "FileRenamed"` where `FileName endswith ".exe"` and `PreviousFileName` does not — these rename chains are reliable indicators of payload staging.

</details>

---

<details>
<summary id="-flag-26--double-extension-evasion">🚩 <strong>Flag 26: Double-Extension Evasion</strong></summary>

### 🎯 Objective
Identify the filename used between initial delivery and executable form that contains two extensions.

### 📌 Finding
**`Sarah_Chen_Notes.exe.Txt`** — the payload arrived with a double extension. Windows hides known file extensions by default, so users would see `Sarah_Chen_Notes.exe` and assume it's an executable — while the actual extension making it appear safe to security tools was `.Txt`.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azwks-phtg-02 |
| Double-Extension Filename | Sarah_Chen_Notes.exe.Txt |
| Download URL | https://unresuscitating-donnette-smothery.ngrok-free.app/Sarah_Chen_Notes.Txt |
| Defender Detection | Trojan:Win32/Meterpreter detected even in .Txt form |
| Evasion Goal | Bypass extension-based filtering; appear as text file |

### 💡 Why it matters
The double-extension technique is a classic social engineering and AV evasion method. By naming the file `Sarah_Chen_Notes.exe.Txt`, the attacker makes it appear to be a text file to casual inspection while the embedded `.exe` in the name may cause confusion in some security tools. Defender still detected it, but the technique is designed to bypass simpler controls.

### 🔧 KQL Query Used
```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where DeviceName == "azwks-phtg-02"
| where ActionType == "FileRenamed"
| where PreviousFileName has ".exe.Txt" or FileName has ".exe.Txt"
| project TimeGenerated, FileName, PreviousFileName, FolderPath
```

### 🖼️ Screenshot
*Sarah_Chen_Notes.exe.Txt confirmed as double-extension filename*

### 🛠️ Detection Recommendation
Enable file extension visibility across all endpoints (disable "Hide extensions for known file types" in Windows Explorer). Alert on any file with a double extension pattern (`*.exe.txt`, `*.bat.txt`) being created or downloaded.

**Hunting Tip:** Search `DeviceFileEvents` for filenames containing two periods with an executable extension before a benign extension — this pattern is rare in legitimate environments and almost always indicates evasion.

</details>

---

<details>
<summary id="-flag-27--file-sha256">🚩 <strong>Flag 27: File SHA256</strong></summary>

### 🎯 Objective
Identify the SHA256 hash of the payload file — the immutable identifier that persists across all renames.

### 📌 Finding
SHA256: **`224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695`**

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azwks-phtg-02 |
| SHA256 | 224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695 |
| Associated Files | Sarah_Chen_Notes.exe.Txt → Sarah_Chen_Notes.exe → PHTG.exe |
| Classification | Trojan:Win32/Meterpreter |

### 💡 Why it matters
File names can be changed — hashes cannot. The SHA256 is the definitive identifier for this payload across all rename events, locations, and systems. It can be used to hunt for the same file across the entire environment and submitted to threat intelligence platforms for enrichment.

### 🔧 KQL Query Used
```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where DeviceName == "azwks-phtg-02"
| where FileName == "Sarah_Chen_Notes.exe"
| project TimeGenerated, FileName, FolderPath, SHA256, ActionType
| order by TimeGenerated asc
```

### 🖼️ Screenshot
*SHA256 confirmed: 224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695*

### 🛠️ Detection Recommendation
Add this SHA256 to Microsoft Defender custom indicators as a block. Search all other endpoints in the environment for any file matching this hash.

**Hunting Tip:** Always pivot from filename to SHA256 as early as possible in a file-based investigation — it enables tracking across renames and provides a reliable IOC for environment-wide hunting.

</details>

---

<details>
<summary id="-flag-28--final-file-name">🚩 <strong>Flag 28: Final File Name</strong></summary>

### 🎯 Objective
Track the payload forward through all rename events to identify its final observed filename.

### 📌 Finding
**`PHTG.exe`** — the payload was ultimately renamed to blend in with legitimate HealthCloud service files at `C:\ProgramData\PHTG\HealthCloud\PHTG.exe`.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azwks-phtg-02 |
| Final Filename | PHTG.exe |
| Final Path | C:\ProgramData\PHTG\HealthCloud\PHTG.exe |
| Timestamp | 2025-12-13 05:16:22 UTC |
| Previous Name | Sarah_Chen_Notes.exe |

### 💡 Why it matters
Renaming the payload to `PHTG.exe` and placing it in the HealthCloud service directory is a sophisticated masquerading technique. Any SOC analyst reviewing running processes would see `PHTG.exe` in a `PHTG\HealthCloud` directory and likely dismiss it as a legitimate service binary.

### 🔧 KQL Query Used
```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where DeviceName == "azwks-phtg-02"
| where SHA256 == "224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695"
| project TimeGenerated, FileName, PreviousFileName, FolderPath, ActionType
| order by TimeGenerated asc
```

### 🖼️ Screenshot
*PHTG.exe confirmed as final filename at HealthCloud path*

### 🛠️ Detection Recommendation
Maintain a file integrity baseline for all service directories. Any new executable appearing in `C:\ProgramData\PHTG\HealthCloud\` that was not part of the original deployment should trigger an alert.

**Hunting Tip:** Track SHA256 hashes forward through `FileRenamed` events to reconstruct the complete rename chain — this reveals the attacker's full staging and masquerading strategy.

</details>

---

<details>
<summary id="-flag-29--file-classification">🚩 <strong>Flag 29: File Classification</strong></summary>

### 🎯 Objective
Determine the malware family classification assigned by Microsoft Defender's detection engine.

### 📌 Finding
**Meterpreter** — Microsoft Defender classified the payload as `Trojan:Win32/Meterpreter.gen!E` and `Trojan:Win32/Meterpreter.RPZ!MTB`. Defender quarantined the file three times before the attacker switched it to Passive Mode.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azwks-phtg-02 |
| Malware Family | Meterpreter |
| Full Classifications | Trojan:Win32/Meterpreter.gen!E, Trojan:Win32/Meterpreter.RPZ!MTB |
| Quarantine Events | 3 (between 14:11–14:17 on Dec 12) |
| Download URL | https://unresuscitating-donnette-smothery.ngrok-free.app/Sarah_Chen_Notes.Txt |

### 💡 Why it matters
Meterpreter is one of the most capable post-exploitation frameworks available — part of the Metasploit toolkit. It provides the attacker with full interactive shell access, file system control, keylogging, screenshot capability, and pivoting. Its detection at the quarantine stage shows Defender was working correctly before being disabled.

### 🔧 KQL Query Used
```kql
DeviceEvents
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where DeviceName == "azwks-phtg-02"
| where ActionType has "AntivirusDetection"
| where SHA256 == "224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695"
| project TimeGenerated, ActionType, SHA256, AdditionalFields
| order by TimeGenerated asc
```

### 🖼️ Screenshot
*Trojan:Win32/Meterpreter classifications confirmed in AdditionalFields*

### 🛠️ Detection Recommendation
Configure alerts for any Meterpreter detection regardless of Defender's operating mode. The detection itself — even in passive mode — should trigger an immediate incident response workflow.

**Hunting Tip:** Always parse the `AdditionalFields` JSON in `DeviceEvents` for antivirus detections — it contains the full threat name, description, and report source which are essential for classification and response prioritization.

</details>

---

<details>
<summary id="-flag-30--why-did-it-run">🚩 <strong>Flag 30: Why Did It Run</strong></summary>

### 🎯 Objective
Determine what change to Defender's operating state allowed the payload to execute after being quarantined three times.

### 📌 Finding
**Passive Mode** — the attacker switched Microsoft Defender from Active Mode to Passive Mode. In this state Defender still detects and logs threats but no longer quarantines or blocks them.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azwks-phtg-02 |
| Defender State | Passive Mode |
| Evidence | ReportSource: "Windows Defender Antivirus passive mode" |
| Quarantine Events Before | 3 (between 14:11–14:17 Dec 12) |
| Result | Payload executed without block after mode change |

### 💡 Why it matters
Switching Defender to Passive Mode is achievable via registry modification and is a documented attacker technique. In Passive Mode, Defender becomes a logging-only tool — it sees the threat but is powerless to stop it. This is a critical defensive gap that should be immediately detectable.

### 🔧 KQL Query Used
```kql
DeviceEvents
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where DeviceName == "azwks-phtg-02"
| where ActionType has "AntivirusDetection"
| where SHA256 == "224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695"
| project TimeGenerated, ActionType, AdditionalFields
-- Look for ReportSource containing "passive mode"
```

### 🖼️ Screenshot
*"Windows Defender Antivirus passive mode" confirmed in ReportSource field*

### 🛠️ Detection Recommendation
Enable Microsoft Defender Tamper Protection to prevent unauthorized mode changes. Alert immediately on registry modifications to `HKLM\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection` — specifically `ForceDefenderPassiveMode` being set to `1`.

**Hunting Tip:** The `ReportSource` key within the `AdditionalFields` JSON in `DeviceEvents` reveals whether Defender was in active or passive mode at the time of detection — always check this field when investigating AV detections.

</details>

---

<details>
<summary id="-flag-31--first-execution">🚩 <strong>Flag 31: First Execution</strong></summary>

### 🎯 Objective
Identify the filename under which the payload executed during the first phase of execution.

### 📌 Finding
**`Sarah_Chen_Notes.exe`** — the payload first executed under its original name in `C:\Users\vmAdminUsername\Documents\PHTG\` before being relocated and renamed for persistent execution.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azwks-phtg-02 |
| First Execution Filename | Sarah_Chen_Notes.exe |
| Location | C:\Users\vmAdminUsername\Documents\PHTG\ |
| Phase | Initial execution (December 12) |
| Phase 2 Filename | PHTG.exe (December 13, via Launch.bat) |

### 💡 Why it matters
Understanding the two-phase execution pattern is critical for accurate timeline reconstruction. Phase 1 (Sarah_Chen_Notes.exe) was the attacker's initial test/establishment of the C2 channel. Phase 2 (PHTG.exe via Launch.bat) was the persistent, automated execution designed to survive reboots.

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where DeviceName == "azwks-phtg-02"
| where SHA256 == "224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated asc
```

### 🖼️ Screenshot
*Sarah_Chen_Notes.exe confirmed as Phase 1 execution filename*

### 🛠️ Detection Recommendation
Alert on any process execution matching known malicious SHA256 hashes regardless of filename — hash-based detection is rename-resistant.

**Hunting Tip:** Always query `DeviceProcessEvents` by `SHA256` rather than `FileName` when tracking malicious executables — filenames change, hashes don't.

</details>

---

<details>
<summary id="-flag-32--parent-process">🚩 <strong>Flag 32: Parent Process</strong></summary>

### 🎯 Objective
Identify which process initiated the later phase executions of the payload.

### 📌 Finding
**`cmd.exe`** — the later executions of `PHTG.exe` were launched by `cmd.exe` running the `Launch.bat` batch file, enabling automated persistent execution.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azwks-phtg-02 |
| Child Process | PHTG.exe |
| Parent Process | cmd.exe |
| Initiating Command | cmd.exe /c "C:\ProgramData\PHTG\HealthCloud\Launch.bat" |
| Phase | Persistent execution (December 13+) |

### 💡 Why it matters
The shift from interactive execution (Phase 1) to batch-file-initiated execution (Phase 2) represents the attacker establishing persistence. The `cmd.exe` → `Launch.bat` → `PHTG.exe` chain means the malware now executes automatically as part of the legitimate HealthCloud service startup sequence.

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where DeviceName == "azwks-phtg-02"
| where FileName == "PHTG.exe"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

### 🖼️ Screenshot
*cmd.exe confirmed as initiating process for PHTG.exe*

### 🛠️ Detection Recommendation
Alert on `cmd.exe` spawning executables from `C:\ProgramData\` directories — this is an unusual pattern for legitimate service execution and a reliable indicator of batch-based persistence.

**Hunting Tip:** The process tree `cmd.exe → batch file → payload` is a classic persistence pattern. Always review `InitiatingProcessCommandLine` to see what the parent was actually executing.

</details>

---

<details>
<summary id="-flag-33--batch-file-wrapper">🚩 <strong>Flag 33: Batch File Wrapper</strong></summary>

### 🎯 Objective
Identify the full path of the batch file used to wrap and execute the payload in the later phase.

### 📌 Finding
**`C:\ProgramData\PHTG\HealthCloud\Launch.bat`** — the legitimate HealthCloud service batch file that was modified by the attacker to include execution of `PHTG.exe`.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azwks-phtg-02 |
| Batch File Path | C:\ProgramData\PHTG\HealthCloud\Launch.bat |
| Initiating Command | cmd.exe /c "C:\ProgramData\PHTG\HealthCloud\Launch.bat" |
| Modification Time | 2025-12-13 05:19:36 UTC |
| Previous Name | Launch.txt (renamed from text to batch) |

### 💡 Why it matters
`Launch.bat` was originally a legitimate HealthCloud service file that was renamed from `Launch.txt` and modified to include the malicious payload. Every time the HealthCloud service starts — which it was designed to do automatically — `Launch.bat` executes, ensuring the Meterpreter session is re-established even after reboots.

### 🔧 KQL Query Used
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where DeviceName == "azwks-phtg-02"
| where FileName == "PHTG.exe"
| project TimeGenerated, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

### 🖼️ Screenshot
*C:\ProgramData\PHTG\HealthCloud\Launch.bat confirmed in InitiatingProcessCommandLine*

### 🛠️ Detection Recommendation
Implement file integrity monitoring on all service directories. Any modification to `.bat` files in `C:\ProgramData\` should trigger an alert and require change management approval.

**Hunting Tip:** When investigating persistence, always check `DeviceFileEvents` for recent modifications to `.bat`, `.cmd`, and `.ps1` files in service directories — these are common persistence targets.

</details>

---

<details>
<summary id="-flag-34--c2-ip">🚩 <strong>Flag 34: C2 IP</strong></summary>

### 🎯 Objective
Identify the external IP address the compromised device communicated with after payload execution.

### 📌 Finding
**`173.244.55.130`** — the Meterpreter payload beaconed to this IP in the same `/28` subnet as the attacker's RDP IPs, confirming consolidated infrastructure.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azwks-phtg-02 |
| C2 IP | 173.244.55.130 |
| C2 Port | 4444 |
| Country | Uruguay |
| Subnet | 173.244.55.128/28 |
| Initiating Process | PHTG.exe (SHA256: 224462ce...) |

### 💡 Why it matters
The C2 IP being in the same `/28` subnet as the RDP access IPs (`173.244.55.128` and `173.244.55.131`) confirms all attacker infrastructure — initial access, brute force, and C2 — was operated from a single Uruguayan network block. This consolidation is both an operational security failure by the attacker and a gift for defenders — block one subnet, block everything.

### 🔧 KQL Query Used
```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where DeviceName == "azwks-phtg-02"
| where InitiatingProcessSHA256 == "224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695"
| where RemoteIPType == "Public"
| project TimeGenerated, InitiatingProcessFileName, RemoteIP, RemotePort
| order by TimeGenerated asc
```

### 🖼️ Screenshot
*C2 beacon to 173.244.55.130 confirmed*

### 🛠️ Detection Recommendation
Block the entire `173.244.55.128/28` subnet immediately. Add `173.244.55.130` to threat intelligence feeds as a confirmed Meterpreter C2 endpoint.

**Hunting Tip:** Use `InitiatingProcessSHA256` in `DeviceNetworkEvents` to track all network activity by a specific malicious binary — this works even after the file has been renamed or moved.

</details>

---

<details>
<summary id="-flag-35--c2-geography">🚩 <strong>Flag 35: C2 Geography</strong></summary>

### 🎯 Objective
Determine where the C2 infrastructure is geographically located.

### 📌 Finding
**Uruguay, South America** — the entire attacker infrastructure (RDP access IPs and C2 server) is located in Uruguay within the `173.244.55.128/28` subnet.

### 🔍 Evidence

| Field | Value |
|------|-------|
| C2 IP | 173.244.55.130 |
| Country | Uruguay |
| Continent | South America |
| Subnet | 173.244.55.128/28 |
| GeoTable Mapping | network: 173.244.55.128/28, country_iso_code: UY |

### 💡 Why it matters
Geographic attribution of C2 infrastructure is a key element of threat intelligence. Uruguay appearing as both the authentication source and C2 location confirms this is a single, consolidated operation — not a distributed attack using multiple independent infrastructure providers.

### 🔧 KQL Query Used
```kql
-- GeoIP lookup on 173.244.55.130 via GeoTable
-- Confirmed: network 173.244.55.128/28 → UY → Uruguay → South America
```

### 🖼️ Screenshot
*Uruguay, South America confirmed for 173.244.55.128/28 subnet*

### 🛠️ Detection Recommendation
Add Uruguay to geo-blocking rules for all internet-facing services given the complete absence of legitimate business activity with this country.

**Hunting Tip:** When C2 infrastructure shares the same geographic region and subnet as the initial access IPs, it strongly suggests a single actor operating their own infrastructure rather than renting from a bulletproof hosting provider.

</details>

---

<details>
<summary id="-flag-36--c2-remote-port">🚩 <strong>Flag 36: C2 Remote Port</strong></summary>

### 🎯 Objective
Identify the remote port used by the Meterpreter payload for C2 communication.

### 📌 Finding
**Port 4444** — the default Metasploit Meterpreter listener port, used without any custom configuration by the attacker.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azwks-phtg-02 |
| C2 IP | 173.244.55.130 |
| C2 Port | 4444 |
| Significance | Default Metasploit listener port — no operational security applied |

### 💡 Why it matters
Port 4444 is the default Metasploit C2 port and is so well known in the security community that its use is practically a signature of out-of-the-box Metasploit. The attacker's failure to change this default configuration provides an easy detection opportunity and suggests either overconfidence or haste.

### 🔧 KQL Query Used
```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where DeviceName == "azwks-phtg-02"
| where InitiatingProcessSHA256 == "224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695"
| where RemoteIPType == "Public"
| project TimeGenerated, RemoteIP, RemotePort
```

### 🖼️ Screenshot
*Port 4444 confirmed as C2 communication port*

### 🛠️ Detection Recommendation
Block all outbound connections to port 4444 at the firewall level — there is no legitimate business use for this port in most environments. Alert on any outbound connection to non-standard ports from endpoints.

**Hunting Tip:** Maintain a list of known-malicious default tool ports (4444 for Meterpreter, 1337, 31337, 8888, etc.) and alert on any outbound connections to these ports from any endpoint.

</details>

---

<details>
<summary id="-flag-37--repurposed-baseline">🚩 <strong>Flag 37: Repurposed Baseline</strong></summary>

### 🎯 Objective
Identify the legitimate internal service whose infrastructure was repurposed by the attacker for persistence.

### 📌 Finding
**HealthCloud** — PHTG's newly deployed internal endpoint health service, rolled out December 11, 2025. The attacker placed `PHTG.exe` (Meterpreter) inside `C:\ProgramData\PHTG\HealthCloud\` and modified `Launch.bat` to execute it automatically.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | azwks-phtg-02 |
| Legitimate Service | HealthCloud |
| Service Directory | C:\ProgramData\PHTG\HealthCloud\ |
| Payload Placed | PHTG.exe (Meterpreter) |
| Persistence Mechanism | Launch.bat modified to execute PHTG.exe |
| Service Rollout Date | 2025-12-11 (same day as LinkedIn OPSEC failure) |

### 💡 Why it matters
By hiding the payload inside a service directory that was expected to contain executables and batch files, the attacker made detection significantly harder. Analysts reviewing running processes would see `PHTG.exe` in a PHTG-branded HealthCloud directory and likely dismiss it as legitimate. This technique — using the victim's own infrastructure as a hiding place — is known as living off the land persistence and represents a sophisticated, deliberate choice by the attacker.

The timing is also significant: HealthCloud was rolled out the same day the LinkedIn post appeared. The attacker read the internal notes about HealthCloud during the initial access session, understood the service's expected behavior, and then used that knowledge to craft a convincing persistence mechanism.

### 🔧 KQL Query Used
```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where DeviceName == "azwks-phtg-02"
| where FolderPath has "HealthCloud"
| project TimeGenerated, FileName, PreviousFileName, FolderPath, ActionType, SHA256
| order by TimeGenerated asc
```

### 🖼️ Screenshot
*PHTG.exe and modified Launch.bat confirmed in HealthCloud directory*

### 🛠️ Detection Recommendation
Any newly deployed service should have its directory added to file integrity monitoring from day one. Alert on any new executable appearing in a service directory that was not part of the original deployment package. Maintain a cryptographic baseline of all files in `C:\ProgramData\` service directories.

**Hunting Tip:** When a new internal service is deployed, immediately baseline all files in its directory. Any subsequent additions or modifications should generate an alert — especially executables and batch files. New service rollouts are a high-value target window for attackers.

</details>

---

## 🚨 Detection Gaps & Recommendations

### Observed Gaps

- **No NSG restriction on RDP** — Port 3389 was open to `0.0.0.0/0`, allowing global scanning and brute-force from any IP on the internet
- **Weak credential policy** — `vmadminusername` is a predictable account name that brute-force wordlists target by default; no account lockout policy was enforced
- **No MFA on RDP** — A single password was the only barrier to remote access; MFA would have prevented the compromise regardless of credential strength
- **Defender tamper protection disabled** — The attacker was able to switch Defender from Active to Passive Mode without triggering an alert or being blocked
- **No file integrity monitoring on service directories** — A new executable (`PHTG.exe`) was placed in a service directory and `Launch.bat` was modified without triggering any alert
- **No outbound port filtering** — The Meterpreter C2 beacon to port 4444 was not blocked or alerted upon
- **No geo-based Conditional Access** — Authentication from Uruguay succeeded without any additional verification or challenge
- **OPSEC training gap** — Engineering staff were unaware of the risks of posting screenshots of internal infrastructure to social media
- **No new service baseline** — HealthCloud was deployed without a cryptographic file baseline, making unauthorized additions undetectable

### Recommendations

- **Restrict RDP at NSG level** — Allow inbound port 3389 only from known corporate IP ranges or remove public exposure entirely and use Azure Bastion
- **Enforce strong credential naming policies** — Reject generic account names at provisioning time; require complexity and uniqueness for all accounts
- **Implement MFA on all remote access** — Azure AD Conditional Access with MFA should be mandatory for any RDP-capable account
- **Enable Defender Tamper Protection** — Prevent unauthorized changes to Defender's operating mode via Microsoft Defender for Endpoint settings
- **Deploy File Integrity Monitoring** — Alert on new executables or modified batch files in service directories such as `C:\ProgramData\PHTG\HealthCloud\`
- **Block non-standard outbound ports** — Deny outbound traffic on ports like 4444, 1337, 31337 at the firewall/NSG level
- **Implement geo-based Conditional Access** — Block or require step-up authentication for any logon from outside PHTG's US operating region
- **Implement OPSEC training** — Educate all staff on the risks of posting screenshots containing infrastructure details to social media
- **Block the 173.244.55.128/28 subnet** — All attacker infrastructure was consolidated in this Uruguayan range; blocking it removes access from all three identified IPs
- **Baseline all new service deployments** — Establish cryptographic file baselines for every new service directory at deployment time and monitor for deviations

---

## 🧾 Final Assessment

This intrusion represents a complete attack lifecycle executed with professional-grade tooling and deliberate tradecraft. Starting from a single OPSEC failure — a LinkedIn post containing an Azure portal screenshot — the attacker Sarah Chen systematically brute-forced an internet-exposed RDP service, established persistent access through the HealthCloud service baseline, deployed a Meterpreter payload for full remote control, and communicated with C2 infrastructure consolidated within the Uruguayan subnet `173.244.55.128/28`.

The attacker demonstrated above-average sophistication: using double-extension evasion to bypass casual inspection, switching Defender to Passive Mode to defeat quarantine, masquerading the payload as a legitimate HealthCloud service file, and leveraging the victim's own service infrastructure for persistence without writing new scheduled tasks or registry keys. However, the use of the default Metasploit port 4444 and the attacker's own name embedded in the payload filename represent operational security failures that provided both detection opportunities and attribution artifacts.

PHTG's defensive posture at the time of the incident was critically insufficient: public RDP exposure, weak credentials, no MFA, disabled endpoint protection, and no file integrity monitoring created a chain of exploitable weaknesses that required no zero-day vulnerabilities or advanced techniques to exploit. The entire intrusion was accomplished using publicly available tools and well-documented techniques — all of which have available detections.

All findings are fully reproducible via the KQL queries documented in this report. All 37 techniques map directly to documented MITRE ATT&CK procedures. Immediate containment actions should include: isolating `azwks-phtg-02`, resetting all credentials on the device, blocking the `173.244.55.128/28` subnet, removing `PHTG.exe` and restoring `Launch.bat` to its original state, and re-enabling Defender in Active Mode with Tamper Protection enabled.

**Risk Rating: CRITICAL** — Active persistent C2 access established. Full incident response engagement required.

---

## 📎 Analyst Notes

- Report structured for interview and portfolio review
- Evidence reproducible via advanced hunting in Microsoft Sentinel (`law-cyber-range` workspace)
- All 37 flags mapped directly to MITRE ATT&CK framework
- Hunt conducted December 9–23, 2025 UTC
- Attacker attributed to **Sarah Chen** based on device hostname artifacts (`sarah-che`, `sarah-cheη`) and payload naming convention (`Sarah_Chen_Notes.exe`)
- Full attacker infrastructure confined to subnet `173.244.55.128/28` (Uruguay, South America)

**Key IOCs:**

| Type | Value |
|------|-------|
| IP (RDP) | 173.244.55.131 |
| IP (RDP) | 173.244.55.128 |
| IP (C2) | 173.244.55.130 |
| Subnet | 173.244.55.128/28 |
| SHA256 | 224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695 |
| URL | https://unresuscitating-donnette-smothery.ngrok-free.app/ |
| Malware | Trojan:Win32/Meterpreter.gen!E |
| Account | vmadminusername |
| C2 Port | 4444 |
| Persistence | C:\ProgramData\PHTG\HealthCloud\Launch.bat |
| Payload | C:\ProgramData\PHTG\HealthCloud\PHTG.exe |
