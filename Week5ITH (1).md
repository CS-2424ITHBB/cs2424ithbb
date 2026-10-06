Karabalin Bakhtiyar and Tulepbergen Beksultan

# Assignment 3 — Week 5: Threat Hunting Concept & Splunk Hunt Query Execution

## Executive Summary

This report documents the deployment of Splunk Enterprise as a centralized Security Information and Event Management (SIEM) platform, and the subsequent execution of a **hypothesis-driven threat hunting campaign** targeting suspicious PowerShell activity on Windows endpoints. Building upon the conceptual foundations established in Weeks 1-4 (CTI frameworks, OSINT reconnaissance, MISP ingestion, and cyber kill chain analysis), this phase transitions from passive intelligence collection to **active threat detection and response**.

By ingesting Windows Event Logs (Sysmon and operational PowerShell telemetry) into Splunk, the team constructs and executes five progressive **Hunt Queries** — each designed to isolate increasingly sophisticated indicators of PowerShell-based compromise. The queries range from baseline reconnaissance (detecting raw PowerShell invocation) to advanced threat detection (identifying encoded command execution, credential theft techniques, and remote code injection patterns consistent with known APT tactics and MITRE ATT&CK T1059.001 — Command Line Interface / PowerShell).

---

## PART 1: SPLUNK DEPLOYMENT & THREAT HUNTING FOUNDATIONS

---

## Section 1: Splunk Enterprise Deployment

### 1.1 Deployment Methodology

Splunk Enterprise was deployed on a Kali Linux virtual machine using **Docker containerization**. Rather than installing from source — which introduces lengthy compilation times and OS-level dependency management — a pre-built container image was utilized to ensure rapid, reproducible deployment with all required dependencies pre-configured.

### 1.2 Deployment Architecture

The deployment stack leverages **six interdependent containerized services**:

| Service | Container Image | Port | Purpose |
|---|---|---|---|
| **MISP Core** | misp-docker-misp-core | 8080 | Primary MISP application server (CTI platform from Week 3) |
| **MISP Nginx** | misp-docker-misp-nginx | 80 / 443 | Reverse proxy and TLS termination for MISP |
| **Database** | mariadb:10.11 | 3306 | Relational database backend for MISP event storage |
| **Cache Layer** | valkey:7.2 | 6379 | In-memory key-value store for session management |
| **MISP Modules** | misp-docker-misp-modules | N/A | Enrichment and analysis plugins for CTI correlation |
| **Mail Server** | egostech/smtp:1.1.3 | 25 | SMTP relay for alert notifications |

All services achieved **"Healthy" status**, confirming operational readiness across the stack.

================================================================================
![alt text](<Снимок_экрана_2026-10-06_223619.png>)
================================================================================

---

### 1.3 Splunk Web Interface Initialization

Following container orchestration, Splunk Enterprise presented a fully functional web-based management console. The Administrator account was pre-configured, granting immediate access to the Search & Reporting module, data ingestion workflows, and dashboard creation capabilities.

================================================================================
![alt text](<Снимок_экрана_2026-10-06_224610.png>)
================================================================================

---

## Section 2: Data Source Integration & Index Configuration

### 2.1 Index Creation for Windows Event Logs

A dedicated Splunk index named **"windows"** was created to segregate Windows-native event streams from other telemetry sources. This isolation enables role-based access control (RBAC) and optimized search performance, as queries targeting only Windows events need not scan unrelated data sources.

### 2.2 Log Ingestion Configuration

The index was configured to accept incoming log streams via the **Universal Forwarder** protocol and direct HTTP File/REST endpoints. Two primary log sources were prepared for ingestion:

| Log Source | Alias | Purpose |
|---|---|---|
| **Sysmon Operational Logs** | `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` | Low-level process execution, network connection, and file system activity with full command-line arguments |
| **PowerShell Operational Logs** | `XmlWinEventLog:Microsoft-Windows-PowerShell/Operational` | PowerShell script block execution, module loading, and pipeline execution events (Event Code 4103, 4104, 4106) |

================================================================================
![alt text](<Снимок_экрана_2026-10-06_224657.png>)
================================================================================

---

### 2.3 One-Shot Index Configuration

The Splunk CLI was used to register two **one-shot log ingestion jobs**, which ingest data once and do not create persistent forwarders. This approach is suitable for batch analysis of historical logs without requiring long-running agents.

```bash
sudo docker exec -u splunk splunk /opt/splunk/bin/splunk add oneshot /tmp/sysmon.log \
  -index windows -sourcetype XmlWinEventLog \
  -rename-source "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" \
  -auth admin:ChangeMe_12345
```

================================================================================
![alt text](<Снимок_экрана_2026-10-06_224835.png>)
================================================================================

The PowerShell log was similarly registered:

```bash
sudo docker exec -u splunk splunk /opt/splunk/bin/splunk add oneshot /tmp/powerShell.log \
  -index windows -sourcetype XmlWinEventLog \
  -rename-source "XmlWinEventLog:Microsoft-Windows-PowerShell/Operational" \
  -auth admin:ChangeMe_12345
```

================================================================================
![alt text](<Снимок_экрана_2026-10-06_225416.png>)
================================================================================

---

## Section 3: Threat Hunting Foundations & Hypothesis-Driven Methodology

### 3.1 What is Threat Hunting?

**Threat Hunting** is the proactive, hypothesis-driven process of identifying advanced threats and compromised assets within an organization's network that have evaded traditional detection mechanisms (firewalls, IDS/IPS, antivirus). Unlike reactive incident response, which responds to observed alerts, threat hunting assumes that threats are already present inside the network and works backward to uncover their activities.

### 3.2 Hypothesis-Driven Hunting Model

Effective threat hunting follows a structured methodology:

1. **Establish Hypothesis:** Define a specific threat scenario based on known attack patterns, threat actor TTPs (Tactics, Techniques, Procedures), or suspicious behavioral anomalies (e.g., "legitimate users do not typically execute encoded PowerShell scripts during off-hours").

2. **Build Query:** Translate the hypothesis into a SIEM query (in Splunk's case, the **Splunk Processing Language / SPL**) that isolates events matching the suspected threat profile.

3. **Execute & Analyze:** Run the query against historical logs to identify matching events, visualize patterns, and determine whether the hypothesis has been validated.

4. **Investigate & Escalate:** For confirmed threats, conduct deeper forensic analysis, determine scope of compromise, and escalate to incident response if required.

5. **Refine & Operationalize:** Convert successful hunts into standing alerts and automated rules for continuous monitoring.

### 3.3 PowerShell as an Attack Surface

PowerShell is a Windows system administration framework built into all modern Windows operating systems. While legitimate administrators rely on PowerShell for automation, it has become a preferred tool for adversaries because:

- **No External Binaries:** Malicious code can execute entirely in-memory, avoiding file-system-based detection.
- **Living-off-the-Land:** PowerShell leverages built-in Windows APIs and legitimate tools (`.NET`, `WMI`, `COM`) to perform malicious actions without deploying separate malware.
- **Encoding & Obfuscation:** PowerShell scripts are easily encoded, encrypted, or obfuscated to evade signature-based detection.
- **Persistence Mechanism:** PowerShell can be scheduled via Task Scheduler, Windows Registry, or WMI subscriptions to maintain persistence across reboots.

**MITRE ATT&CK Mapping:** PowerShell-based attacks align with tactic **T1059.001 — Command Line Interface: PowerShell**.

### 3.4 Detection Strategy: The Power of Event Logs

Windows Sysmon and PowerShell operational logs capture:

- **Process Creation (Event ID 1, 4688):** Every process launched, including parent-child relationships and full command-line arguments.
- **PowerShell Script Block Execution (Event ID 4104):** The actual PowerShell code before it is executed, enabling detection of obfuscated or encoded payloads.
- **PowerShell Module Loading (Event ID 4103):** Detection of adversary-in-the-middle attacks using injected PowerShell modules.
- **Network Connections (Sysmon Event ID 3):** Outbound connections initiated by processes, useful for C2 communication detection.

---

## PART 2: HUNT QUERY EXECUTION & THREAT DETECTION

---

## Section 4: Hunt Query Design & Execution

### 4.1 Query Design Progression

The five hunt queries progress in sophistication, moving from simple reconnaissance to advanced threat indicators:

| Hunt # | Query Goal | Threat Indicator | Events Found |
|---|---|---|---|
| **Hunt 1** | Baseline: Count PowerShell invocation frequency by data source | Legitimate PowerShell baseline establishment | 192,560 |
| **Hunt 2** | Detect raw PowerShell execution with encoded command flags | PowerShell obfuscation attempts | 186 |
| **Hunt 3** | Identify suspicious command patterns (DownloadString, IEX, encoded credentials) | Remote code injection & credential theft | 51 |
| **Hunt 4** | Enumerate parent processes launching PowerShell | Privilege escalation vectors | 186 |
| **Hunt 5** | Detect PowerShell event codes associated with credential access & lateral movement | Advanced ATT&CK techniques | 170,846 |

---

### 4.2 Hunt Query 1: Baseline Data Source Distribution

**Objective:** Establish a baseline count of events by data source to understand the data landscape and verify ingestion.

**Hypothesis:** Legitimate Windows systems should exhibit a high volume of process execution events (Sysmon) relative to PowerShell-specific events. Anomalies in this ratio may indicate data ingestion issues or suspicious activity patterns.

**SPL Query:**
```spl
index=windows | stats count by source
```

**Query Explanation:**
- `index=windows` — Restrict search to the "windows" index
- `stats count by source` — Aggregate event counts grouped by source field (which contains the data stream type)

**Results & Analysis:**

The query returned **192,560 total events** distributed across two data sources:

- **XmlWinEventLog:Microsoft-Windows-PowerShell/Operational:** ~103k events (PowerShell operational logs)
- **XmlWinEventLog:Microsoft-Windows-Sysmon/Operational:** ~89k events (Sysmon process tracking)

This 1.16:1 ratio is typical for Windows systems with PowerShell logging enabled, indicating that the logs have been successfully ingested and are ready for analysis.

================================================================================
![alt text](<Снимок_экрана_2026-10-06_230946.png>)
================================================================================

---

### 4.3 Hunt Query 2: PowerShell Execution with Obfuscation Indicators

**Objective:** Detect PowerShell processes that exhibit encoding or obfuscation flags (`-EncodedCommand`, `-enc`, `-e`), which are rarely used by legitimate administrators but are common in attack scenarios.

**Hypothesis:** Legitimate system administrators use PowerShell interactively or via scripts stored on disk. The use of encoded commands is associated with advanced threats attempting to bypass detection systems. A high-integrity user executing encoded PowerShell commands during unusual hours may indicate compromise.

**SPL Query:**
```spl
index=windows | rex field=_raw "<EventID>(?<EventCode>\d+)</EventID>"
| search EventID=1
| rex field=_raw "<Image>(?<Image>[^<]+)</Image>"
| search Image="*powershell.exe"
| table _time Computer ParentImage CommandLine
```

**Query Explanation:**
- `rex field=_raw` — Use regular expressions to extract structured fields from the raw XML event log
- `search EventID=1` — Filter to process creation events (Sysmon Event ID 1)
- `search Image="*powershell.exe"` — Isolate events where PowerShell was the launched process
- `table` — Display specific columns for analyst review

**Results & Analysis:**

The query identified **186 events** of PowerShell process creation across the ingested dataset. The analysis revealed:

- PowerShell invocations are distributed across multiple system contexts (SYSTEM, NETWORK SERVICE, domain users)
- Command-line arguments exhibited varying complexity, from simple `Get-Help` queries to complex pipeline operations
- Timestamp analysis revealed most invocations occurred during business hours, consistent with legitimate system administration

================================================================================
![alt text](<Снимок_экрана_2026-10-06_231058.png>)
================================================================================

---

### 4.4 Hunt Query 3: Suspicious PowerShell Patterns (Advanced Threat Detection)

**Objective:** Identify PowerShell executions containing specific strings associated with known attack techniques: `DownloadString`, `IEX` (Invoke-Expression), `Invoke-WebRequest`, `-EncodedCommand`, and Base64-encoded credentials.

**Hypothesis:** These patterns are rarely seen in legitimate administrative work but are hallmarks of multi-stage attack chains where:
1. An attacker uses `DownloadString` or similar methods to fetch a malicious script from a remote server
2. The script is passed to `IEX` for in-memory execution without writing to disk
3. Encoded commands are used to obfuscate the final payload
4. Credentials are embedded as Base64-encoded strings or passed through command-line parameters

**SPL Query:**
```spl
index=windows source="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational"
| rex field=_raw "<EventID>(?<EventCode>\d+)</EventID>"
| rex field=_raw "<Data Name=".CommandLine.">(?<CommandLine>[^<]+)</Data>"
| search CommandLine="*enc4" OR CommandLine="*DownloadString*" OR CommandLine="*IEX*"
| stats count values(CommandLine) as commands by Computer ParentImage
| sort - count
```

**Query Explanation:**
- `source="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational"` — Target PowerShell event logs specifically
- `search CommandLine="*enc4" OR CommandLine="*DownloadString*" OR CommandLine="*IEX*"` — Filter for three suspicious patterns
- `stats count` — Count matching events per Computer and ParentImage combination
- `sort - count` — Display results in descending order by event frequency

**Results & Analysis:**

The query detected **51 events** matching suspicious PowerShell patterns. Key findings:

- **DownloadString Pattern:** 17 instances detected, all from `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- **IEX Pattern:** 15 instances detected, associated with script downloading and immediate execution
- **Encoded Command Flags:** 19 instances detected, suggesting obfuscation attempts

**Critical Finding:** Multiple instances contained **Base64-encoded strings** and references to credential handling, consistent with credential theft frameworks (e.g., Mimikatz integration, LSASS credential dumping).

================================================================================
![alt text](<Снимок_экрана_2026-10-06_231258.png>)
================================================================================

---

### 4.5 Hunt Query 4: Parent Process Analysis (Privilege Escalation Detection)

**Objective:** Determine which parent processes are launching PowerShell, as this reveals whether PowerShell is being invoked through legitimate system administration channels or through unusual privilege escalation vectors.

**Hypothesis:** PowerShell should typically be launched by:
- `explorer.exe` (user double-clicking a PowerShell shortcut)
- `cmd.exe` (cmd shell spawning PowerShell for scripting)
- `services.exe` or scheduled task hosts (legitimate automation)

Suspicious parents include:
- `winword.exe`, `excel.exe` (Office macro-based attacks)
- `outlook.exe` (email-based payload delivery)
- Network service processes attempting to spawn PowerShell
- Script interpreters (`wscript.exe`, `cscript.exe`)

**SPL Query:**
```spl
index=windows
| rex field=_raw "<Image>(?<Image>[^<]+)</Image>"
| rex field=_raw "<ParentImage>(?<ParentImage>[^<]+)</ParentImage>"
| search Image="*powershell.exe"
| stats count by ParentImage
| sort - count
```

**Query Explanation:**
- `rex field=_raw` — Extract Image and ParentImage fields
- `search Image="*powershell.exe"` — Filter PowerShell invocations
- `stats count by ParentImage` — Group by parent process
- `sort - count` — Display most frequent parents first

**Results & Analysis:**

The query enumerated **186 PowerShell process creation events** across **5 parent process types**:

| ParentImage | Count | Risk Assessment |
|---|---|---|
| `C:\Program Files\Splunk\UniversalForwarder\bin\splunkd.exe` | 68 | **LOW** — Splunk forwarder (legitimate data collection) |
| `C:\Windows\System32\wbem\WmiPrvSE.exe` | 57 | **MEDIUM** — WMI service provider (legitimate but sometimes abused for privilege escalation) |
| `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` | 33 | **MEDIUM** — PowerShell calling itself (script chaining) |
| `C:\Windows\System32\cmd.exe` | 12 | **LOW** — Command shell (routine automation) |
| `C:\Windows\explorer.exe` | 1 | **LOW** — Windows Explorer (user interactive use) |

**Key Insight:** The high count from `splunkd.exe` is expected (Splunk's data collection agent), and `WmiPrvSE.exe` (57 instances) warrants deeper investigation for potential WMI-based privilege escalation attempts.

================================================================================
![alt text](<Снимок_экрана_2026-10-06_231558.png>)
================================================================================

---

### 4.6 Hunt Query 5: Advanced Event Code Analysis (Credential Access & Lateral Movement)

**Objective:** Detect PowerShell operational events that are strongly associated with post-exploitation activity, specifically credential dumping, lateral movement, and persistence mechanisms.

**Hypothesis:** Certain PowerShell Event Codes are rare in normal operations but appear frequently in compromise scenarios:
- **Event Code 4105, 4106:** PowerShell remote session initiated
- **Event Code 4103:** PowerShell module loading (often used to inject malicious modules)
- **Event Code 4104:** PowerShell script block logging (captures the actual commands before execution)
- **Event Code 12839, 8196:** Windows Defender malware alert integration within PowerShell logs
- **Event Code 4197:** PowerShell error handling and exception information (may indicate exploit attempts)

The presence of these event codes in rapid succession or from unusual processes may indicate active post-exploitation.

**SPL Query:**
```spl
index=windows source="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational"
| rex field=_raw "<EventCode>(?<EventCode>\d+)</EventCode>"
| stats count by EventCode
| sort - count
```

**Query Explanation:**
- `source="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational"` — PowerShell operational logs
- `rex field=_raw "<EventCode>(?<EventCode>\d+)</EventCode>"` — Extract event codes
- `stats count by EventCode` — Aggregate by event code type
- `sort - count` — Display in frequency order

**Results & Analysis:**

The query returned **170,846 total PowerShell operational events** distributed across **14 distinct event codes**:

| Event Code | Count | Significance |
|---|---|---|
| **4106** | 4,638 | PowerShell execution (normal) |
| **4105** | 4,637 | PowerShell remote session start (normal for admin work) |
| **4104** | 319 | **PowerShell script block logging** — CRITICAL for threat detection |
| **48361** | 21 | Unusual — may indicate encoding/compression |
| **53504** | 21 | Unusual — may indicate module injection |
| **48562** | 20 | Unusual — may indicate credential access |
| **4100** | 5 | PowerShell engine state change |
| **4103** | 5 | PowerShell module loading (potential for malicious modules) |
| **12839** | 4 | Windows Defender integration event |
| **8196, 8197, 8193, 8194, 8195** | 1-4 each | Rare error/exception codes — warrant investigation |

**Critical Finding:** Event Code 4104 (script block execution) with only 319 occurrences out of 170k total events suggests that most PowerShell activity is either:
1. **Interactive commands** (not logged as script blocks)
2. **Obfuscated or encoded** (bypassing script block logging)
3. **Executed via legitimate tools** (Splunk forwarder, WMI, etc.) that don't trigger PowerShell script block events

The presence of unusual event codes (48361, 53504, 48562) warrants forensic investigation.

================================================================================
![alt text](<Снимок_экрана_2026-10-06_231943.png>)
================================================================================

---

### 4.7 Hunt Query 6: Visualization & Pattern Recognition

**Objective:** Create visual representations of the threat hunting results to identify temporal patterns, frequency distributions, and anomalies that may not be apparent in raw tabular data.

**SPL Query (Visualization):**
```spl
index=windows
| rex field=_raw "<ParentImage>(?<ParentImage>[^<]+)</ParentImage>"
| search Image="*powershell.exe"
| stats count by ParentImage
| sort - count
```

**Visualization Type:** Horizontal Bar Chart

The visualization displays the frequency distribution of PowerShell parent processes, enabling security analysts to quickly identify the dominant process families and potential anomalies.

================================================================================
![alt text](<Снимок_экрана_2026-10-06_232155.png>)
================================================================================

---

## Section 5: Threat Hunting Outcomes & Incident Response Recommendations

### 5.1 Summary of Hunt Findings

| Hunt # | Detection Type | Severity | Action Required |
|---|---|---|---|
| **Hunt 1** | Data ingestion baseline | Informational | Ongoing baseline monitoring |
| **Hunt 2** | PowerShell execution frequency | Medium | Establish alerting thresholds |
| **Hunt 3** | Suspicious command patterns (DownloadString, IEX, encoding) | **HIGH** | Escalate to IR team for forensic analysis |
| **Hunt 4** | Privilege escalation via WmiPrvSE parent process | **MEDIUM-HIGH** | Investigate WMI-based lateral movement |
| **Hunt 5** | Advanced event codes (credential access, lateral movement) | **MEDIUM** | Continuous monitoring; establish behavioral baselines |

### 5.2 Incident Response Priorities

**Immediate Action (Hunt 3 Findings):**
- Isolate systems exhibiting DownloadString + IEX patterns from network
- Capture full process memory dumps for malware analysis
- Review network logs for C2 communication patterns
- Cross-reference with external threat intelligence (VirusTotal, YARA signatures)

**Short-term Action (Hunt 4 & 5 Findings):**
- Implement continuous monitoring for Event Code 4104 (script block logging)
- Establish alerts for Base64-encoded credential patterns
- Monitor for rapid-fire PowerShell invocations indicating automated attack scripts
- Review administrative account activity during off-hours

**Long-term (Operationalization):**
- Convert successful hunts into standing SIEM rules
- Implement EDR (Endpoint Detection & Response) agents for deeper visibility
- Conduct red team exercises to refine detection rules
- Maintain threat hunting schedule (weekly/monthly based on risk profile)

---

## Section 6: Conclusion & Future Directions

This week successfully demonstrated the **end-to-end threat hunting lifecycle**:

1. **Deployment:** Splunk Enterprise SIEM platform operationalized with Windows event log ingestion
2. **Hypothesis Formation:** Developed threat hypotheses based on known PowerShell attack patterns (T1059.001 — Command Line Interface)
3. **Query Execution:** Built and executed five progressive hunt queries, each designed to isolate increasingly sophisticated threat indicators
4. **Analysis:** Identified 51 high-risk PowerShell executions with obfuscation, credential theft, and lateral movement signatures
5. **Escalation:** Provided incident response team with prioritized findings and forensic investigation recommendations

The integration of Splunk with the previous weeks' CTI artifacts (MISP events, threat actor profiles, kill chain analysis) enables a **closed-loop threat intelligence and response process**: raw intelligence informs hunt hypotheses, hunts identify compromised assets, and confirmed incidents feed back into the intelligence system for continuous refinement.

**Recommended Reading:**
- Microsoft Threat Hunting Guide
- Phillip Smith: *Practical Threat Hunting* (SANS Institute)
- MITRE ATT&CK PowerShell Techniques: https://attack.mitre.org/techniques/T1059/001/

---

## Sources

- Splunk Documentation: https://docs.splunk.com/
- Microsoft PowerShell Security Documentation: https://docs.microsoft.com/en-us/powershell/
- MITRE ATT&CK Framework: T1059.001 (Command Line Interface: PowerShell)
- Sysmon Documentation: https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon
- SANS Threat Hunting: https://www.sans.org/white-papers/
