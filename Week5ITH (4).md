Karabalin Bakhtiyar and Tulepbergen Beksultan

Executive Summary

This report documents the deployment of Splunk Enterprise and the execution of five hunt queries targeting suspicious PowerShell activity on Windows endpoints. Windows Event Logs (Sysmon and PowerShell operational logs) were ingested into Splunk to detect indicators of PowerShell-based compromise.

---

## Section 1: Splunk Enterprise Deployment

### 1.1 Deployment

Splunk Enterprise was deployed on Kali Linux via Docker. All services achieved **"Healthy" status** and web interface was operational.

![Splunk deployment healthy status](Снимок_экрана_2026-10-06_223619.png)

### 1.2 Web Console

Splunk web console initialized with Administrator access to Search & Reporting module.

![Splunk web console initialization](Снимок_экрана_2026-10-06_224610.png)

---

## Section 2: Data Source Integration

### 2.1 Index Configuration

Splunk index **"windows"** created to ingest Windows event streams:

| Log Source | Purpose |
|---|---|
| **Sysmon Operational Logs** | Process execution, network connections, file system activity |
| **PowerShell Operational Logs** | Script block execution, module loading, pipeline events |

![Index configuration for windows logs](Снимок_экрана_2026-10-06_224657.png)

### 2.2 Log Ingestion

Sysmon and PowerShell logs registered via Splunk CLI.

![Sysmon log ingestion](Снимок_экрана_2026-10-06_224835.png)

![PowerShell log ingestion](Снимок_экрана_2026-10-06_225416.png)

---

## Section 3: Hunt Query Execution

### 3.1 Hunt Query 1: Baseline Data Source Distribution

**Objective:** Baseline event count by data source.

**Results:**

The query returned **192,560 total events** distributed across two sources:
- XmlWinEventLog:Microsoft-Windows-PowerShell/Operational: ~103k events
- XmlWinEventLog:Microsoft-Windows-Sysmon/Operational: ~89k events

![Hunt Query 1 - baseline event distribution](Снимок_экрана_2026-10-06_230946.png)

---

### 3.2 Hunt Query 2: PowerShell Process Execution

**Objective:** Detect PowerShell process creation events.

**Results:**

Identified **186 events** of PowerShell process creation:
- Invocations distributed across SYSTEM, NETWORK SERVICE, and domain user contexts
- Most occurred during business hours

![Hunt Query 2 - PowerShell process execution events](Снимок_экрана_2026-10-06_231058.png)

---

### 3.3 Hunt Query 3: Suspicious PowerShell Patterns

**Objective:** Identify PowerShell executions with `DownloadString`, `IEX`, `-EncodedCommand`, and Base64-encoded credentials.

**Results:**

Detected **51 events** matching suspicious patterns:
- **DownloadString Pattern:** 17 instances
- **IEX Pattern:** 15 instances
- **Encoded Command Flags:** 19 instances

**Critical Finding:** Multiple instances contained **Base64-encoded strings** and credential handling references, consistent with credential theft frameworks (Mimikatz, LSASS dumping).

![Hunt Query 3 - suspicious PowerShell patterns with DownloadString and IEX](Снимок_экрана_2026-10-06_231258.png)

---

### 3.4 Hunt Query 4: Parent Process Analysis

**Objective:** Identify which parent processes launch PowerShell.

**Results:**

Enumerated **186 PowerShell process creation events** across **5 parent process types**:

| ParentImage | Count | Risk |
|---|---|---|
| `splunkd.exe` | 68 | LOW |
| `WmiPrvSE.exe` | 57 | MEDIUM |
| `powershell.exe` | 33 | MEDIUM |
| `cmd.exe` | 12 | LOW |
| `explorer.exe` | 1 | LOW |

**Key Finding:** WmiPrvSE.exe (57 instances) warrants investigation for potential WMI-based privilege escalation.

![Hunt Query 4 - parent process analysis](Снимок_экрана_2026-10-06_231558.png)

---

### 3.5 Hunt Query 5: Advanced Event Code Analysis

**Objective:** Detect PowerShell operational event codes associated with post-exploitation activity.

**Results:**

The query returned **170,846 total PowerShell operational events** across **14 distinct event codes**:

| Event Code | Count | Significance |
|---|---|---|
| **4106** | 4,638 | PowerShell execution (normal) |
| **4105** | 4,637 | PowerShell remote session start (normal) |
| **4104** | 319 | **Script block logging** — CRITICAL |
| **48361, 53504, 48562** | 20-21 each | Unusual — warrant investigation |
| **4103** | 5 | PowerShell module loading |
| **12839** | 4 | Windows Defender integration |

**Critical Finding:** Event Code 4104 (script block execution) appears only 319 times, suggesting most PowerShell activity is either interactive, obfuscated, or executed via legitimate tools. Unusual event codes warrant forensic investigation.

![Hunt Query 5 - advanced event code analysis](Снимок_экрана_2026-10-06_231943.png)

---

### 3.6 Hunt Query 6: Visualization

**Objective:** Visual representation of PowerShell parent process distribution.

**Visualization Type:** Horizontal Bar Chart

![Hunt Query 6 - PowerShell parent process visualization](Снимок_экрана_2026-10-06_232155.png)

---

## Section 4: Conclusions

### 4.1 Hunt Results Summary

| Hunt # | Detection Type | Events | Severity |
|---|---|---|---|
| **Hunt 1** | Data ingestion baseline | 192,560 | Informational |
| **Hunt 2** | PowerShell execution frequency | 186 | Medium |
| **Hunt 3** | Suspicious patterns (DownloadString, IEX, encoding) | **51** | **HIGH** |
| **Hunt 4** | Parent process analysis | 186 | Medium-High |
| **Hunt 5** | Advanced event codes | 170,846 | Medium |

### 4.2 Key Findings

1. **Hunt 3 identified 51 high-risk PowerShell executions** with obfuscation, credential theft, and remote code injection signatures
2. **WmiPrvSE.exe spawning PowerShell (57 instances)** indicates potential WMI-based privilege escalation
3. **Base64-encoded credentials detected** in multiple command-line arguments
4. **Event Code 4104 underrepresentation** (319/170k) suggests obfuscation bypass

---

## Sources

- Splunk Documentation: https://docs.splunk.com/
- Microsoft PowerShell Security: https://docs.microsoft.com/en-us/powershell/
- Sysmon Documentation: https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon
