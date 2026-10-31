# Week 8 — Adversary Emulation Plan with Real-World Confirmations

Original authors: Karabalin Bakhtiyar, Tulepbergen Beksultan

## Simplified Adversary Emulation Plan

**Initial Access → Persistence → Collection and Exfiltration**

**Reference frameworks:** MITRE ATT&CK (Enterprise) + MITRE CALDERA

### 1. Purpose and Scope

A simple attack scenario for a training environment (purple team): the adversary gains initial access to a workstation, establishes persistence on the system, and exfiltrates data. Each step is mapped to a MITRE ATT&CK technique ID, so the plan can later be assembled in CALDERA: abilities → adversary profile → operation.

**Target assumption:** a single Linux (Kali) workstation in an isolated lab, with no access to production networks.

### 2. Stage 1 — Initial Access

| # | Technique | ATT&CK ID | Description |
| --- | --- | --- | --- |
| 1.1 | Phishing: Spearphishing Attachment | **T1566.001** | The user is sent a malicious attachment (e.g., an office document with a macro) that launches a payload when opened |
| 1.2 | Valid Accounts, fallback option | **T1078** | Logging in with previously compromised or weak credentials through a legitimate channel |

**Success criterion:** first code execution / obtaining a shell on the target host.

**Detection indicator:** an unexpected child process spawned by a user application — on Windows this looks like `winword.exe → powershell.exe`; on Linux, an unexpected `bash`/`python3` spawned by a mail client or document viewer.

**Real-world confirmations:**

Both techniques are among the most heavily used in the industry.

- **T1566.001 — Spearphishing Attachment** (MITRE ATT&CK, attack.mitre.org/techniques/T1566/001/):
  - **APT28** (Russia) sent phishing emails with malicious Microsoft Office attachments and RAR archives.
  - **APT29** (Russia, the group behind the SolarWinds attack) used phishing emails with vulnerability-exploiting attachments.
  - **APT33** (Iran) sent phishing emails with archive attachments, targeting the aviation and energy sectors in the US, Saudi Arabia, and South Korea.
  - **FIN7** (a financially motivated group) sent .rtf, .doc, .xls attachments and password-protected archives containing .exe and .scr executables.
- **T1078 — Valid Accounts** (MITRE ATT&CK, attack.mitre.org/techniques/T1078/): the clearest public example is the **Colonial Pipeline attack in May 2021** (the DarkSide ransomware group). The attackers got into the network through an old VPN account whose password had leaked onto the dark web in an unrelated breach; that account did not have multi-factor authentication enabled. Having gained access this way, they established persistence and deployed ransomware, which led to a 6-day shutdown of a pipeline supplying about 45% of the US East Coast's fuel, and a 75 BTC (\~$4.4 million) ransom payment. MITRE ATT&CK classifies this initial access specifically as T1078 (Valid Accounts). Sources: Colonial Pipeline incident-response reporting (Mandiant/FireEye, CISA), and the T1078 technique page in MITRE ATT&CK.

### 3. Stage 2 — Persistence

| # | Technique | ATT&CK ID | Description |
| --- | --- | --- | --- |
| 2.1 | Scheduled Task/Job: Cron | **T1053.003** | Creating a cron job (`crontab -e`) for the current user so a command runs periodically |

**Success criterion:** the implant survives a cron restart / keeps running after the scheduled interval.

**Detection indicator:** a new line in the current user's `crontab -l`; a `cron`/`crond` process spawning a command unrelated to normal system jobs.

**Real-world confirmations:**

MITRE ATT&CK lists numerous confirmed uses of T1053.003 — Cron (attack.mitre.org/techniques/T1053/003/):

- **Rocke** (a cryptomining-focused group) installed a cron job that downloaded and executed files from its C2 server.
- **Kinsing** used crontab to download and run shell scripts every minute to maintain persistence.
- **APT38** used cron to create pre-scheduled and periodic background jobs on Linux systems.
- **Xbash** creates a cron job for persistence when it detects it is running on Linux.

The Windows sibling technique in the same family, **Scheduled Task (T1053.005)**, was used by **Sandworm Team** during the 2022 attack on the Ukrainian power grid: scheduled tasks were pushed via a Group Policy Object (GPO) to launch the CaddyWiper wiper on a schedule. This confirms that scheduled-execution persistence (whichever OS-specific sub-technique is used) is a well-documented, repeatedly observed real-world pattern, not an abstraction invented for this lab.

### 4. Stage 3 — Collection and Exfiltration

| # | Technique | ATT&CK ID | Description |
| --- | --- | --- | --- |
| 3.1 | Data from Local System | **T1005** | Searching for and collecting target files on the host (in the lab — a canary file) |
| 3.2 | Archive Collected Data: Archive via Utility | **T1560.001** | Compressing files (optionally password-protected) before transfer — to reduce size and evade simple DLP rules |
| 3.3 | Application Layer Protocol: Web Protocols | **T1071.001** | A C2 channel (provided by the CALDERA agent — Sandcat) carrying commands and data over HTTP(S) |
| 3.4 | Exfiltration Over C2 Channel | **T1041** | Sending the archive over the already-established C2 channel, with no separate connection |

**Success criterion:** the canary file reaches the lab's "attacker server."

**Detection indicator:** archives created in temporary folders immediately before network activity; an unusual volume of outbound traffic from the host.

**Real-world confirmations:**

- **T1005 — Data from Local System** (attack.mitre.org/techniques/T1005/): a broad technique used by nearly every group during the collection phase — for example, **Cobalt Strike** (used by dozens of threat actors) natively collects data from the local system; **Fox Kitten** deliberately searched the local system for sensitive documents.
- **T1560.001 — Archive via Utility** (attack.mitre.org/techniques/T1560/001/):
  - **APT28** archived collected data with a password using WinRAR.
  - **APT33** used WinRAR to compress data before exfiltration.
  - **HAFNIUM** used 7-Zip and WinRAR to compress stolen files.
  - During the **SolarWinds Compromise**, APT29 compressed stolen emails into password-protected archives using 7-Zip.
- **T1071.001 — Web Protocols** (attack.mitre.org/techniques/T1071/001/):
  - **APT28** (CHOPSTICK-family implants) used a mix of HTTP, HTTPS, and other legitimate channels for command and control.
  - **APT33** used HTTP for command and control.
  - During the **2015 attack on the Ukrainian power grid**, Sandworm Team (BlackEnergy malware) exchanged data with its C2 servers over HTTP POST requests.
- **T1041 — Exfiltration Over C2 Channel** (attack.mitre.org/techniques/T1041/): a clear example is the **SolarWinds (Sunburst/APT29)** attack — stolen data was exfiltrated over the already-established HTTP C2 channel, disguised as legitimate Orion API responses. The technique was also used by Lazarus Group, APT32, APT39, and others.

### 5. Kill Chain Summary

```
T1566.001 (Phishing attachment) / fallback T1078 (Valid Accounts)
        │
        ▼
T1053.003 (Cron job) — Persistence
        │
        ▼
T1005 (Data collection) ──► T1560.001 (Archiving) ──► T1041 (Exfiltration over C2, via T1071.001)
```

### 6. Notes

- **CALDERA:** each technique above becomes one ability: tactic, ATT&CK ID, and a platform-specific command. Abilities are combined into a single adversary profile and run as an operation on a Sandcat agent. In the lab, initial access is simulated by manually launching the agent on the test host.
- **Lab only:** this plan is intended for training in an isolated environment with the owner's permission. It specifies techniques by ATT&CK ID only — no commands or payloads are included.

### 7. Use of Artificial Intelligence

AI was used to structure the plan and to verify the mapping against ATT&CK, and to compile the real-world confirmation examples from MITRE ATT&CK's public procedure-example data. The scenario design and final review were carried out by the project's authors.

### Conclusion

Every technique in this plan is not an abstraction but a documented behavior that named, tracked threat groups have actually used in confirmed incidents — including Colonial Pipeline (2021), the attacks on the Ukrainian power grid (2015 and 2022), and SolarWinds (2020), alongside Linux-specific cron-persistence cases like Rocke and Kinsing. The plan emulates a sequence that has been observed in the real world, not an invented one.
