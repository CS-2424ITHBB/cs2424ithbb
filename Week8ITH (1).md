Assignment 2 Week 8 Karabalin Bakhtiyar and Tulepbergen Beksultan

# Adversary Emulation Plan (Simple)
### Initial Access → Persistence → Collection and Exfiltration
**Framework reference:** MITRE ATT&CK (Enterprise) + MITRE CALDERA

---

## 1. Purpose and Scope

A simple attack scenario for a training (purple team) environment: an adversary gains initial access to a workstation, establishes persistence, and exfiltrates data. Every step is mapped to a MITRE ATT&CK technique ID, so the plan can later be built in CALDERA as abilities → adversary profile → operation.

**Target assumption:** a single Windows workstation in an isolated lab, with no access to production networks.

---

## 2. Stage 1 — Initial Access

| # | Technique | ATT&CK ID | Description |
|---|-----------|-----------|-------------|
| 1.1 | Phishing: Spearphishing Attachment | **T1566.001** | A malicious attachment (e.g., an office document with a macro) is sent to a user and runs a payload when opened |
| 1.2 | Valid Accounts (alternative) | **T1078** | Logging in with previously compromised or weak credentials through a legitimate channel |

**Success criterion:** first code execution / shell on the target host.
**Detection indicator:** an office application starts a child process (e.g., `winword.exe → powershell.exe`).

---

## 3. Stage 2 — Persistence

| # | Technique | ATT&CK ID | Description |
|---|-----------|-----------|-------------|
| 2.1 | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | **T1547.001** | Adding a Run key (`HKCU\...\Run`) so the implant starts at every user logon |
| 2.2 | Scheduled Task/Job: Scheduled Task | **T1053.005** | Creating a scheduled task that periodically re-launches the implant |

**Success criterion:** the implant survives a reboot or user logoff.
**Detection indicator:** new values in autorun registry keys; new scheduled tasks created by a non-privileged user.

---

## 4. Stage 3 — Collection and Exfiltration

| # | Technique | ATT&CK ID | Description |
|---|-----------|-----------|-------------|
| 3.1 | Data from Local System | **T1005** | Finding and collecting target files from the host (in the lab: a canary file) |
| 3.2 | Archive Collected Data: Archive via Utility | **T1560.001** | Compressing (optionally password-protecting) the files before transfer to reduce size and avoid simple DLP rules |
| 3.3 | Application Layer Protocol: Web Protocols | **T1071.001** | The C2 channel (provided by the CALDERA agent, Sandcat) that carries commands and data over HTTP(S) |
| 3.4 | Exfiltration Over C2 Channel | **T1041** | Sending the archive through the already-established C2 channel, without a separate connection |

**Success criterion:** the canary file arrives on the lab "attacker server".
**Detection indicator:** archive files created in temp folders right before network activity; unusual outbound traffic volume from the host.

---

## 5. Kill Chain Summary

```
T1566.001 (Phishing Attachment)
        │
        ▼
T1547.001 (Run Key) ──► T1053.005 (Scheduled Task)
        │
        ▼
T1005 (Collect Data) ──► T1560.001 (Archive) ──► T1041 (Exfil over C2, via T1071.001)
```

---

## 6. Notes

- **CALDERA:** each technique above becomes one ability (tactic, ATT&CK ID, and a command for the platform). The abilities are grouped into one adversary profile and run as an operation on a Sandcat agent. In the lab, Initial Access is simulated by manually starting the agent on the test host.
- **Lab only:** this plan is for education in an isolated environment with the owner's permission. It lists techniques by ATT&CK ID and contains no commands or payloads.

---

## 7. Artificial Intelligence Usage

AI was used to help structure this plan and check the ATT&CK mapping. The scenario and final review were done by the project authors.

---

## Sources

- MITRE ATT&CK (attack.mitre.org): T1566.001, T1078, T1547.001, T1053.005, T1005, T1560.001, T1071.001, T1041.
- MITRE CALDERA Documentation (caldera.readthedocs.io).
