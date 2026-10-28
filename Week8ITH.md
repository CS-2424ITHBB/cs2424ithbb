# Adversary Emulation Plan (Simple)
### Initial Access → Persistence → Data Exfiltration
**Framework reference:** MITRE ATT&CK (Enterprise) + MITRE CALDERA

---

## 1. Purpose and Scope

A simple attack scenario emulation for a training (purple team) environment: an adversary gains initial access to a workstation, establishes persistence, and exfiltrates data. Every technique is mapped to a MITRE ATT&CK ID so the plan can later be implemented as an adversary profile in CALDERA (abilities → ability sets → operation).

**Target assumption:** a single Windows/Linux workstation in an isolated lab environment, with no access to production networks.

---

## 2. Stage 1 — Initial Access

| # | Technique | ATT&CK ID | Description |
|---|-----------|-----------|--------------|
| 1.1 | Phishing: Spearphishing Attachment | **T1566.001** | Sending a malicious attachment to a target user (e.g., a macro embedded in an office document) that executes a payload when opened |
| 1.2 | (alternative) Valid Accounts | **T1078** | Using previously compromised or weak credentials to log in through a legitimate channel |

**Success criterion:** first code execution / shell obtained on the target host.
**Detection indicator (blue team):** attachment-open event + child process spawned by the office application (e.g., `winword.exe → powershell.exe`).

---

## 3. Stage 2 — Persistence

| # | Technique | ATT&CK ID | Description |
|---|-----------|-----------|--------------|
| 2.1 | Boot or Logon Autostart Execution: Registry Run Keys | **T1547.001** | Adding a registry run key (`HKCU\...\Run`) so the agent/implant launches on every user logon |
| 2.2 | Scheduled Task/Job | **T1053.005** | Creating a scheduled task that periodically re-launches the implant |

**Success criterion:** the implant survives a reboot / user logoff.
**Detection indicator:** new values in registry autorun keys; new scheduled tasks created by a non-privileged user.

---

## 4. Stage 3 — Data Exfiltration

| # | Technique | ATT&CK ID | Description |
|---|-----------|-----------|--------------|
| 3.1 | Exfiltration Over C2 Channel | **T1041** | Transferring collected files over the already-established command-and-control channel, without opening a separate connection |
| 3.2 | Archive Collected Data | **T1560** | Archiving (optionally with password protection/encryption) collected files before transfer, to reduce size and evade simple DLP rules |

**Success criterion:** a test marker file (canary file) is successfully received on the "attacker server" side within the lab environment.
**Detection indicator:** anomalous outbound traffic/volume from the host; archive files created in temp directories immediately before network activity.

---

## 5. Kill Chain Summary

```
T1566.001 (Phishing Attachment)
        │
        ▼
T1547.001 (Registry Run Key) ──► T1053.005 (Scheduled Task)
        │
        ▼
T1560 (Archive Data) ──► T1041 (Exfil over C2)
```

---

## 6. Implementation in MITRE CALDERA

Per the CALDERA documentation, each technique above is defined as a separate **ability** (a YAML entry specifying `tactic`, `technique_id`, and the command for Windows/Linux/macOS). These abilities are grouped into an **adversary profile** (sequence: Initial Access → Persistence → Exfiltration), which is then executed as an **operation** against an agent (Sandcat) deployed on the test host. This allows the plan to be reproduced automatically and lets defenders record which techniques were detected (an actionable purple-team report).

---

## 7. Limitations and Ethics

This plan is **for educational/demonstration purposes only** and is intended strictly for an isolated lab environment with the explicit authorization of the system owner, consistent with adversary emulation methodology and CALDERA's usage guidelines. No specific commands or payloads are included here — the plan describes techniques at the ATT&CK ID level; their concrete implementation is left to the student within the lab exercise.
