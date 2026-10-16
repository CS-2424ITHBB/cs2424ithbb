Assignment 2 Week 6 Karabalin Bakhtiyar and Tulepbergen Beksultan

# Technique Study and Attack Simulation: T1059 (Command and Scripting Interpreter)

## Executive Summary


----------

## 1. Technique Study: T1059 — Command and Scripting Interpreter

### 1.1 Overview

T1059 covers adversaries abusing command and script interpreters to execute commands, scripts, or binaries during or after gaining access to a system. It is one of the most commonly observed techniques across real-world intrusions because nearly every operating system ships with a built-in interpreter.

### 1.2 Sub-techniques

| ID | Name | Platform |
|---|---|---|
| T1059.001 | PowerShell | Windows |
| T1059.003 | Windows Command Shell | Windows |
| T1059.004 | Unix Shell | Linux / macOS |
| T1059.005 | Visual Basic | Windows |
| T1059.006 | Python | Cross-platform |
| T1059.007 | JavaScript | Cross-platform |
| T1059.008 | Network Device CLI | Network devices |

This report focuses on **T1059.004 (Unix Shell)**, since the simulation was executed on a Linux host, in contrast to Week 5's Windows/PowerShell hunt.

### 1.3 Relevance and Known Usage

Unix shell abuse is commonly seen after initial access on Linux servers, IoT devices, and cloud instances — including, notably, misconfigured webcamXP and similar embedded devices studied in Weeks 1-2 of this project, where the host operating system can be reached once the web interface is compromised. Numerous threat groups and malware families rely on shell commands for reconnaissance, payload retrieval, and persistence.

### 1.4 Mitigations and Data Sources (per ATT&CK)

- **Mitigations:** Execution Prevention (M1038), Privileged Account Management (M1026), Disable or Remove Feature or Program (M1042).
- **Data Sources:** Command: Command Execution, Process: Process Creation, Process: Process Command-Line Parameters, File: File Creation (for dropped tools).

----------

## 2. ATT&CK Navigator — Brief Overview


================================================================================
![alt text](<Screens/navigator_layer.png>)
================================================================================

*Figure 1. ATT&CK Navigator layer showing the techniques covered by this week's simulation, color-coded by tactic.*

----------

## 3. Attack Simulation

### 3.1 Scope and Safety

All actions below were executed locally, on the authors' own Kali Linux VM, against no external target. Commands either reproduce benign system behavior (discovery) or download non-malicious public files, to safely demonstrate the *mechanics* of each ATT&CK technique without any real malicious payload or impact.

### 3.2 Logging Setup

`auditd` was installed and configured to log every process execution (`execve`), acting as the local telemetry source — analogous to the Sysmon/PowerShell logging used in Week 5.

```bash
sudo apt update
sudo apt install auditd -y
sudo systemctl enable --now auditd
sudo auditctl -a always,exit -F arch=b64 -S execve -k shell_sim
```

================================================================================
![alt text](<Screens/step0_auditd_setup.png>)
================================================================================

*Figure 2. `auditd` installed, enabled, and the `shell_sim` audit rule applied.*

### 3.3 Step 1 — System Information Discovery (T1082)

```bash
whoami
uname -a
id
```

================================================================================
![alt text](<Screens/step1_discovery_system.png>)
================================================================================

*Figure 3. Output confirming current user, kernel/OS version, and UID/GID context.*

### 3.4 Step 2 — File/Directory and Process Discovery (T1083 / T1057)

```bash
ls -la /home
ps aux
```

================================================================================
![alt text](<Screens/step2_discovery_files_process.png>)
================================================================================

*Figure 4. Home directory listing and running process table.*

### 3.5 Step 3 — Ingress Tool Transfer (T1105)

A benign public file was downloaded to simulate retrieval of an external tool/payload.

```bash
curl -o /tmp/test_payload.sh https://raw.githubusercontent.com/MISP/2.4/main/README.md
cat /tmp/test_payload.sh | head -5
```

================================================================================
![alt text](<Screens/step3_ingress_tool_transfer.png>)
================================================================================

*Figure 5. File transferred into `/tmp` from an external source via `curl`.*

### 3.6 Step 4 — Persistence via Scheduled Task: Cron (T1053.003)

```bash
(crontab -l 2>/dev/null; echo "* * * * * echo sim_persistence >> /tmp/sim.log") | crontab -
crontab -l
```

================================================================================
![alt text](<Screens/step4_cron_added.png>)
================================================================================

*Figure 6. Cron entry added to the user's crontab.*

After waiting for the job to fire:

```bash
cat /tmp/sim.log
```

================================================================================
![alt text](<Screens/step5_cron_fired.png>)
================================================================================

*Figure 7. Confirmation that the scheduled job executed (`sim_persistence` logged).*

The entry was removed immediately afterward with `crontab -r` to avoid leaving a persistent artifact on the system.

### 3.7 Step 5 — Verifying Telemetry Capture (T1059.004)

All commands above were executed through the Unix shell and captured by the `auditd` rule configured in 3.2, confirming that the interpreter-execution events themselves (the core of T1059.004) were logged alongside the discovery/transfer/persistence actions they enabled.

```bash
sudo ausearch -k shell_sim | tail -40
```

================================================================================
![alt text](<Screens/step6_auditd_log.png>)
================================================================================

*Figure 8. `auditd` log entries showing `execve` events for the shell commands executed in Steps 1-4.*

----------

## 4. Mapping Results to ATT&CK Tactics and Techniques

| # | Action | Tactic | Technique | ID | Evidence |
|---|---|---|---|---|---|
| 1 | Executed commands via Bash | Execution | Command and Scripting Interpreter: Unix Shell | T1059.004 | Figure 8 |
| 2 | `whoami`, `uname -a`, `id` | Discovery | System Information Discovery | T1082 | Figure 3 |
| 3 | `ls -la`, `ps aux` | Discovery | File and Directory Discovery / Process Discovery | T1083 / T1057 | Figure 4 |
| 4 | `curl` download to `/tmp` | Command and Control / Resource Development | Ingress Tool Transfer | T1105 | Figure 5 |
| 5 | Cron job added and fired | Persistence / Scheduled Task Execution | Scheduled Task/Job: Cron | T1053.003 | Figures 6-7 |

----------

## 5. Findings

1. Every shell command executed in Steps 1-4 was captured by the single `execve` audit rule, confirming that a minimal `auditd` configuration gives adequate visibility into T1059.004 activity on Linux.
2. Discovery commands (T1082, T1083, T1057) produce low-noise, high-fidelity signal and are cheap to detect, since they are rarely invoked in this exact sequence by legitimate users.
3. The `curl`-based tool transfer (T1105) is indistinguishable from legitimate administrative activity using command content alone; detection requires correlating destination reputation, process lineage, and subsequent file execution.
4. Cron-based persistence (T1053.003) is trivial to detect if `crontab` changes are monitored, but easy to miss if only process-execution logs are reviewed without also watching `/var/spool/cron` or crontab diffs.
5. This simulation covers the Linux side of T1059 and directly complements the Windows/PowerShell hunt from Week 5 (T1059.001), giving the project coverage across both major interpreter sub-techniques.

----------

## 6. Recommendations

1. Monitor `execve` events for interpreter processes (`bash`, `sh`) combined with network tool invocations (`curl`, `wget`) in the same process lineage — a strong indicator of Ingress Tool Transfer.
2. Alert on any modification to user or system crontabs outside of approved change windows (T1053.003).
3. Baseline normal discovery-command usage per host/user to reduce false positives while still catching anomalous recon sequences.
4. Forward `auditd` logs to a central SIEM (e.g., the Splunk instance from Week 5) to correlate Linux shell activity with the Windows PowerShell telemetry already collected, enabling cross-platform hunting.
5. Maintain and update the ATT&CK Navigator layer as new techniques are hunted each week, building a cumulative coverage map for the project.

----------

## 7. Artificial Intelligence Usage

AI was used as a supporting instrument to structure this report, explain the T1059 technique family, and help design a safe, reproducible command sequence for the simulation and its ATT&CK mapping. All command execution, log collection, screenshot capture, and validation were performed by the project authors on their own Kali Linux VM.

----------

## Sources

- MITRE ATT&CK (attack.mitre.org): T1059, T1059.004, T1082, T1083, T1057, T1105, T1053.003.
- MITRE ATT&CK Navigator documentation (github.com/mitre-attack/attack-navigator).
- `auditd` / Linux Audit Framework documentation.
