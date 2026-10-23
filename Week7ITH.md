Assignment 2 Week 7 Karabalin Bakhtiyar and Tulepbergen Beksultan

# Using MITRE CAR: Implementing the PowerShell Execution Analytic (CAR-2014-04-003) in Splunk

## Executive Summary

This report takes a ready-made analytic from the MITRE Cyber Analytics Repository (CAR), **CAR-2014-04-003: Powershell Execution**, and turns it into a working detection in the Splunk instance built in Week 5. The analytic looks for PowerShell that was not launched interactively (parent process is not `explorer.exe`). On the Atomic Red Team dataset it returned **185 events on 3 hosts**. This is too noisy to alert on, so we tuned it with the suspicious flags found in Week 5 (encoded commands, download cradles, bypass switches) and reduced the result to **51 events in 5 groups**. The tuned search was saved as a scheduled Splunk alert. The analytic is mapped to ATT&CK T1059.001, and we add three techniques that we observed in the data (T1027, T1105, T1047).

----------

## 1. Theory: MITRE CAR and "Analytics vs Detections"

**MITRE CAR** (car.mitre.org) is a public library of analytics. Each entry describes a behavior of an attacker, the ATT&CK techniques it covers, the data needed to see it, and ready-to-use implementations (pseudocode, Splunk, EQL and others) together with true-positive examples.

The key idea of this week is the difference between an *analytic* and a *detection*:

| | Analytic | Detection |
|---|---|---|
| What it is | The **logic**: which behavior to look for and in which data | A **deployed rule** in a specific SIEM that produces alerts |
| Platform | Independent (pseudocode) | Tied to our fields, data and Splunk |
| Needs | Data model (objects and fields) | Field mapping, tuning, schedule, alert action |
| Example here | "powershell.exe with a parent other than explorer.exe" | Splunk search with `rex` extraction, exclusions and a saved hourly alert |

One analytic can become many detections (Splunk, Elastic, Sigma), and a raw analytic is usually **not** ready to alert: it must be adapted to local fields and tuned to remove noise.

----------

## 2. Selected Analytic: CAR-2014-04-003 (Powershell Execution)

We chose this analytic because it covers T1059.001, the technique hunted in Week 5, and our Splunk index `windows` already contains the Sysmon data it needs.

| Property | Value |
|---|---|
| ID / name | CAR-2014-04-003: Powershell Execution |
| Information domain / data subtype | Host / Process |
| Analytic type / platform | TTP / Windows |
| Contributor | MITRE |
| D3FEND | D3-PSA, Process Spawn Analysis |
| Data model | `process` `create` `exe`; `process` `create` `parent_exe` |

**ATT&CK coverage declared by CAR:**

| Technique | Sub-technique | Tactic | Level of coverage |
|---|---|---|---|
| Command and Scripting Interpreter (T1059) | PowerShell (T1059.001) | Execution | High |
| Command and Scripting Interpreter (T1059) | PowerShell (T1059.001) | Defense Evasion | Moderate |

**Pseudocode:** look for versions of PowerShell that were not launched interactively.

```
process = search Process:Create
powershell = filter process where (exe == "powershell.exe" AND parent_exe != "explorer.exe")
output powershell
```

================================================================================
![alt text](<Screens/week7_fig1.png>)
================================================================================

*Figure 1. MITRE CAR analytic CAR-2014-04-003 (PowerShell Execution) and its ATT&CK coverage.*

================================================================================
![alt text](<Screens/week7_fig2.png>)
================================================================================

*Figure 2. Pseudocode and Splunk implementation of the analytic: process-creation events where the image is powershell.exe and the parent is not explorer.exe.*

----------

## 3. Implementation in Splunk

### 3.1 Environment

The analytic was run in the Splunk Enterprise container from Week 5 on the Kali VM, in the index `windows`, which holds the Atomic Red Team dataset for T1059.001 (Sysmon and PowerShell logs). The time range is set to **All time**, because Splunk shows the loading time, not the original event time.

================================================================================
![alt text](<Screens/week7_fig3.png>)
================================================================================

*Figure 3. Splunk container running and healthy on the Kali host.*

### 3.2 Mapping CAR fields to our fields

The CAR Splunk version expects ready fields (`Image`, `ParentImage`, `CommandLine`, `ComputerName`). In our index, Sysmon events are XML text, so the fields must be extracted with `rex` first. This adaptation step is exactly what separates an analytic from a detection.

| CAR data model | Field in the CAR Splunk query | Field in our Splunk | How we get it |
|---|---|---|---|
| `process create exe` | `Image` | `Image` | `rex` on `<Data Name='Image'>` |
| `process create parent_exe` | `ParentImage` | `ParentImage` | `rex` on `<Data Name='ParentImage'>` |
| command line (output) | `CommandLine` | `CommandLine` | `rex` on `<Data Name='CommandLine'>` |
| host (output) | `ComputerName` | `Computer` | `rex` on `<Computer>` |
| Sysmon process creation | `EventCode=1` | `EventID=1` | `rex` on `<EventID>` |

### 3.3 Data check

```
index=windows | rex field=_raw "<EventID>(?<EventID>\d+)</EventID>" | search EventID=1 | stats count
```

The index contains **406** Sysmon process-creation events, which is the data the analytic requires.

================================================================================
![alt text](<Screens/week7_fig4.png>)
================================================================================

*Figure 4. Sysmon process-creation events (EventID 1) in index "windows": 406 events, the data required by the analytic.*

### 3.4 Baseline: all PowerShell launches

```
index=windows
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| search EventID=1
| rex field=_raw "<Computer>(?<Computer>[^<]*)</Computer>"
| rex field=_raw "<Data Name=.Image.>(?<Image>[^<]*)"
| rex field=_raw "<Data Name=.CommandLine.>(?<CommandLine>[^<]*)"
| rex field=_raw "<Data Name=.ParentImage.>(?<ParentImage>[^<]*)"
| search Image="*powershell.exe"
| table _time Computer ParentImage CommandLine
```

This returns **186 events**, the same number as in Week 5. It is our baseline, before the CAR parent-process condition is applied.

================================================================================
![alt text](<Screens/week7_fig5.png>)
================================================================================

*Figure 5. Baseline: all 186 PowerShell launches in the dataset (no parent-process condition).*

### 3.5 CAR logic: PowerShell not launched from explorer.exe

```
index=windows
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| search EventID=1
| rex field=_raw "<Computer>(?<Computer>[^<]*)</Computer>"
| rex field=_raw "<Data Name=.Image.>(?<Image>[^<]*)"
| rex field=_raw "<Data Name=.CommandLine.>(?<CommandLine>[^<]*)"
| rex field=_raw "<Data Name=.ParentImage.>(?<ParentImage>[^<]*)"
| search Image="*powershell.exe"
| search NOT ParentImage="*explorer.exe"
| stats count values(CommandLine) as "Command Lines" values(ParentImage) as "Parent Images" by Computer
```

This is our translation of the CAR pseudocode and of its Splunk version. It returns **185 events on 3 hosts** (one launch from `explorer.exe` is removed). The output is still noisy: it contains the Splunk forwarder's own scripts (`splunk-powershell.exe`) next to real test commands such as `-exec bypass`, a download of PowerShell scripts from `raw.githubusercontent.com`, and `DownloadFile` from a shortened link.

Two small differences from the CAR Splunk query: it matches the path `C:\Windows\*\powershell.exe` and excludes exactly `C:\Windows\explorer.exe`, while we use the wildcards `*powershell.exe` and `*explorer.exe`. Our wildcard is broader and also matches `splunk-powershell.exe`.

================================================================================
![alt text](<Screens/week7_fig6.png>)
================================================================================

*Figure 6. CAR logic in Splunk: PowerShell launches whose parent is not explorer.exe (185 events on 3 hosts).*

### 3.6 From analytic to detection: tuning

An alert on 185 events would not be usable. We added the suspicious indicators found in Week 5 and excluded the known-good Splunk forwarder parent:

```
index=windows
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| search EventID=1
| rex field=_raw "<Computer>(?<Computer>[^<]*)</Computer>"
| rex field=_raw "<Data Name=.Image.>(?<Image>[^<]*)"
| rex field=_raw "<Data Name=.CommandLine.>(?<CommandLine>[^<]*)"
| rex field=_raw "<Data Name=.ParentImage.>(?<ParentImage>[^<]*)"
| search Image="*powershell.exe"
| search NOT ParentImage="*splunkd.exe"
| search CommandLine="*-enc*" OR CommandLine="*EncodedCommand*" OR CommandLine="*DownloadString*" OR CommandLine="*IEX*" OR CommandLine="*bypass*" OR CommandLine="*hidden*"
| stats count values(CommandLine) as commands by Computer ParentImage
| sort - count
```

The result is **51 events in 5 groups**, about 73% fewer than the 186 baseline. The `splunkd.exe` exclusion did not change the count on this dataset (the forwarder launches do not carry these flags), but it is kept so the detection stays stable if the forwarder starts using such arguments.

================================================================================
![alt text](<Screens/week7_fig7.png>)
================================================================================

*Figure 7. Tuned detection: only launches with encoded-command, download-cradle or bypass flags remain (51 events in 5 groups). Splunk forwarder parent excluded.*

| Stage | Events |
|---|---|
| Sysmon process creation (EventID 1) | 406 |
| All PowerShell launches (baseline) | 186 |
| CAR logic (parent is not explorer.exe) | 185 |
| Tuned detection (suspicious flags) | 51 |

### 3.7 Saving the detection as a Splunk alert

The tuned search was saved with **Save As, Alert**: title `CAR-2014-04-003 Suspicious PowerShell Launch`, type Scheduled (hourly, at 0 minutes past the hour), trigger when the number of results is greater than 0, trigger for each result, action *Add to Triggered Alerts* with severity High. At this point the analytic becomes an operational detection.

================================================================================
![alt text](<Screens/week7_fig8.png>)
================================================================================

*Figure 8. The tuned analytic is saved as a scheduled Splunk alert.*

================================================================================
![alt text](<Screens/week7_fig9.png>)
================================================================================

*Figure 9. The alert is registered in Splunk (enabled, private, hourly). No fired events yet, because it runs on a schedule.*

----------

## 4. Mapping to ATT&CK Tactics and Techniques

| Behavior | Tactic | Technique | ID | Source of mapping | Evidence |
|---|---|---|---|---|---|
| PowerShell not launched from explorer.exe | Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | **CAR** (coverage High) | Fig. 6 |
| Same behavior used to hide activity | Defense Evasion | Command and Scripting Interpreter: PowerShell | T1059.001 | **CAR** (coverage Moderate) | Fig. 2 |
| `-Enc` / `-EncodedCommand` arguments | Defense Evasion | Obfuscated Files or Information | T1027 | Observed in data | Fig. 5, Fig. 7 |
| `DownloadFile`, `DownloadString`, script from raw.githubusercontent.com | Command and Control | Ingress Tool Transfer | T1105 | Observed in data | Fig. 6, Fig. 7 |
| PowerShell started by `WmiPrvSE.exe` | Execution | Windows Management Instrumentation | T1047 | Observed in data | Fig. 5 |

CAR itself declares only T1059.001. The other three techniques are **not part of the analytic**: we added them because the same events in our dataset show these behaviors (they match the Week 5 findings). The CAR true-positive example (Mordor dataset) has the same pattern as our data: parent `wmiprvse.exe` and arguments `-nop -sta -w 1 -enc`.

Note: CAR uses the tactic name *Defense Evasion*, while the newer ATT&CK version in the Navigator shows T1027 under *Stealth*.

================================================================================
![alt text](<Screens/week7_fig10.png>)
================================================================================

*Figure 10. ATT&CK Navigator layer: T1059.001, T1027, T1105 and T1047.*

----------

## 5. Findings

1. The CAR pseudocode is easy to translate, but **field names and data format differ**: our XML events required `rex` extraction before the analytic could run.
2. The raw analytic gives **185 events on 3 hosts**, so it is a good *starting point* but not a usable alert.
3. Combining the CAR logic with the Week 5 indicators cut the result to **51 events (5 groups)** and kept all the interesting commands (encoded payloads, download cradles, bypass).
4. The parent-process condition is useful but weak alone: a legitimate parent is not proof of safe activity, and malicious PowerShell can also be started from `explorer.exe`.
5. Our wildcard `*powershell.exe` also matches `splunk-powershell.exe`. A stricter path as in CAR (`C:\Windows\*\powershell.exe`) would remove this known-good noise.

## 6. Limitations and Recommendations

- The dataset is a simulation (Atomic Red Team) from a lab host, so real false-positive rates are unknown.
- Splunk timestamps show loading time, so no timeline analysis was done.
- The alert is hourly and has not fired yet; for real use, test it on fresh data.
- Use the full path match from CAR and allowlist known parents (Splunk forwarder) after checking them.
- Detect encoded commands by pattern, not by exact text, so shortened parameters (`-Enc`, `-Enco`) are covered.
- Keep Sysmon process creation (EventID 1) enabled on every endpoint, because the analytic depends on it.

----------

## 7. Artificial Intelligence Usage

AI was used as a supporting instrument to structure this report, explain the CAR framework and the difference between analytics and detections, and help adapt the CAR pseudocode to our Splunk fields. All searches, tuning, alert configuration, screenshots and validation were performed by the project authors on their own Kali Linux VM.

----------

## Sources

- MITRE CAR (car.mitre.org): CAR-2014-04-003, Powershell Execution.
- MITRE ATT&CK (attack.mitre.org): T1059.001, T1027, T1105, T1047.
- MITRE D3FEND: D3-PSA, Process Spawn Analysis.
- MITRE ATT&CK Navigator (github.com/mitre-attack/attack-navigator).
- Splunk `attack_data` repository, Atomic Red Team dataset for T1059.001 (Week 5).
