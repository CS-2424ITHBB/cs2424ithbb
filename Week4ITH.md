Assigment 2 Week 4 Karabalin Bakhtiyar and Tulepbergen Beksultan

## 1. Brief Incident Description

In January 2012, a researcher using the alias **"someLuser"** discovered and published a vulnerability in the firmware of TRENDnet SecurView home IP cameras. A flaw in the **Direct Video Stream Authentication (DVSA)** mechanism allowed direct access to the live video (and, on some models, audio) stream without a login or password, simply by requesting a specific URL. Because the manufacturer also transmitted credentials in clear (unencrypted) text, both channels were compromised: the video stream itself and the access passwords.

After the exploit was published, links to accessible cameras spread across forums; later, a separate project plotted hundreds of such cameras on Google Maps. The result was public access to the video of nearly **700 cameras**, including bedrooms, children's rooms, and rooms with security systems. In 2013, the U.S. Federal Trade Commission (FTC) required TRENDnet to fix the problem and undergo security audits for 20 years.

---

## 2. Analysis by Cyber Kill Chain Stage (Lockheed Martin)

| Stage | What happened | Evidence / source |
|---|---|---|
| **1. Reconnaissance** | The researcher "someLuser" studied the firmware and web interface of TRENDnet SecurView cameras, analyzing HTTP request handling and the authentication mechanism. | Console-cowboys blog post (Jan 10, 2012) with an analysis of the firmware and DVSA logic. |
| **2. Weaponization** | Based on the analysis, a working bypass technique was developed: a direct HTTP request to a specific camera CGI endpoint that serves the video stream without checking login/password. | Publicly disclosed PoC URL of the form `/anony/mjpg.cgi`, which works without authorization on vulnerable models. |
| **3. Delivery** | The bypass method and the list of vulnerable models were published on an open blog; links to the exploit and to specific accessible cameras then spread across forums. | Blog post of January 10, 2012; reposts on forums and aggregators (e.g., cams.hhba.info). |
| **4. Exploitation** | Anyone could send the crafted HTTP request to a camera's external IP — authentication was bypassed due to the DVSA flaw in the firmware of 20 SecurView models. | FTC complaint: "design flaw that allowed hackers to bypass a login system and access live feeds". |
| **5. Installation** | There was no classic malware installation — the vulnerability was exploited "on the fly" via the camera's standard web server; "persistence" consisted of publishing and cataloging the accessible addresses. | The "TrendNet Exposed" project plotted hundreds of accessible cameras on Google Maps a year after the patch. |
| **6. Command & Control** | No separate C2 channel was needed — the camera itself remained a permanently accessible public video server; instead of C2 infrastructure, attackers used automated discovery/collection of accessible hosts. | Mass publication of links to ~700 cameras on forums, which let third parties connect directly. |
| **7. Actions on Objectives** | Viewing (and in some cases listening through the microphone to) private video streams: bedrooms, baby cribs, living spaces; in one documented incident, a voice message was spoken to a sleeping child through a compromised monitor. | FTC materials (*In re TRENDnet*, 2013): "private lives of hundreds of consumers... went public". |

**Case specifics:** the *Installation* and *Command & Control* stages are absent in the classic sense (malware installation, a control channel) — this is typical of attacks that exploit a logic vulnerability or leak through misconfiguration, as opposed to payload-driven (malware-driven) attacks. Their role here is played by the "persistence of knowledge" about vulnerable hosts (cataloging) and repeatable direct access through the device's standard web interface.

---

## 3. Mapping to MITRE ATT&CK (TTPs)

The ATT&CK (Enterprise) matrix is not specifically designed for IoT/embedded devices, but the main tactics and techniques transfer directly, since the attack went through the device's standard web service.

| ATT&CK Tactic | Technique | ID | Rationale |
|---|---|---|---|
| Reconnaissance | Gather Victim Host Information | `T1592.002` | Analysis of the camera's firmware/software and authentication logic before searching for a bypass. |
| Reconnaissance | Active Scanning: Vulnerability Scanning | `T1595.002` | Finding and checking camera models vulnerable to the DVSA bypass at public internet addresses. |
| Resource Development | Acquire Infrastructure / Develop Capabilities: Exploits | `T1588.005` | Creation of a working PoC request (exploit) that bypasses authentication. |
| Initial Access | Exploit Public-Facing Application | `T1190` | Sending a specially crafted HTTP request to the camera's publicly accessible web server to bypass login. |
| Credential Access | Adversary-in-the-Middle / Network Sniffing | `T1040` | Camera logins and passwords were transmitted in clear text over the network, making them interceptable. |
| Collection | Video Capture | `T1125` | Obtaining the live video stream from the camera without authorization. |
| Collection | Audio Capture | `T1123` | In some incidents — access to the camera's/monitor's built-in microphone. |
| Collection | Automated Collection | `T1119` | Mass cataloging of hundreds of accessible cameras (the Google Maps aggregator). |
| Exfiltration | Exfiltration Over Web Service | `T1567` | Publishing direct links to video streams and their coordinates on public forums/maps — effectively a leak into the public domain. |
| Impact | — (privacy violation; not a separate ATT&CK Impact technique) | — | Violation of the privacy of hundreds of families; reputational and legal damage (FTC case). |

---

## 6. Sources

- FTC, *In the Matter of TRENDnet, Inc.*, File No. 1223090 (2013) — official complaint and settlement.
- console-cowboys blog — someLuser's post of January 10, 2012, analyzing the DVSA vulnerability.
- MITRE ATT&CK (attack.mitre.org) — techniques T1592.002, T1595.002, T1588.005, T1190, T1040, T1125, T1123, T1119, T1567.

