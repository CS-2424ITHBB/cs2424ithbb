Karabalin, Tulepbergen

Executive Summary

This report documents the deployment of the Malware Information Sharing Platform (MISP) via Docker, and the subsequent ingestion of Indicators of Compromise (IOCs) derived from the passive OSINT reconnaissance conducted in Week 2 against exposed webcamXP surveillance servers. Building directly on the Data Source Mapping Matrix established previously, this phase transforms raw Shodan telemetry (IP addresses, HTTP banners, open ports, and organizational attribution) into structured, machine-readable Cyber Threat Intelligence artifacts. The report further demonstrates the data processing pipeline — ingestion, deduplication, and normalization — required to convert unstructured reconnaissance data into a validated, publishable MISP Event.

----------

Section 1: MISP Deployment

1.1 Deployment Methodology

MISP was deployed locally using the official `misp-docker` container stack (github.com/MISP/misp-docker) on a Kali Linux virtual machine running Docker Engine and Docker Compose. Rather than building images from source — which introduces build-time dependency failures and disk exhaustion risks — pre-built images were pulled directly from the GitHub Container Registry (ghcr.io), ensuring a reproducible and stable deployment.

1.2 Deployment Steps

1. Cloned the official repository: `git clone https://github.com/MISP/misp-docker`
2. Generated the environment configuration file from the provided template: `cp template.env .env`
3. Configured core runtime variables (`ADMIN_EMAIL`, `BASE_URL`) within `.env`
4. Pulled pre-built images and launched the multi-container stack: `docker-compose up -d`
5. Verified container health across all six services: db (MariaDB), redis (Valkey), mail, misp-modules, misp-core, and misp-nginx

1.3 Verification of Deployment

All six containers reached a `Healthy` status, confirming that the MISP core application, its background workers, database, cache layer, and reverse proxy were fully operational and reachable via `http://localhost`.

================================================================================
![alt text](<Снимок_экрана_2026-09-26_144217.png>)
================================================================================

----------

Section 2: Event Creation and IOC Ingestion

2.1 Event Initialization

A new MISP Event was created to serve as the container for all IOCs collected during the Week 2 Shodan reconnaissance phase against webcamXP infrastructure. The event was configured with the following metadata:

- **Event Info:** webcamXP Exposure Campaign — Shodan OSINT Collection
- **Threat Level:** Medium
- **Analysis:** Initial
- **Distribution:** Your organisation only

================================================================================
![alt text](<Снимок_экрана_2026-09-26_144326.png>)
![alt text](<Снимок_экрана_2026-09-26_144508.png>)
================================================================================

2.2 Bulk IOC Ingestion via Freetext Import

To efficiently convert the raw IP addresses harvested from Shodan (Week 2, Section 1.3) into formal MISP attributes, the built-in **Freetext Import Tool** was used. This tool parses unstructured text input and automatically infers the correct MISP attribute type for each value — in this case, correctly classifying all submitted values as `ip-dst` under the `Network activity` category.

Submitted IOCs:
- 184.57.102.6
- 61.78.164.58
- 67.162.253.121
- 181.1.44.232

================================================================================
![alt text](<Снимок_экрана_2026-09-26_145914.png>)
================================================================================

2.3 Manual Attribute Enrichment

In addition to the automatically imported IP addresses, supplementary contextual attributes were added manually to preserve the full spectrum of data captured during the OSINT phase:

| Category | Type | Value |
|---|---|---|
| Network activity | port | 8080 |
| Payload delivery | text | Server: webcamXP 5 |
| Other | text | Charter Communications Inc |

================================================================================
![alt text](<Снимок_экрана_2026-09-26_150311.png>)
================================================================================

----------

Section 3: Data Filtering and Normalization

3.1 Normalization

A core requirement of the data processing phase is ensuring that all ingested telemetry conforms to a single, consistent schema rather than existing as unstructured text. The Freetext Import Tool enforced this automatically: all four IP addresses — regardless of their source formatting — were normalized into the identical MISP attribute type `ip-dst`, under the identical category `Network activity`. This uniformity is what enables downstream correlation, search, and automated sharing between MISP instances.

3.2 Deduplication

To validate MISP's native deduplication safeguards, an already-ingested IOC (`184.57.102.6`) was resubmitted through the standard **Add Attribute** form. MISP correctly identified the resubmission and raised the warning: *"A similar attribute already exists for this event."* This confirms that the platform actively prevents redundant IOC entries within a single event, satisfying the filtering requirement of the assignment.

================================================================================
![alt text](<1790418165632_image.png>)
================================================================================

3.3 Data Mapping: Shodan (Week 2) → MISP Attributes

| Week 2 Data Element (Shodan) | MISP Category | MISP Attribute Type | Value |
|---|---|---|---|
| IPv4 Address (DS-1) | Network activity | ip-dst | 184.57.102.6, 61.78.164.58, 67.162.253.121, 181.1.44.232 |
| Open Network Ports (DS-5) | Network activity | port | 8080 |
| HTTP Banner (DS-2) | Payload delivery | text | Server: webcamXP 5 |
| Organization Data / ASN (DS-6) | Other | text | Charter Communications Inc |

----------

Section 4: Event Publication

Following ingestion, filtering, and validation, the event was published to finalize its lifecycle within the platform — a required step to make the intelligence available for internal consumption and future correlation against newly ingested feeds. The event record confirms a total of **7 attributes** attached, with a first published timestamp of 2026-09-26 10:03:23.

================================================================================
![alt text](<Снимок_экрана_2026-09-26_151124.png>)
================================================================================

----------

Section 5: Conclusion

This phase successfully closed the loop between passive OSINT collection (Week 2) and structured threat intelligence processing (Week 3). By deploying MISP and ingesting the previously harvested webcamXP indicators, the raw Shodan telemetry was transformed into a normalized, deduplicated, and published Event — directly demonstrating the "Ingestion → Normalization & Filtering → Mapping & Enrichment" pipeline defined in the Week 2 Data Mapping Matrix. The resulting MISP Event now serves as a reusable, shareable intelligence artifact that could be exported, correlated against external feeds, or used to drive automated defensive actions such as firewall blocklisting.
