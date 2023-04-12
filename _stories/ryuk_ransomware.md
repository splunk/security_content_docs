---
title: "Ryuk Ransomware"
last_modified_at: 2020-11-06
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Network_Traffic
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Leverage searches that allow you to detect and investigate unusual activities that might relate to the Ryuk ransomware, including looking for file writes associated with Ryuk, Stopping Security Access Manager, DisableAntiSpyware registry key modification, suspicious psexec use, and more.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic)
- **Last Updated**: 2020-11-06
- **Author**: Jose Hernandez, Splunk
- **ID**: 507edc74-13d5-4339-878e-b9744ded1f35

#### Narrative

Cybersecurity Infrastructure Security Agency (CISA) released Alert (AA20-302A) on October 28th called Ransomware Activity Targeting the Healthcare and Public Health Sector. This alert details TTPs associated with ongoing and possible imminent attacks against the Healthcare sector, and is a joint advisory in coordination with other U.S. Government agencies. The objective of these malicious campaigns is to infiltrate targets in named sectors and to drop ransomware payloads, which will likely cause disruption of service and increase risk of actual harm to the health and safety of patients at hospitals, even with the aggravant of an ongoing COVID-19 pandemic. This document specifically refers to several crimeware exploitation frameworks, emphasizing the use of Ryuk ransomware as payload. The Ryuk ransomware payload is not new. It has been well documented and identified in multiple variants. Payloads need a carrier, and for Ryuk it has often been exploitation frameworks such as Cobalt Strike, or popular crimeware frameworks such as Emotet or Trickbot.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [BCDEdit Failure Recovery Modification](/endpoint/809b31d2-5462-11eb-ae93-0242ac130002/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [BCDEdit Failure Recovery Modification](/endpoint/76d79d6e-25bb-40f6-b3b2-e0a6b7e5ea13/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Common Ransomware Extensions](/endpoint/a9e5c5db-db11-43ca-86a8-c852d1b2c0ec/) | [Data Destruction](/tags/#data-destruction) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Common Ransomware Notes](/endpoint/ada0f478-84a8-4641-a3f1-d82362d6bd71/) | [Data Destruction](/tags/#data-destruction) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [NLTest Domain Trust Discovery](/endpoint/c3e05466-5f22-11eb-ae93-0242ac130002/) | [Domain Trust Discovery](/tags/#domain-trust-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Remote Desktop Network Bruteforce](/network/a98727cc-286b-4ff2-b898-41df64695923/) | [Remote Desktop Protocol](/tags/#remote-desktop-protocol), [Remote Services](/tags/#remote-services) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Remote Desktop Network Traffic](/network/272b8407-842d-4b3d-bead-a704584003d3/) | [Remote Desktop Protocol](/tags/#remote-desktop-protocol), [Remote Services](/tags/#remote-services) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Ryuk Test Files Detected](/endpoint/57d44d70-28d9-4ed1-acf5-1c80ae2bbce3/) | [Data Encrypted for Impact](/tags/#data-encrypted-for-impact) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Ryuk Wake on LAN Command](/endpoint/538d0152-7aaa-11eb-beaa-acde48001122/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [Windows Command Shell](/tags/#windows-command-shell) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Spike in File Writes](/endpoint/fdb0f805-74e4-4539-8c00-618927333aae/) |  | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Scheduled Task from Public Directory](/endpoint/7feb7972-7ac3-11eb-bac8-acde48001122/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [WBAdmin Delete System Backups](/endpoint/cd5aed7e-5cea-11eb-ae93-0242ac130002/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [WBAdmin Delete System Backups](/endpoint/71efbf52-4dbb-4c00-a520-306aa546cbb7/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [WinEvent Scheduled Task Created Within Public Path](/endpoint/5d9c6eee-988c-11eb-8253-acde48001122/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [WinEvent Scheduled Task Created to Spawn Shell](/endpoint/203ef0ea-9bd8-11eb-8201-acde48001122/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows DisableAntiSpyware Registry](/endpoint/23150a40-9301-4195-b802-5bb4f43067fb/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Security Account Manager Stopped](/endpoint/69c12d59-d951-431e-ab77-ec426b8d65e6/) | [Service Stop](/tags/#service-stop) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows connhost exe started forcefully](/deprecated/c114aaca-68ee-41c2-ad8c-32bf21db8769/) | [Windows Command Shell](/tags/#windows-command-shell) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://www.splunk.com/en_us/blog/security/detecting-ryuk-using-splunk-attack-range.html](https://www.splunk.com/en_us/blog/security/detecting-ryuk-using-splunk-attack-range.html)
* [https://www.crowdstrike.com/blog/big-game-hunting-with-ryuk-another-lucrative-targeted-ransomware/](https://www.crowdstrike.com/blog/big-game-hunting-with-ryuk-another-lucrative-targeted-ransomware/)
* [https://us-cert.cisa.gov/ncas/alerts/aa20-302a](https://us-cert.cisa.gov/ncas/alerts/aa20-302a)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/ryuk_ransomware.yml) \| *version*: **1**