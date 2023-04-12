---
title: "Chaos Ransomware"
last_modified_at: 2023-01-11
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Leverage searches that allow you to detect and investigate unusual activities that might relate to the Chaos ransomware, including looking for file writes (file encryption and ransomware notes), deleting shadow volume storage, registry key modification, dropping of files in startup folder, and more.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2023-01-11
- **Author**: Teoderick Contreras, Splunk
- **ID**: 153d7b8f-27f2-4e4d-bae8-dfafd93a22a8

#### Narrative

CHAOS ransomware has been seen and monitored since 2021. This ransomware is purportedly a .NET version of Ryuk ransomware but upon closer look to its code and behavior, this malware sample reveals that it doesn't share much relation to the notorious RYUK ransomware. This ransomware is one of the known ransomware that was used in the ongoing geo-political war. This ransomware is capable to check that only one copy of itself is running on the targeted host, delay of execution as part of its defense evasion technique, persistence through registry and startup folder, drop a copy of itself in each root drive of the targeted host and also in %appdata% folder and many more. As of writing this ransomware is still active and keeps on infecting Windows Operating machines and Windows networks.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [CMD Carry Out String Command Parameter](/endpoint/54a6ed00-3256-11ec-b031-acde48001122/) | [Windows Command Shell](/tags/#windows-command-shell), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Common Ransomware Notes](/endpoint/ada0f478-84a8-4641-a3f1-d82362d6bd71/) | [Data Destruction](/tags/#data-destruction) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Deleting Shadow Copies](/endpoint/b89919ed-ee5f-492c-b139-95dbb162039e/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Executables Or Script Creation In Suspicious Path](/endpoint/a7e3f0f0-ae42-11eb-b245-acde48001122/) | [Masquerading](/tags/#masquerading) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Prevent Automatic Repair Mode using Bcdedit](/endpoint/7742aa92-c9d9-11eb-bbfc-acde48001122/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Ransomware Notes bulk creation](/endpoint/eff7919a-8330-11eb-83f8-acde48001122/) | [Data Encrypted for Impact](/tags/#data-encrypted-for-impact) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Registry Keys Used For Persistence](/endpoint/f5f6af30-7aa7-4295-bfe9-07fe87c01a4b/) | [Registry Run Keys / Startup Folder](/tags/#registry-run-keys-/-startup-folder), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Process File Path](/endpoint/9be25988-ad82-11eb-a14f-acde48001122/) | [Create or Modify System Process](/tags/#create-or-modify-system-process) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [WBAdmin Delete System Backups](/endpoint/cd5aed7e-5cea-11eb-ae93-0242ac130002/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Boot or Logon Autostart Execution In Startup Folder](/endpoint/99d157cb-923f-4a00-aee9-1f385412146f/) | [Registry Run Keys / Startup Folder](/tags/#registry-run-keys-/-startup-folder), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Replication Through Removable Media](/endpoint/60df805d-4605-41c8-bbba-57baa6a4eb97/) | [Replication Through Removable Media](/tags/#replication-through-removable-media) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows User Execution Malicious URL Shortcut File](/endpoint/5c7ee6ad-baf4-44fb-b2f0-0cfeddf82dbc/) | [Malicious File](/tags/#malicious-file), [User Execution](/tags/#user-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://blog.qualys.com/vulnerabilities-threat-research/2022/01/17/the-chaos-ransomware-can-be-ravaging](https://blog.qualys.com/vulnerabilities-threat-research/2022/01/17/the-chaos-ransomware-can-be-ravaging)
* [https://www.fortinet.com/blog/threat-research/chaos-ransomware-variant-in-fake-minecraft-alt-list-brings-destruction](https://www.fortinet.com/blog/threat-research/chaos-ransomware-variant-in-fake-minecraft-alt-list-brings-destruction)
* [https://marcoramilli.com/2021/06/14/the-allegedly-ryuk-ransomware-builder-ryukjoke/](https://marcoramilli.com/2021/06/14/the-allegedly-ryuk-ransomware-builder-ryukjoke/)
* [https://www.trendmicro.com/en_us/research/21/h/chaos-ransomware-a-dangerous-proof-of-concept.html](https://www.trendmicro.com/en_us/research/21/h/chaos-ransomware-a-dangerous-proof-of-concept.html)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/chaos_ransomware.yml) \| *version*: **1**