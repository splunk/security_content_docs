---
title: "BlackMatter Ransomware"
last_modified_at: 2021-09-06
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

Leverage searches that allow you to detect and investigate unusual activities that might relate to the BlackMatter ransomware, including looking for file writes associated with BlackMatter, force safe mode boot, autadminlogon account registry modification and more.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-09-06
- **Author**: Teoderick Contreras, Splunk
- **ID**: 0da348a3-78a0-412e-ab27-2de9dd7f9fee

#### Narrative

BlackMatter ransomware campaigns targeting healthcare and other vertical sectors, involve the use of ransomware payloads along with exfiltration of data per HHS bulletin. Malicious actors demand payment for ransome of data and threaten deletion and exposure of exfiltrated data.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Add DefaultUser And Password In Registry](/endpoint/d4a3eb62-0f1e-11ec-a971-acde48001122/) | [Credentials in Registry](/tags/#credentials-in-registry), [Unsecured Credentials](/tags/#unsecured-credentials) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Auto Admin Logon Registry Entry](/endpoint/1379d2b8-0f18-11ec-8ca3-acde48001122/) | [Credentials in Registry](/tags/#credentials-in-registry), [Unsecured Credentials](/tags/#unsecured-credentials) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Bcdedit Command Back To Normal Mode Boot](/endpoint/dc7a8004-0f18-11ec-8c54-acde48001122/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Change To Safe Mode With Network Config](/endpoint/81f1dce0-0f18-11ec-a5d7-acde48001122/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Known Services Killed by Ransomware](/endpoint/3070f8e0-c528-11eb-b2a0-acde48001122/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Modification Of Wallpaper](/endpoint/accb0712-c381-11eb-8e5b-acde48001122/) | [Defacement](/tags/#defacement) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Ransomware Notes bulk creation](/endpoint/eff7919a-8330-11eb-83f8-acde48001122/) | [Data Encrypted for Impact](/tags/#data-encrypted-for-impact) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://news.sophos.com/en-us/2021/08/09/blackmatter-ransomware-emerges-from-the-shadow-of-darkside/](https://news.sophos.com/en-us/2021/08/09/blackmatter-ransomware-emerges-from-the-shadow-of-darkside/)
* [https://www.bleepingcomputer.com/news/security/blackmatter-ransomware-gang-rises-from-the-ashes-of-darkside-revil/](https://www.bleepingcomputer.com/news/security/blackmatter-ransomware-gang-rises-from-the-ashes-of-darkside-revil/)
* [https://blog.malwarebytes.com/ransomware/2021/07/blackmatter-a-new-ransomware-group-claims-link-to-darkside-revil/](https://blog.malwarebytes.com/ransomware/2021/07/blackmatter-a-new-ransomware-group-claims-link-to-darkside-revil/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/blackmatter_ransomware.yml) \| *version*: **1**