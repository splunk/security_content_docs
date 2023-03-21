---
title: "Double Zero Destructor"
last_modified_at: 2022-03-25
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

Double Zero Destructor is a destructive payload that enumerates Domain Controllers and executes killswitch if detected. Overwrites files with Zero blocks or using MS Windows API calls such as NtFileOpen, NtFSControlFile. This payload also deletes registry hives HKCU,HKLM, HKU, HKLM BCD.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-03-25
- **Author**: Teoderick Contreras, Rod Soto, Splunk
- **ID**: f56e8c00-3224-4955-9a6e-924ec7da1df7

#### Narrative

Double zero destructor enumerates domain controllers, delete registry hives and overwrites files using zero blocks and API calls.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Executables Or Script Creation In Suspicious Path](/endpoint/a7e3f0f0-ae42-11eb-b245-acde48001122/) | [Masquerading](/tags/#masquerading) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Process File Path](/endpoint/9be25988-ad82-11eb-a14f-acde48001122/) | [Create or Modify System Process](/tags/#create-or-modify-system-process) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Deleted Registry By A Non Critical Process File Path](/endpoint/15e70689-f55b-489e-8a80-6d0cd6d8aad2/) | [Modify Registry](/tags/#modify-registry) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Terminating Lsass Process](/endpoint/7ab3c319-a4e7-4211-9e8c-40a049d0dba6/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://cert.gov.ua/article/38088](https://cert.gov.ua/article/38088)
* [https://blog.talosintelligence.com/2022/03/threat-advisory-doublezero.html](https://blog.talosintelligence.com/2022/03/threat-advisory-doublezero.html)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/double_zero_destructor.yml) \| *version*: **1**