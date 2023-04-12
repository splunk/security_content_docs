---
title: "Swift Slicer"
last_modified_at: 2023-02-01
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

Leverage searches that allow you to detect and investigate unusual activities that might relate to the swift slicer malware including overwriting of files and etc.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2023-02-01
- **Author**: Teoderick Contreras, Rod Soto, Splunk
- **ID**: 234c9dd7-52fb-4d6f-aec9-075ef88a2cea

#### Narrative

Swift Slicer is one of Windows destructive malware found by ESET that was used in a targeted organizarion to wipe critical files like windows drivers and other files to destroy and left the machine inoperable. This malware like Caddy Wiper was deliver through GPO which suggests that the attacker had taken control of the victims active directory environment.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Executables Or Script Creation In Suspicious Path](/endpoint/a7e3f0f0-ae42-11eb-b245-acde48001122/) | [Masquerading](/tags/#masquerading) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Process File Path](/endpoint/9be25988-ad82-11eb-a14f-acde48001122/) | [Create or Modify System Process](/tags/#create-or-modify-system-process) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Data Destruction Recursive Exec Files Deletion](/endpoint/3596a799-6320-4a2f-8772-a9e98ddb2960/) | [Data Destruction](/tags/#data-destruction) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows High File Deletion Frequency](/endpoint/45b125c4-866f-11eb-a95a-acde48001122/) | [Data Destruction](/tags/#data-destruction) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://twitter.com/ESETresearch/status/1618960022150729728](https://twitter.com/ESETresearch/status/1618960022150729728)
* [https://www.welivesecurity.com/2023/01/27/swiftslicer-new-destructive-wiper-malware-ukraine/](https://www.welivesecurity.com/2023/01/27/swiftslicer-new-destructive-wiper-malware-ukraine/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/swift_slicer.yml) \| *version*: **1**