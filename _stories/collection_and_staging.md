---
title: "Collection and Staging"
last_modified_at: 2020-02-03
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

Monitor for and investigate activities--such as suspicious writes to the Windows Recycling Bin or email servers sending high amounts of traffic to specific hosts, for example--that may indicate that an adversary is harvesting and exfiltrating sensitive data. 

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic)
- **Last Updated**: 2020-02-03
- **Author**: Rico Valdez, Splunk
- **ID**: 8e03c61e-13c4-4dcd-bfbe-5ce5a8dc031a

#### Narrative

A common adversary goal is to identify and exfiltrate data of value from a target organization. This data may include email conversations and addresses, confidential company information, links to network design/infrastructure, important dates, and so on.\
 Attacks are composed of three activities: identification, collection, and staging data for exfiltration. Identification typically involves scanning systems and observing user activity. Collection can involve the transfer of large amounts of data from various repositories. Staging/preparation includes moving data to a central location and compressing (and optionally encoding and/or encrypting) it. All of these activities provide opportunities for defenders to identify their presence. \
Use the searches to detect and monitor suspicious behavior related to these activities.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Detect Renamed 7-Zip](/endpoint/4057291a-b8cf-11eb-95fe-acde48001122/) | [Archive via Utility](/tags/#archive-via-utility), [Archive Collected Data](/tags/#archive-collected-data) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Renamed WinRAR](/endpoint/1b7bfb2c-b8e6-11eb-99ac-acde48001122/) | [Archive via Utility](/tags/#archive-via-utility), [Archive Collected Data](/tags/#archive-collected-data) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Email files written outside of the Outlook directory](/application/8d52cf03-ba25-4101-aa78-07994aed4f74/) | [Email Collection](/tags/#email-collection), [Local Email Collection](/tags/#local-email-collection) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Email servers sending high volume traffic to hosts](/application/7f5fb3e1-4209-4914-90db-0ec21b556378/) | [Email Collection](/tags/#email-collection), [Remote Email Collection](/tags/#remote-email-collection) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Hosts receiving high volume of network traffic from email server](/network/7f5fb3e1-4209-4914-90db-0ec21b556368/) | [Remote Email Collection](/tags/#remote-email-collection), [Email Collection](/tags/#email-collection) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious writes to System Volume Information](/deprecated/cd6297cd-2bdd-4aa1-84aa-5d2f84228fac/) | [Masquerading](/tags/#masquerading) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious writes to windows Recycle Bin](/endpoint/b5541828-8ffd-4070-9d95-b3da4de924cb/) | [Masquerading](/tags/#masquerading) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://attack.mitre.org/wiki/Collection](https://attack.mitre.org/wiki/Collection)
* [https://attack.mitre.org/wiki/Technique/T1074](https://attack.mitre.org/wiki/Technique/T1074)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/collection_and_staging.yml) \| *version*: **1**