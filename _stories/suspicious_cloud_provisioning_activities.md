---
title: "Suspicious Cloud Provisioning Activities"
last_modified_at: 2018-08-20
toc: true
toc_label: ""
tags:
  - Splunk Security Analytics for AWS
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Change
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Monitor your cloud infrastructure provisioning activities for behaviors originating from unfamiliar or unusual locations. These behaviors may indicate that malicious activities are occurring somewhere within your cloud environment.

- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Change](https://docs.splunk.com/Documentation/CIM/latest/User/Change)
- **Last Updated**: 2018-08-20
- **Author**: David Dorsey, Splunk
- **ID**: 51045ded-1575-4ba6-aef7-af6c73cffd86

#### Narrative

Because most enterprise cloud infrastructure activities originate from familiar geographic locations, monitoring for activity from unknown or unusual regions is an important security measure. This indicator can be especially useful in environments where it is impossible to add specific IPs to an allow list because they vary.\
This Analytic Story was designed to provide you with flexibility in the precision you employ in specifying legitimate geographic regions. It can be as specific as an IP address or a city, or as broad as a region (think state) or an entire country. By determining how precise you want your geographical locations to be and monitoring for new locations that haven't previously accessed your environment, you can detect adversaries as they begin to probe your environment. Since there are legitimate reasons for activities from unfamiliar locations, this is not a standalone indicator. Nevertheless, location can be a relevant piece of information that you may wish to investigate further.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Cloud Provisioning Activity From Previously Unseen City](/cloud/e7ecc5e0-88df-48b9-91af-51104c68f02f/) | [Valid Accounts](/tags/#valid-accounts) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Cloud Provisioning Activity From Previously Unseen Country](/cloud/94994255-3acf-4213-9b3f-0494df03bb31/) | [Valid Accounts](/tags/#valid-accounts) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Cloud Provisioning Activity From Previously Unseen IP Address](/cloud/f86a8ec9-b042-45eb-92f4-e9ed1d781078/) | [Valid Accounts](/tags/#valid-accounts) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Cloud Provisioning Activity From Previously Unseen Region](/cloud/5aba1860-9617-4af9-b19d-aecac16fe4f2/) | [Valid Accounts](/tags/#valid-accounts) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf](https://d0.awsstatic.com/whitepapers/aws-security-best-practices.pdf)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/suspicious_cloud_provisioning_activities.yml) \| *version*: **1**