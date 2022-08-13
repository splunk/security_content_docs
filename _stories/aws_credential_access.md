---
title: "AWS Credential Access"
last_modified_at: 2022-08-19
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Authentication
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Identify activity and techniques associated with accessing credential files from AWS resources, monitor unusual authentication related activities to the AWS Console and other services such as RDS.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Authentication](https://docs.splunk.com/Documentation/CIM/latest/User/Authentication)
- **Last Updated**: 2022-08-19
- **Author**: Gowthamaraj Rajendran, Bhavin Patel,  Splunk
- **ID**: 4210b690-293f-411d-a9d8-bcfb2ea5fff9

#### Narrative

Adversaries employ a variety of techniques to steal AWS Cloud credentials like account names, passwords and keys. Usage of legitimate keys will assist the attackers to gain access to other sensitive system and they can also mimic legitimate behaviour making them harder to be detected. Such activity may involve mulitple failed login to the console, new console logins and password reset activities.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [AWS Credential Access Failed Login](/cloud/a19b354d-0d7f-47f3-8ea6-1a7c36434968/) | [Password Guessing](/tags/#password-guessing) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [AWS Credential Access GetPasswordData](/cloud/4d347c4a-306e-41db-8d10-b46baf71b3e2/) | [Unsecured Credentials](/tags/#unsecured-credentials) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [AWS Credential Access RDS Password reset](/cloud/6153c5ea-ed30-4878-81e6-21ecdb198189/) | [Password Cracking](/tags/#password-cracking) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect AWS Console Login by New User](/cloud/bc91a8cd-35e7-4bb2-6140-e756cc46fd71/) |  | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect AWS Console Login by User from New City](/cloud/121b0b11-f8ac-4ed6-a132-3800ca4fc07a/) | [Unused/Unsupported Cloud Regions](/tags/#unused/unsupported-cloud-regions) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect AWS Console Login by User from New Country](/cloud/67bd3def-c41c-4bf6-837b-ae196b4257c6/) | [Unused/Unsupported Cloud Regions](/tags/#unused/unsupported-cloud-regions) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect AWS Console Login by User from New Region](/cloud/9f31aa8e-e37c-46bc-bce1-8b3be646d026/) | [Unused/Unsupported Cloud Regions](/tags/#unused/unsupported-cloud-regions) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/aws_credential_access.yml) \| *version*: **1**