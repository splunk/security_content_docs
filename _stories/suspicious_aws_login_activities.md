---
title: "Suspicious AWS Login Activities"
last_modified_at: 2019-05-01
toc: true
toc_label: ""
tags:
  - Splunk Security Analytics for AWS
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Authentication
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Monitor your AWS authentication events using your CloudTrail logs. Searches within this Analytic Story will help you stay aware of and investigate suspicious logins. 

- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Authentication](https://docs.splunk.com/Documentation/CIM/latest/User/Authentication)
- **Last Updated**: 2019-05-01
- **Author**: Bhavin Patel, Splunk
- **ID**: 2e8948a5-5239-406b-b56b-6c59f1268af3

#### Narrative

It is important to monitor and control who has access to your AWS infrastructure. Detecting suspicious logins to your AWS infrastructure will provide good starting points for investigations. Abusive behaviors caused by compromised credentials can lead to direct monetary costs, as you will be billed for any EC2 instances created by the attacker.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [AWS Successful Console Authentication From Multiple IPs](/cloud/395e50e1-2b87-4fa3-8632-0dfbdcbcd2cb/) | [Compromise Accounts](/tags/#compromise-accounts), [Unused/Unsupported Cloud Regions](/tags/#unused/unsupported-cloud-regions) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect AWS Console Login by User from New City](/cloud/121b0b11-f8ac-4ed6-a132-3800ca4fc07a/) | [Compromise Accounts](/tags/#compromise-accounts), [Cloud Accounts](/tags/#cloud-accounts), [Unused/Unsupported Cloud Regions](/tags/#unused/unsupported-cloud-regions) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect AWS Console Login by User from New Country](/cloud/67bd3def-c41c-4bf6-837b-ae196b4257c6/) | [Compromise Accounts](/tags/#compromise-accounts), [Cloud Accounts](/tags/#cloud-accounts), [Unused/Unsupported Cloud Regions](/tags/#unused/unsupported-cloud-regions) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect AWS Console Login by User from New Region](/cloud/9f31aa8e-e37c-46bc-bce1-8b3be646d026/) | [Compromise Accounts](/tags/#compromise-accounts), [Cloud Accounts](/tags/#cloud-accounts), [Unused/Unsupported Cloud Regions](/tags/#unused/unsupported-cloud-regions) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect new user AWS Console Login](/deprecated/ada0f478-84a8-4641-a3f3-d82362dffd75/) | [Cloud Accounts](/tags/#cloud-accounts) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html](https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/suspicious_aws_login_activities.yml) \| *version*: **1**