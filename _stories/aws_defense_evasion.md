---
title: "AWS Defense Evasion"
last_modified_at: 2022-07-15
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Web
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Identify activity and techniques associated with the Evasion of Defenses within AWS, such as Disabling CloudTrail, Deleting CloudTrail and many others.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Web](https://docs.splunk.com/Documentation/CIM/latest/User/Web)
- **Last Updated**: 2022-07-15
- **Author**: Gowthamaraj Rajendran, Splunk
- **ID**: 4e00b690-293f-434d-a9d8-bcfb2ea5fff9

#### Narrative

Adversaries employ a variety of techniques in order to avoid detection and operate without barriers. This often involves modifying the configuration of security monitoring tools to get around them or explicitly disabling them to prevent them from running. This Analytic Story includes analytics that identify activity consistent with adversaries attempting to disable various security mechanisms on AWS. Such activity may involve deleting the CloudTrail logs , as this is where all the AWS logs get stored or explicitly changing the retention policy of S3 buckets. Other times, adversaries attempt deletion of a specified AWS CloudWatch log group.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [AWS Defense Evasion Delete CloudWatch Log Group](/cloud/d308b0f1-edb7-4a62-a614-af321160710f/) | [Impair Defenses](/tags/#impair-defenses), [Disable Cloud Logs](/tags/#disable-cloud-logs) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [AWS Defense Evasion Delete Cloudtrail](/cloud/82092925-9ca1-4e06-98b8-85a2d3889552/) | [Disable Cloud Logs](/tags/#disable-cloud-logs), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [AWS Defense Evasion Impair Security Services](/cloud/b28c4957-96a6-47e0-a965-6c767aac1458/) | [Disable Cloud Logs](/tags/#disable-cloud-logs), [Impair Defenses](/tags/#impair-defenses) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [AWS Defense Evasion PutBucketLifecycle](/cloud/ce1c0e2b-9303-4903-818b-0d9002fc6ea4/) | [Disable Cloud Logs](/tags/#disable-cloud-logs), [Impair Defenses](/tags/#impair-defenses) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [AWS Defense Evasion Stop Logging Cloudtrail](/cloud/8a2f3ca2-4eb5-4389-a549-14063882e537/) | [Disable Cloud Logs](/tags/#disable-cloud-logs), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [AWS Defense Evasion Update Cloudtrail](/cloud/7c921d28-ef48-4f1b-85b3-0af8af7697db/) | [Impair Defenses](/tags/#impair-defenses), [Disable Cloud Logs](/tags/#disable-cloud-logs) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://attack.mitre.org/tactics/TA0005/](https://attack.mitre.org/tactics/TA0005/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/aws_defense_evasion.yml) \| *version*: **1**