---
title: "Suspicious Cloud Authentication Activities"
last_modified_at: 2020-06-04
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

Monitor your cloud authentication events. Searches within this Analytic Story leverage the recent cloud updates to the Authentication data model to help you stay aware of and investigate suspicious login activity. 

- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Authentication](https://docs.splunk.com/Documentation/CIM/latest/User/Authentication)
- **Last Updated**: 2020-06-04
- **Author**: Rico Valdez, Splunk
- **ID**: 6380ebbb-55c5-4fce-b754-01fd565fb73c

#### Narrative

It is important to monitor and control who has access to your cloud infrastructure. Detecting suspicious logins will provide good starting points for investigations. Abusive behaviors caused by compromised credentials can lead to direct monetary costs, as you will be billed for any compute activity whether legitimate or otherwise.\
This Analytic Story has data model versions of cloud searches leveraging Authentication data, including those looking for suspicious login activity, and cross-account activity for AWS.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [AWS Cross Account Activity From Previously Unseen Account](/cloud/21193641-cb96-4a2c-a707-d9b9a7f7792b/) |  | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect AWS Console Login by New User](/cloud/bc91a8cd-35e7-4bb2-6140-e756cc46fd71/) |  | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect AWS Console Login by User from New City](/cloud/121b0b11-f8ac-4ed6-a132-3800ca4fc07a/) | [Unused/Unsupported Cloud Regions](/tags/#unused/unsupported-cloud-regions) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect AWS Console Login by User from New Country](/cloud/67bd3def-c41c-4bf6-837b-ae196b4257c6/) | [Unused/Unsupported Cloud Regions](/tags/#unused/unsupported-cloud-regions) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect AWS Console Login by User from New Region](/cloud/9f31aa8e-e37c-46bc-bce1-8b3be646d026/) | [Unused/Unsupported Cloud Regions](/tags/#unused/unsupported-cloud-regions) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://aws.amazon.com/blogs/security/aws-cloudtrail-now-tracks-cross-account-activity-to-its-origin/](https://aws.amazon.com/blogs/security/aws-cloudtrail-now-tracks-cross-account-activity-to-its-origin/)
* [https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html](https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/suspicious_cloud_authentication_activities.yml) \| *version*: **1**