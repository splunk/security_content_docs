---
title: "AWS Network ACL Activity"
last_modified_at: 2018-05-21
toc: true
toc_label: ""
tags:
  - Splunk Security Analytics for AWS
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Monitor your AWS network infrastructure for bad configurations and malicious activity. Investigative searches help you probe deeper, when the facts warrant it.

- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2018-05-21
- **Author**: Bhavin Patel, Splunk
- **ID**: 2e8948a5-5239-406b-b56b-6c50ff268af4

#### Narrative

AWS CloudTrail is an AWS service that helps you enable governance, compliance, and operational/risk auditing of your AWS account. Actions taken by a user, role, or an AWS service are recorded as events in CloudTrail. It is crucial for a company to monitor events and actions taken in the AWS Management Console, AWS Command Line Interface, and AWS SDKs and APIs to ensure that your servers are not vulnerable to attacks. This analytic story contains detection searches that leverage CloudTrail logs from AWS to check for bad configurations and malicious activity in your AWS network access controls.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [AWS Network Access Control List Created with All Open Ports](/cloud/ada0f478-84a8-4641-a3f1-d82362d6bd75/) | [Disable or Modify Cloud Firewall](/tags/#disable-or-modify-cloud-firewall), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [AWS Network Access Control List Deleted](/cloud/ada0f478-84a8-4641-a3f1-d82362d6fd75/) | [Disable or Modify Cloud Firewall](/tags/#disable-or-modify-cloud-firewall), [Impair Defenses](/tags/#impair-defenses) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Spike in Network ACL Activity](/deprecated/ada0f478-84a8-4641-a1f1-e32372d4bd53/) | [Disable or Modify Cloud Firewall](/tags/#disable-or-modify-cloud-firewall) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Spike in blocked Outbound Traffic from your AWS](/cloud/d3fffa37-492f-487b-a35d-c60fcb2acf01/) |  | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Appendix_NACLs.html](https://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Appendix_NACLs.html)
* [https://aws.amazon.com/blogs/security/how-to-help-prepare-for-ddos-attacks-by-reducing-your-attack-surface/](https://aws.amazon.com/blogs/security/how-to-help-prepare-for-ddos-attacks-by-reducing-your-attack-surface/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/aws_network_acl_activity.yml) \| *version*: **2**