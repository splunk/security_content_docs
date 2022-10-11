---
title: "AWS IAM Privilege Escalation"
last_modified_at: 2021-03-08
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

This analytic story contains detections that query your AWS Cloudtrail for activities related to privilege escalation.

- **Product**: Splunk Security Analytics for AWS, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2021-03-08
- **Author**: Bhavin Patel, Splunk
- **ID**: ced74200-8465-4bc3-bd2c-22782eec6750

#### Narrative

Amazon Web Services provides a neat feature called Identity and Access Management (IAM) that enables organizations to manage various AWS services and resources in a secure way. All IAM users have roles, groups and policies associated with them which governs and sets permissions to allow a user to access specific restrictions.\
However, if these IAM policies are misconfigured and have specific combinations of weak permissions; it can allow attackers to escalate their privileges and further compromise the organization. Rhino Security Labs have published comprehensive blogs detailing various AWS Escalation methods. By using this as an inspiration, Splunks research team wants to highlight how these attack vectors look in AWS Cloudtrail logs and provide you with detection queries to uncover these potentially malicious events via this Analytic Story. 

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [AWS Create Policy Version to allow all resources](/cloud/2a9b80d3-6340-4345-b5ad-212bf3d0dac4/) | [Cloud Accounts](/tags/#cloud-accounts), [Valid Accounts](/tags/#valid-accounts) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [AWS CreateAccessKey](/cloud/2a9b80d3-6340-4345-11ad-212bf3d0d111/) | [Cloud Account](/tags/#cloud-account), [Create Account](/tags/#create-account) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [AWS CreateLoginProfile](/cloud/2a9b80d3-6340-4345-11ad-212bf444d111/) | [Cloud Account](/tags/#cloud-account), [Create Account](/tags/#create-account) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [AWS IAM Assume Role Policy Brute Force](/cloud/f19e09b0-9308-11eb-b7ec-acde48001122/) | [Cloud Infrastructure Discovery](/tags/#cloud-infrastructure-discovery), [Brute Force](/tags/#brute-force) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [AWS IAM Delete Policy](/cloud/ec3a9362-92fe-11eb-99d0-acde48001122/) | [Account Manipulation](/tags/#account-manipulation) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [AWS IAM Failure Group Deletion](/cloud/723b861a-92eb-11eb-93b8-acde48001122/) | [Account Manipulation](/tags/#account-manipulation) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [AWS IAM Successful Group Deletion](/cloud/e776d06c-9267-11eb-819b-acde48001122/) | [Cloud Groups](/tags/#cloud-groups), [Account Manipulation](/tags/#account-manipulation), [Permission Groups Discovery](/tags/#permission-groups-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [AWS SetDefaultPolicyVersion](/cloud/2a9b80d3-6340-4345-11ad-212bf3d0dac4/) | [Cloud Accounts](/tags/#cloud-accounts), [Valid Accounts](/tags/#valid-accounts) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [AWS UpdateLoginProfile](/cloud/2a9b80d3-6a40-4115-11ad-212bf3d0d111/) | [Cloud Account](/tags/#cloud-account), [Create Account](/tags/#create-account) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)
* [https://www.cyberark.com/resources/threat-research-blog/the-cloud-shadow-admin-threat-10-permissions-to-protect](https://www.cyberark.com/resources/threat-research-blog/the-cloud-shadow-admin-threat-10-permissions-to-protect)
* [https://labs.bishopfox.com/tech-blog/privilege-escalation-in-aws](https://labs.bishopfox.com/tech-blog/privilege-escalation-in-aws)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/aws_iam_privilege_escalation.yml) \| *version*: **1**