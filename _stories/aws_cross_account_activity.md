---
title: "AWS Cross Account Activity"
last_modified_at: 2018-06-04
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Track when a user assumes an IAM role in another AWS account to obtain cross-account access to services and resources in that account. Accessing new roles could be an indication of malicious activity.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2018-06-04
- **Author**: David Dorsey, Splunk
- **ID**: 2f2f610a-d64d-48c2-b57c-967a2b49ab5a

#### Narrative

Amazon Web Services (AWS) admins manage access to AWS resources and services across the enterprise using AWS's Identity and Access Management (IAM) functionality. IAM provides the ability to create and manage AWS users, groups, and roles-each with their own unique set of privileges and defined access to specific resources (such as EC2 instances, the AWS Management Console, API, or the command-line interface). Unlike conventional (human) users, IAM roles are assumable by anyone in the organization. They provide users with dynamically created temporary security credentials that expire within a set time period.\
Herein lies the rub. In between the time between when the temporary credentials are issued and when they expire is a period of opportunity, where a user could leverage the temporary credentials to wreak havoc-spin up or remove instances, create new users, elevate privileges, and other malicious activities-throughout the environment.\
This Analytic Story includes searches that will help you monitor your AWS CloudTrail logs for evidence of suspicious cross-account activity.  For example, while accessing multiple AWS accounts and roles may be perfectly valid behavior, it may be suspicious when an account requests privileges of an account it has not accessed in the past. After identifying suspicious activities, you can use the provided investigative searches to help you probe more deeply.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [aws detect attach to role policy](/cloud/88fc31dd-f331-448c-9856-d3d51dd5d3a1/) | [Valid Accounts](/tags/#valid-accounts) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [aws detect permanent key creation](/cloud/12d6d713-3cb4-4ffc-a064-1dca3d1cca01/) | [Valid Accounts](/tags/#valid-accounts) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [aws detect role creation](/cloud/5f04081e-ddee-4353-afe4-504f288de9ad/) | [Valid Accounts](/tags/#valid-accounts) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [aws detect sts assume role abuse](/cloud/8e565314-b6a2-46d8-9f05-1a34a176a662/) | [Valid Accounts](/tags/#valid-accounts) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [aws detect sts get session token abuse](/cloud/85d7b35f-b8b5-4b01-916f-29b81e7a0551/) | [Use Alternate Authentication Material](/tags/#use-alternate-authentication-material) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://aws.amazon.com/blogs/security/aws-cloudtrail-now-tracks-cross-account-activity-to-its-origin/](https://aws.amazon.com/blogs/security/aws-cloudtrail-now-tracks-cross-account-activity-to-its-origin/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/aws_cross_account_activity.yml) \| *version*: **1**