---
title: "AWS IAM Account Locking"
last_modified_at: 2023-05-08
toc: true
toc_label: ""
tags:
  - Investigation
  - Splunk SOAR
  - AWS IAM
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

Accepts user name that needs to be disabled in AWS IAM Active Directory. Disabling an account involves deleting their login profile which will clear the user&#39;s password. Generates an observable output based on the status of account locking or disabling.

- **Type**: Investigation
- **Product**: Splunk SOAR
- **Apps**: [AWS IAM](https://splunkbase.splunk.com/apps?keyword=aws+iam&filters=product%3Asoar)
- **Last Updated**: 2023-05-08
- **Author**: Teoderick Contreras, Splunk
- **ID**: f15e4ab7-b057-4225-86ae-c36ab78b50f2
- **Use-cases**:
  - Phishing
  - Endpoint

#### Associated Detections


#### How To Implement
This input playbook requires the AWS IAM connector to be configured. It is designed to work in conjunction with the Dynamic Attribute Lookup playbook or other playbooks in the same style.


#### [D3FEND](https://d3fend.mitre.org/)

| ID          | Technique   | Definition     | Category       |
| ----------- | ----------- | -------------- | -------------- |
| D3-AL | [Account Locking](https://d3fend.mitre.org/technique/d3f:AccountLocking) | The process of temporarily disabling user accounts on a system or domain. | Credential Eviction |

#### [Explore Playbook](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/AWS_IAM_Account_Locking.json){: .btn .btn--info}

[![explore](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/AWS_IAM_Account_Locking.png){:height="500px" width="500px"}](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/AWS_IAM_Account_Locking.json)

#### Required field


#### Reference



[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/AWS_IAM_Account_Locking.yml) \| *version*: **1**