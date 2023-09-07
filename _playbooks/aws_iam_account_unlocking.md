---
title: "AWS IAM Account Unlocking"
last_modified_at: 2023-6-21
toc: true
toc_label: ""
tags:
  - Response
  - Splunk SOAR
  - AWS IAM
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

Accepts user, to be enabled using AWS IAM connector. Enabling an account involves reattaching their login profile which will require setting a new password. This playbook produces a normalized observables output for each user. 

- **Type**: Response
- **Product**: Splunk SOAR
- **Apps**: [AWS IAM](https://splunkbase.splunk.com/apps?keyword=aws+iam&filters=product%3Asoar)
- **Last Updated**: 2023-6-21
- **Author**: Lou Stella, Splunk
- **ID**: f15a4db3-b157-4225-86ae-c36ab78b50f2
- **Use-cases**:

#### Associated Detections


#### How To Implement
This input playbook requires the AWS IAM connector to be configured.


#### [Explore Playbook](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/AWS_IAM_Account_Unlocking.json){: .btn .btn--info}

[![explore](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/AWS_IAM_Account_Unlocking.png){:height="500px" width="500px"}](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/AWS_IAM_Account_Unlocking.json)

#### Required field


#### Reference



[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/AWS_IAM_Account_Unlocking.yml) \| *version*: **1**