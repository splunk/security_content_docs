---
title: "Azure AD Account Locking"
last_modified_at: 2023-05-08
toc: true
toc_label: ""
tags:
  - Investigation
  - Splunk SOAR
  - Azure AD Graph
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

Accepts user, to be disabled using Azure AD Graph connector. This playbook produces a normalized observables output for each user and device.

- **Type**: Investigation
- **Product**: Splunk SOAR
- **Apps**: [Azure AD Graph](https://splunkbase.splunk.com/apps?keyword=azure+ad+graph&filters=product%3Asoar)
- **Last Updated**: 2023-05-08
- **Author**: Teoderick Contreras, Splunk
- **ID**: c3c0157d-7da0-46cb-8b97-327ee92f591c
- **Use-cases**:
  - Phishing
  - Endpoint

#### Associated Detections


#### How To Implement
This input playbook requires the Azure AD Graph connector to be configured. It is designed to work in conjunction with the Dynamic Attribute Lookup playbook or other playbooks in the same style.


#### [D3FEND](https://d3fend.mitre.org/)

| ID          | Technique   | Definition     | Category       |
| ----------- | ----------- | -------------- | -------------- |
| D3-AL | [Account Locking](https://d3fend.mitre.org/technique/d3f:AccountLocking) | The process of temporarily disabling user accounts on a system or domain. | Credential Eviction |

#### [Explore Playbook](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/Azure_AD_Account_Locking.json){: .btn .btn--info}

[![explore](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/Azure_AD_Account_Locking.png){:height="500px" width="500px"}](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/Azure_AD_Account_Locking.json)

#### Required field


#### Reference



[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/Azure_AD_Account_Locking.yml) \| *version*: **1**