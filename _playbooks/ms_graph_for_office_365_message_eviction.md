---
title: "MS Graph for Office 365 Message Eviction"
last_modified_at: 2024-01-21
toc: true
toc_label: ""
tags:
  - Response
  - Splunk SOAR
  - MS Graph for Office 365
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

Accepts message ID that needs to be evicted from provided email mailbox in Microsoft Office365. Generates an observable output based on the status of message eviction.

- **Type**: Response
- **Product**: Splunk SOAR
- **Apps**: [MS Graph for Office 365](https://splunkbase.splunk.com/apps?keyword=ms+graph+for+office+365&filters=product%3Asoar)
- **Last Updated**: 2024-01-21
- **Author**: Lou Stella, Splunk
- **ID**: 5299d6dd-e9c4-4bfd-b031-928acd1ff816
- **Use-cases**:
  - Phishing

#### Associated Detections


#### How To Implement
This input playbook requires the MS Graph for Office 365 connector to be configured.


#### [D3FEND](https://d3fend.mitre.org/)

| ID          | Technique   | Definition     | Category       |
| ----------- | ----------- | -------------- | -------------- |
| D3-ER | [Email Removal](https://d3fend.mitre.org/technique/d3f:EmailRemoval) | The file removal technique deletes malicious artifacts or programs from a computer system. | File Eviction |

#### [Explore Playbook](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/MS_Graph_for_Office_365_Message_Eviction.json){: .btn .btn--info}

[![explore](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/MS_Graph_for_Office_365_Message_Eviction.png){:height="500px" width="500px"}](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/MS_Graph_for_Office_365_Message_Eviction.json)

#### Required field


#### Reference



[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/MS_Graph_for_Office_365_Message_Eviction.yml) \| *version*: **1**