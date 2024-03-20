---
title: "MS Graph for Office 365 Message Restore"
last_modified_at: 2024-02-15
toc: true
toc_label: ""
tags:
  - Response
  - Splunk SOAR
  - MS Graph for Office 365
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

Accepts message ID that needs to be restored to the provided email mailbox in Microsoft Office365. Generates an observable output based on the status of message restoration.

- **Type**: Response
- **Product**: Splunk SOAR
- **Apps**: [MS Graph for Office 365](https://splunkbase.splunk.com/apps?keyword=ms+graph+for+office+365&filters=product%3Asoar)
- **Last Updated**: 2024-02-15
- **Author**: Lou Stella, Splunk
- **ID**: 5299d6dd-e9c4-4bad-b041-928ace1ff811
- **Use-cases**:
  - Phishing

#### Associated Detections


#### How To Implement
This input playbook requires the MS Graph for Office 365 connector to be configured.


#### [D3FEND](https://d3fend.mitre.org/)

| ID          | Technique   | Definition     | Category       |
| ----------- | ----------- | -------------- | -------------- |
| D3-RE | [Restore Email](https://d3fend.mitre.org/technique/d3f:RestoreEmail) | Restoring a file for an entity to access. | Restore Object |

#### [Explore Playbook](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/MS_Graph_for_Office_365_Message_Restore.json){: .btn .btn--info}

[![explore](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/MS_Graph_for_Office_365_Message_Restore.png){:height="500px" width="500px"}](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/MS_Graph_for_Office_365_Message_Restore.json)

#### Required field


#### Reference



[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/MS_Graph_for_Office_365_Message_Restore.yml) \| *version*: **1**