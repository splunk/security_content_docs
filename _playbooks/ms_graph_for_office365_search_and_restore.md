---
title: "MS Graph for Office365 Search and Restore"
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

Accepts an Internet Message ID and an email mailbox, searches for the Message ID&#39;s presence in each mailbox&#39;s recoverable deleted items, and then restores the ones it finds.

- **Type**: Response
- **Product**: Splunk SOAR
- **Apps**: [MS Graph for Office 365](https://splunkbase.splunk.com/apps?keyword=ms+graph+for+office+365&filters=product%3Asoar)
- **Last Updated**: 2024-02-15
- **Author**: Lou Stella, Splunk
- **ID**: 511236ad-a8c4-47ed-b631-928ab1dff71a
- **Use-cases**:
  - Phishing

#### Associated Detections


#### How To Implement
This input playbook requires the MS Graph for Office365 connector to be configured.  Careful attention should be paid to the documentation for this connector&#39;s required permissions.


#### [D3FEND](https://d3fend.mitre.org/)

| ID          | Technique   | Definition     | Category       |
| ----------- | ----------- | -------------- | -------------- |
| D3-RE | [Restore Email](https://d3fend.mitre.org/technique/d3f:RestoreEmail) | Restoring a file for an entity to access. | Restore Object |

#### [Explore Playbook](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/MS_Graph_for_Office_365_Search_and_Restore.json){: .btn .btn--info}

[![explore](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/MS_Graph_for_Office_365_Search_and_Restore.png){:height="500px" width="500px"}](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/MS_Graph_for_Office_365_Search_and_Restore.json)

#### Required field


#### Reference



[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/MS_Graph_for_Office_365_Search_and_Restore.yml) \| *version*: **1**