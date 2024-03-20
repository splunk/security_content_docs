---
title: "MS Graph for Office365 Search and Purge"
last_modified_at: 2024-02-03
toc: true
toc_label: ""
tags:
  - Response
  - Splunk SOAR
  - MS Graph for Office 365
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

Accepts an Internet Message ID, searches for its presence in each mailbox in the tenant, and then deletes the ones it finds. Microsoft does have a &#34;soft-delete&#34; option, messages run through the Message Eviction playbook will be recoverable.

- **Type**: Response
- **Product**: Splunk SOAR
- **Apps**: [MS Graph for Office 365](https://splunkbase.splunk.com/apps?keyword=ms+graph+for+office+365&filters=product%3Asoar)
- **Last Updated**: 2024-02-03
- **Author**: Lou Stella, Splunk
- **ID**: 5112d6ad-a8c4-47ed-b831-928ac1dff716
- **Use-cases**:
  - Phishing

#### Associated Detections


#### How To Implement
This input playbook requires the MS Graph for Office365 connector to be configured.  Careful attention should be paid to the documentation for this connector&#39;s required permissions.


#### [D3FEND](https://d3fend.mitre.org/)

| ID          | Technique   | Definition     | Category       |
| ----------- | ----------- | -------------- | -------------- |
| D3-ER | [Email Removal](https://d3fend.mitre.org/technique/d3f:EmailRemoval) | The file removal technique deletes malicious artifacts or programs from a computer system. | File Eviction |

| D3-IAA | [Identifier Activity Analysis](https://d3fend.mitre.org/technique/d3f:IdentifierActivityAnalysis) | Taking known malicious identifiers and determining if they are present in a system. | Identifier Analysis |

#### [Explore Playbook](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/MS_Graph_for_Office_365_Search_and_Purge.json){: .btn .btn--info}

[![explore](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/MS_Graph_for_Office_365_Search_and_Purge.png){:height="500px" width="500px"}](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/MS_Graph_for_Office_365_Search_and_Purge.json)

#### Required field


#### Reference



[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/MS_Graph_for_Office_365_Search_and_Purge.yml) \| *version*: **1**