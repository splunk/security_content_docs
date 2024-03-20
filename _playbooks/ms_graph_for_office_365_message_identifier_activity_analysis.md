---
title: "MS Graph for Office 365 Message Identifier Activity Analysis"
last_modified_at: 2024-02-03
toc: true
toc_label: ""
tags:
  - Investigation
  - Splunk SOAR
  - MS Graph for Office 365
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

Accepts an internet message id, and asks Microsoft for a list of users with mailboxes to search, and then searches each one to look for records that have a matching internet message id.  It then produces a normalized output and summary table.

- **Type**: Investigation
- **Product**: Splunk SOAR
- **Apps**: [MS Graph for Office 365](https://splunkbase.splunk.com/apps?keyword=ms+graph+for+office+365&filters=product%3Asoar)
- **Last Updated**: 2024-02-03
- **Author**: Lou Stella, Splunk
- **ID**: 5292d6ad-e9c4-4bfd-b831-928ac1dff816
- **Use-cases**:
  - Phishing

#### Associated Detections


#### How To Implement
This input playbook requires the MS Graph for Office 365 connector to be configured.


#### [D3FEND](https://d3fend.mitre.org/)

| ID          | Technique   | Definition     | Category       |
| ----------- | ----------- | -------------- | -------------- |
| D3-IAA | [Identifier Activity Analysis](https://d3fend.mitre.org/technique/d3f:IdentifierActivityAnalysis) | Taking known malicious identifiers and determining if they are present in a system. | Identifier Analysis |

#### [Explore Playbook](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/MS_Graph_for_Office_365_Message_Identifier_Activity_Analysis.json){: .btn .btn--info}

[![explore](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/MS_Graph_for_Office_365_Message_Identifier_Activity_Analysis.png){:height="500px" width="500px"}](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/MS_Graph_for_Office_365_Message_Identifier_Activity_Analysis.json)

#### Required field


#### Reference



[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/MS_Graph_for_Office_365_Message_Identifier_Activity_Analysis.yml) \| *version*: **1**