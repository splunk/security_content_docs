---
title: "G Suite for GMail Message Identifier Activity Analysis"
last_modified_at: 2023-05-12
toc: true
toc_label: ""
tags:
  - Investigation
  - Splunk SOAR
  - G Suite for GMail
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

Accepts an internet message id, and asks Gmail for a list of mailboxes to search, and then searches each one to look for records that have a matching internet message id.  It then produces a normalized output and summary table.

- **Type**: Investigation
- **Product**: Splunk SOAR
- **Apps**: [G Suite for GMail](https://splunkbase.splunk.com/apps?keyword=g+suite+for+gmail&filters=product%3Asoar)
- **Last Updated**: 2023-05-12
- **Author**: Lou Stella, Splunk
- **ID**: 5299d6dd-e9c4-4afa-b051-928ace0ff816
- **Use-cases**:
  - Phishing

#### Associated Detections


#### How To Implement
This input playbook requires the G Suite for GMail connector to be configured. It is designed to work in environments that posess a maximum of 500 mailboxes at this time, due to a limitation in the G Suite for GMail connector.


#### [D3FEND](https://d3fend.mitre.org/)

| ID          | Technique   | Definition     | Category       |
| ----------- | ----------- | -------------- | -------------- |
| D3-IAA | [Identifier Activity Analysis](https://d3fend.mitre.org/technique/d3f:IdentifierActivityAnalysis) | Taking known malicious identifiers and determining if they are present in a system. | Identifier Analysis |

#### [Explore Playbook](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/G_Suite_for_GMail_Message_Identifier_Acitivity_Analysis.json){: .btn .btn--info}

[![explore](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/G_Suite_for_GMail_Message_Identifier_Acitivity_Analysis.png){:height="500px" width="500px"}](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/G_Suite_for_GMail_Message_Identifier_Acitivity_Analysis.json)

#### Required field


#### Reference



[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/G_Suite_for_GMail_Message_Identifier_Acitivity_Analysis.yml) \| *version*: **1**