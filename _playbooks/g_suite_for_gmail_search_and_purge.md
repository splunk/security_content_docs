---
title: "G Suite for Gmail Search and Purge"
last_modified_at: 2024-02-19
toc: true
toc_label: ""
tags:
  - Response
  - Splunk SOAR
  - G Suite for GMail
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

Accepts an Internet Message ID, searches for its presence in up to 500 mailboxes, and then deletes the ones it finds. GMail does not have a &#34;soft-delete&#34; option, messages run through the Message Eviction playbook will be permanently deleted.

- **Type**: Response
- **Product**: Splunk SOAR
- **Apps**: [G Suite for GMail](https://splunkbase.splunk.com/apps?keyword=g+suite+for+gmail&filters=product%3Asoar)
- **Last Updated**: 2024-02-19
- **Author**: Lou Stella, Splunk
- **ID**: 5294d3bd-e9c4-4bfa-b051-92cacd0ff925
- **Use-cases**:
  - Phishing

#### Associated Detections


#### How To Implement
This input playbook requires the G Suite for GMail connector to be configured. It is designed to work in environments that posess a maximum of 500 mailboxes at this time, due to a limitation in the G Suite for GMail connector.


#### [D3FEND](https://d3fend.mitre.org/)

| ID          | Technique   | Definition     | Category       |
| ----------- | ----------- | -------------- | -------------- |
| D3-ER | [Email Removal](https://d3fend.mitre.org/technique/d3f:EmailRemoval) | The file removal technique deletes malicious artifacts or programs from a computer system. | File Eviction |

| D3-IAA | [Identifier Activity Analysis](https://d3fend.mitre.org/technique/d3f:IdentifierActivityAnalysis) | Taking known malicious identifiers and determining if they are present in a system. | Identifier Analysis |

#### [Explore Playbook](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/G_Suite_for_Gmail_Search_and_Purge.json){: .btn .btn--info}

[![explore](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/G_Suite_for_Gmail_Search_and_Purge.png){:height="500px" width="500px"}](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/G_Suite_for_Gmail_Search_and_Purge.json)

#### Required field


#### Reference



[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/G_Suite_for_Gmail_Search_and_Purge.yml) \| *version*: **1**