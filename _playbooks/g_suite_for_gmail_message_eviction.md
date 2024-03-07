---
title: "G Suite for Gmail Message Eviction"
last_modified_at: 2024-01-21
toc: true
toc_label: ""
tags:
  - Response
  - Splunk SOAR
  - G Suite for GMail
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

Accepts a gmail email ID, and then attempts to delete the email from the mailbox. GMail does not have a &#34;soft-delete&#34; option, messages run through the Message Eviction playbook will be permanently deleted.

- **Type**: Response
- **Product**: Splunk SOAR
- **Apps**: [G Suite for GMail](https://splunkbase.splunk.com/apps?keyword=g+suite+for+gmail&filters=product%3Asoar)
- **Last Updated**: 2024-01-21
- **Author**: Lou Stella, Splunk
- **ID**: 5299d3ad-e9c4-4afa-b051-92cacd0ff916
- **Use-cases**:
  - Phishing

#### Associated Detections


#### How To Implement
This input playbook requires the G Suite for GMail connector to be configured. It is designed to work in environments that posess a maximum of 500 mailboxes at this time, due to a limitation in the G Suite for GMail connector.


#### [D3FEND](https://d3fend.mitre.org/)

| ID          | Technique   | Definition     | Category       |
| ----------- | ----------- |--------------- |--------------- |
| D3-ER | [](https://d3fend.mitre.org/technique/d3f:) |  |  |

#### [Explore Playbook](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/G_Suite_for_Gmail_Message_Eviction.json){: .btn .btn--info}

[![explore](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/G_Suite_for_Gmail_Message_Eviction.png){:height="500px" width="500px"}](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/G_Suite_for_Gmail_Message_Eviction.json)

#### Required field


#### Reference



[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/G_Suite_for_Gmail_Message_Eviction.yml) \| *version*: **1**