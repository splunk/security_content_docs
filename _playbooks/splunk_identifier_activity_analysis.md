---
title: "Splunk Identifier Activity Analysis"
last_modified_at: 2023-03-31
toc: true
toc_label: ""
tags:
  - Investigation
  - Splunk SOAR
  - Splunk
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

Accepts a file_hash, domain, IP address, or URL, and asks Splunk for a list of devices that have interacted with each. It then produces a normalized output and summary table.

- **Type**: Investigation
- **Product**: Splunk SOAR
- **Apps**: [Splunk](https://splunkbase.splunk.com/apps?keyword=splunk&filters=product%3Asoar)
- **Last Updated**: 2023-03-31
- **Author**: Lou Stella, Splunk; Kelby Shelton, Splunk
- **ID**: 5299b9dc-e8c4-46ba-d942-92ace0ff816d
- **Use-cases**:
  - Enrichment

#### Associated Detections


#### How To Implement
This input playbook requires the Splunk connector to be configured. It is designed to work in conjunction with the Dynamic Identifier Activity Analysis playbook or other playbooks in the same style.


#### [D3FEND](https://d3fend.mitre.org/)

| ID          | Technique   | Definition     | Category       |
| ----------- | ----------- |--------------- |--------------- |
| D3-IAA | [Identifier Activity Analysis](https://d3fend.mitre.org/technique/d3f:IdentifierActivityAnalysis) | Taking known malicious identifiers and determining if they are present in a system. | Identifier Analysis |

#### [Explore Playbook](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/Splunk_Identifier_Activity_Analysis.json){: .btn .btn--info}

[![explore](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/Splunk_Identifier_Activity_Analysis.png){:height="500px" width="500px"}](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/Splunk_Identifier_Activity_Analysis.json)

#### Required field


#### Reference



[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/Splunk_Identifier_Activity_Analysis.yml) \| *version*: **1**