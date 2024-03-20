---
title: "CrowdStrike OAuth API Dynamic Analysis"
last_modified_at: 2023-03-23
toc: true
toc_label: ""
tags:
  - Investigation
  - Splunk SOAR
  - CrowdStrike OAuth API
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

Accepts url link, domain or vault_id (hash) to be detonated using CrowdStrike OAuth API connector. This playbook produces a normalized output for each user and device.

- **Type**: Investigation
- **Product**: Splunk SOAR
- **Apps**: [CrowdStrike OAuth API](https://splunkbase.splunk.com/apps?keyword=crowdstrike+oauth+api&filters=product%3Asoar)
- **Last Updated**: 2023-03-23
- **Author**: Teoderick Contreras, Splunk
- **ID**: 5299d9dc-e9d5-41fb-b051-92ace0ff816d
- **Use-cases**:
  - Enrichment
  - Phishing
  - Endpoint

#### Associated Detections


#### How To Implement
This input playbook requires the Crowdstrike OAuth API connector to be configured. It is designed to work in conjunction with the Dynamic Attribute Lookup playbook or other playbooks in the same style.


#### [D3FEND](https://d3fend.mitre.org/)

| ID          | Technique   | Definition     | Category       |
| ----------- | ----------- | -------------- | -------------- |
| D3-DA | [Dynamic Analysis](https://d3fend.mitre.org/technique/d3f:DynamicAnalysis) | Executing or opening a file in a synthetic &#34;sandbox&#34; environment to determine if the file is a malicious program or if the file exploits another program such as a document reader. | File Analysis |

#### [Explore Playbook](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/CrowdStrike_OAuth_API_Dynamic_Analysis.json){: .btn .btn--info}

[![explore](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/CrowdStrike_OAuth_API_Dynamic_Analysis.png){:height="500px" width="500px"}](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/CrowdStrike_OAuth_API_Dynamic_Analysis.json)

#### Required field


#### Reference



[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/CrowdStrike_OAuth_API_Dynamic_Analysis.yml) \| *version*: **1**