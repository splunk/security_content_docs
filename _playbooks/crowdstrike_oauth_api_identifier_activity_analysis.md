---
title: "CrowdStrike OAuth API Identifier Activity Analysis"
last_modified_at: 2023-03-30
toc: true
toc_label: ""
tags:
  - Investigation
  - Splunk SOAR
  - CrowdStrike OAuth API
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

Accepts a file hash or domain name, and asks CrowdStrike for a list of device IDs that have interacted with each. The list of IDs is then sent back to Crowdstrike to get more information, and then produces a normalized output and summary table.

- **Type**: Investigation
- **Product**: Splunk SOAR
- **Apps**: [CrowdStrike OAuth API](https://splunkbase.splunk.com/apps/#/search/CrowdStrike OAuth API/product/soar)
- **Last Updated**: 2023-03-30
- **Author**: Lou Stella, Splunk
- **ID**: 5299d9dc-e9c4-42fa-b051-92ace0ff816d

#### Associated Detections


#### How To Implement
This input playbook requires the Crowdstrike OAuth API connector to be configured. It is designed to work in conjunction with the Dynamic Identifier Activity Analysis playbook or other playbooks in the same style.


#### [Explore Playbook](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/CrowdStrike_OAuth_API_Identifier_Activity_Analysis.json){: .btn .btn--info}

[![explore](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/CrowdStrike_OAuth_API_Identifier_Activity_Analysis.png){:height="500px" width="500px"}](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/CrowdStrike_OAuth_API_Identifier_Activity_Analysis.json)

#### Required field


#### Reference



[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/CrowdStrike_OAuth_API_Identifier_Activity_Analysis.yml) \| *version*: **1**