---
title: "Windows Defender ATP Identifier Activity Analysis"
last_modified_at: 2023-03-30
toc: true
toc_label: ""
tags:
  - Investigation
  - Splunk SOAR
  - Windows Defender ATP
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

Accepts a file_hash or domain name, and asks Windows Defender ATP for a list of devices that have interacted with each. It then produces a normalized output and summary table.

- **Type**: Investigation
- **Product**: Splunk SOAR
- **Apps**: [Windows Defender ATP](https://splunkbase.splunk.com/apps/#/search/Windows Defender ATP/product/soar)
- **Last Updated**: 2023-03-30
- **Author**: Lou Stella, Splunk
- **ID**: 5299d9dc-e9c4-46fa-da42-92ace0ff816d

#### Associated Detections


#### How To Implement
This input playbook requires the Windows Defender ATP connector to be configured. It is designed to work in conjunction with the Dynamic Identifier Activity Analysis playbook or other playbooks in the same style.


#### [Explore Playbook](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/Windows_Defender_ATP_Identifier_Activity_Analysis.json){: .btn .btn--info}

[![explore](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/Windows_Defender_ATP_Identifier_Activity_Analysis.png){:height="500px" width="500px"}](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/Windows_Defender_ATP_Identifier_Activity_Analysis.json)

#### Required field


#### Reference



[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/Windows_Defender_ATP_Identifier_Activity_Analysis.yml) \| *version*: **1**