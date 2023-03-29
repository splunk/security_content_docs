---
title: "SAA Dynamic Analysis"
last_modified_at: 2023-03-24
toc: true
toc_label: ""
tags:
  - Investigation
  - Splunk SOAR
  - CrowdStrike OAuth API
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

Accepts url link, domain or vault_id (hash) to be detonated using Splunk Attacker (SAA) API connector. This playbook produces a normalized output for each user and device.

- **Type**: Investigation
- **Product**: Splunk SOAR
- **Apps**: [CrowdStrike OAuth API](https://splunkbase.splunk.com/apps/#/search/CrowdStrike OAuth API/product/soar)
- **Last Updated**: 2023-03-24
- **Author**: Teoderick Contreras, Splunk
- **ID**: 2754c122-c63b-4558-9b83-23c1e1b96177

#### Associated Detections


#### How To Implement
This input playbook requires the SAA API connector to be configured. It is designed to work in conjunction with the Dynamic Attribute Lookup playbook or other playbooks in the same style.


#### [Explore Playbook](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/SAA_Dynamic_Analysis.json){: .btn .btn--info}

[![explore](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/SAA_Dynamic_Analysis.png){:height="500px" width="500px"}](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/SAA_Dynamic_Analysis.json)

#### Required field


#### Reference



[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/SAA_Dynamic_Analysis.yml) \| *version*: **1**