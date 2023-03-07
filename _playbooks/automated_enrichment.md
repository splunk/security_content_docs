---
title: "Automated Enrichment"
last_modified_at: 2023-03-06
toc: true
toc_label: ""
tags:
  - Investigation
  - Splunk SOAR
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

Moves the event status to open and then launches the Dynamic playbooks for Reputation Analysis, Attribute Lookup, and Related Tickets.

- **Type**: Investigation
- **Product**: Splunk SOAR
- **Apps**: 
- **Last Updated**: 2023-03-06
- **Author**: Kelby Shelton, Patrick Bareiss, Teoderick Contreras, Lou Stella Splunk
- **ID**: fc0edc96-ff1b-65e0-9a4d-64da6783fd64

#### Associated Detections


#### How To Implement
This playbook relies on local versions of the Dynamic Identifier Reputation Analysis, Dynamic Attributed Lookup, and Dynamic Related Tickets Search playbooks, as well as compatible input playbooks for those.


#### [Explore Playbook](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/Automated_Enrichment.json){: .btn .btn--info}

[![explore](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/Automated_Enrichment.png){:height="500px" width="500px"}](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/Automated_Enrichment.json)

#### Required field


#### Reference



[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/Automated_Enrichment.yml) \| *version*: **1**