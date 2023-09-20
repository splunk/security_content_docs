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

Moves the event status to open and then launches the Dispatch playbooks for Reputation Analysis, Attribute Lookup, and Related Tickets.

- **Type**: Investigation
- **Product**: Splunk SOAR
- **Apps**: 
- **Last Updated**: 2023-03-06
- **Author**: Kelby Shelton, Patrick Bareiss, Teoderick Contreras, Lou Stella Splunk
- **ID**: fc0edc96-ff1b-65e0-9a4d-64da6783fd64
- **Use-cases**:

#### Associated Detections


#### How To Implement
1. Ensure you have a reputation analysis playbook (e.g. VirusTotal v3), an attribute lookup playbook (e.g. Azure AD), and a related ticket search playbook (e.g. ServiceNow).\n2. Download local versions of Identifier Reputation Analysis Dispatch, Attribute Lookup Dispatch, and Related Tickets Search Dispatch playbooks.


#### [Explore Playbook](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/Automated_Enrichment.json){: .btn .btn--info}

[![explore](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/Automated_Enrichment.png){:height="500px" width="500px"}](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/Automated_Enrichment.json)

#### Required field


#### Reference



[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/Automated_Enrichment.yml) \| *version*: **2**