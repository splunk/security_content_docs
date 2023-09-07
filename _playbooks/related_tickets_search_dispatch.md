---
title: "Related Tickets Search Dispatch"
last_modified_at: 2023-02-28
toc: true
toc_label: ""
tags:
  - Investigation
  - Splunk SOAR
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

Detects available indicators and routes them to dispatch related ticket search playbooks. The output of the analysis will update any artifacts, tasks, and indicator tags.

- **Type**: Investigation
- **Product**: Splunk SOAR
- **Apps**: 
- **Last Updated**: 2023-02-28
- **Author**: Patrick Bareiss, Splunk
- **ID**: fc0edc96-ab1f-48b9-9b4d-63da61bafe74
- **Use-cases**:
  - Enrichment

#### Associated Detections


#### How To Implement
This playbook looks for artifacts and then dispatches the community Related Tickets playbooks. This playbook takes the output of those playbooks and nicely formats them into notes and tags indicators with their results.


#### [Explore Playbook](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/Related_Tickets_Search_Dispatch.json){: .btn .btn--info}

[![explore](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/Related_Tickets_Search_Dispatch.png){:height="500px" width="500px"}](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/Related_Tickets_Search_Dispatch.json)

#### Required field


#### Reference

* [https://d3fend.mitre.org/technique/d3f:IdentifierReputationAnalysis/](https://d3fend.mitre.org/technique/d3f:IdentifierReputationAnalysis/)




[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/Related_Tickets_Search_Dispatch.yml) \| *version*: **1**