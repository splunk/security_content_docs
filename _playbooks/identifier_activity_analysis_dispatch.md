---
title: "Identifier Activity Analysis Dispatch"
last_modified_at: 2023-02-28
toc: true
toc_label: ""
tags:
  - Investigation
  - Splunk SOAR
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

Detects available indicators and routes them to related identifier activity analysis playbooks. The output of the analysis will update any artifacts, tasks, and indicator tags.

- **Type**: Investigation
- **Product**: Splunk SOAR
- **Apps**: 
- **Last Updated**: 2023-02-28
- **Author**: Lou Stella, Splunk
- **ID**: fc0edc96-ab1f-48b9-1b4d-63da52dbfa74

#### Associated Detections


#### How To Implement
This playbook looks for artifacts and then dispatches the community Related Tickets playbooks. This playbook takes the output of those playbooks and nicely formats them into notes and tags indicators with their results.


#### [Explore Playbook](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/Identifier_Activity_Analysis_Dispatch.json){: .btn .btn--info}

[![explore](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/Identifier_Activity_Analysis_Dispatch.png){:height="500px" width="500px"}](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/Identifier_Activity_Analysis_Dispatch.json)

#### Required field


#### Reference



[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/Identifier_Activity_Analysis_Dispatch.yml) \| *version*: **1**