---
title: "Dynamic Attribute Lookup"
last_modified_at: 2023-03-06
toc: true
toc_label: ""
tags:
  - Investigation
  - Splunk SOAR
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

Detects available entities and routes them to attribute lookup playbooks. The output of the playbooks will create new artifacts for any technologies that returned information.

- **Type**: Investigation
- **Product**: Splunk SOAR
- **Apps**: 
- **Last Updated**: 2023-03-06
- **Author**: Lou Stella, Splunk
- **ID**: fc0edc96-ff2b-68d0-9a4d-63da6783fd64

#### Associated Detections


#### How To Implement
This playbook looks for artifacts and then dispatches the community Attribute Lookup playbooks. This playbook takes the output of those playbooks and nicely formats them into new artifacts with their results.


#### [Explore Playbook](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/Dynamic_Attribute_Lookup.json){: .btn .btn--info}

[![explore](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/Dynamic_Attribute_Lookup.png){:height="500px" width="500px"}](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/Dynamic_Attribute_Lookup.json)

#### Required field


#### Reference



[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/Dynamic_Attribute_Lookup.yml) \| *version*: **1**