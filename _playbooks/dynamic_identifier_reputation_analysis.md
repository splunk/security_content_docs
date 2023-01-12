---
title: "Dynamic Identifier Reputation Analysis"
last_modified_at: 2023-01-11
toc: true
toc_label: ""
tags:
  - Investigation
  - Splunk SOAR
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

Detects available indicators and routes them to indicator reputation analysis playbooks. The output of the analysis will update any artifacts, tasks, and indicator tags. https://d3fend.mitre.org/technique/d3f:IdentifierReputationAnalysis/

- **Type**: Investigation
- **Product**: Splunk SOAR
- **Apps**: 
- **Last Updated**: 2023-01-11
- **Author**: Kelby Shelton, Splunk
- **ID**: fc0edc96-ff2b-48b0-9b4d-63da6783fd64

#### Associated Detections


#### How To Implement
This playbook looks for artifacts and then dispatches the community Reputation playbooks. This playbook takes the output of those playbooks and nicely formats them into notes and tags indicators with their results.


#### [Explore Playbook](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/Dynamic_Identifier_Reputation_Analysis.json){: .btn .btn--info}

[![explore](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/Dynamic_Identifier_Reputation_Analysis.png){:height="500px" width="500px"}](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/Dynamic_Identifier_Reputation_Analysis.json)

#### Required field


#### Reference

* [https://d3fend.mitre.org/technique/d3f:IdentifierReputationAnalysis/](https://d3fend.mitre.org/technique/d3f:IdentifierReputationAnalysis/)




[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/Dynamic_Identifier_Reputation_Analysis.yml) \| *version*: **1**