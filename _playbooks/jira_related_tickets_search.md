---
title: "Jira Related Tickets Search"
last_modified_at: 2023-08-22
toc: true
toc_label: ""
tags:
  - Investigation
  - Splunk SOAR
  - Jira
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

Accepts a user or device and identifies if related tickets exists in a timeframe of last 30 days. Generates a global report and list of observables.

- **Type**: Investigation
- **Product**: Splunk SOAR
- **Apps**: [Jira](https://splunkbase.splunk.com/apps?keyword=jira&filters=product%3Asoar)
- **Last Updated**: 2023-08-22
- **Author**: Eric Li, Splunk
- **ID**: bd20698c-42d6-45ec-b7a0-fc356d624bdf
- **Use-cases**:

#### Associated Detections


#### How To Implement
This input playbook requires the Jira connector to be configured. It is designed to work in conjunction with the Dynamic Related Tickets Search playbook or other playbooks in the same style.


#### [D3FEND](https://d3fend.mitre.org/)

| ID          | Technique   | Definition     | Category       |
| ----------- | ----------- | -------------- | -------------- |
| D3-IRA | [Identifier Reputation Analysis](https://d3fend.mitre.org/technique/d3f:IdentifierReputationAnalysis) | Analyzing the reputation of an identifier. | Identifier Analysis |

#### [Explore Playbook](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/Jira_Related_Tickets_Search.json){: .btn .btn--info}

[![explore](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/Jira_Related_Tickets_Search.png){:height="500px" width="500px"}](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/Jira_Related_Tickets_Search.json)

#### Required field


#### Reference

* [https://d3fend.mitre.org/technique/d3f:IdentifierReputationAnalysis/](https://d3fend.mitre.org/technique/d3f:IdentifierReputationAnalysis/)




[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/Jira_Related_Tickets_Search.yml) \| *version*: **1**