---
title: "Splunk Notable Related Tickets Search"
last_modified_at: 2023-02-28
toc: true
toc_label: ""
tags:
  - Investigation
  - Splunk SOAR
  - Splunk
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

Accepts a user or device and identifies if related notables exists in a timeframe of last 24 hours. Generates a global report and list of observables.

- **Type**: Investigation
- **Product**: Splunk SOAR
- **Apps**: [Splunk](https://splunkbase.splunk.com/apps/#/search/Splunk/product/soar)
- **Last Updated**: 2023-02-28
- **Author**: Patrick Bareiss, Splunk
- **ID**: fc0edc96-ff2b-58b0-9b4d-43bc61bafe74

#### Associated Detections


#### How To Implement
This input playbook requires the Splunk connector to be configured. It is designed to work in conjunction with the Dynamic Related Tickets Seach playbook or other playbooks in the same style.


#### [Explore Playbook](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/Splunk_Notable_Related_Tickets_Search.json){: .btn .btn--info}

[![explore](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/Splunk_Notable_Related_Tickets_Search.png){:height="500px" width="500px"}](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/Splunk_Notable_Related_Tickets_Search.json)

#### Required field


#### Reference

* [https://d3fend.mitre.org/technique/d3f:IdentifierReputationAnalysis/](https://d3fend.mitre.org/technique/d3f:IdentifierReputationAnalysis/)




[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/Splunk_Notable_Related_Tickets_Search.yml) \| *version*: **1**