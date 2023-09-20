---
title: "ServiceNow Related Tickets Search"
last_modified_at: 2023-02-28
toc: true
toc_label: ""
tags:
  - Investigation
  - Splunk SOAR
  - ServiceNow
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

Accepts a user or device and identifies if related tickets exists in a timeframe of last 30 days. Generates a global report and list of observables.

- **Type**: Investigation
- **Product**: Splunk SOAR
- **Apps**: [ServiceNow](https://splunkbase.splunk.com/apps?keyword=servicenow&filters=product%3Asoar)
- **Last Updated**: 2023-02-28
- **Author**: Patrick Bareiss, Splunk
- **ID**: fc0edc96-ff2b-48b0-9b4d-63da61bafe74
- **Use-cases**:
  - Enrichment

#### Associated Detections


#### How To Implement
This input playbook requires the ServiceNow connector to be configured. It is designed to work in conjunction with the Dynamic Related Tickets Search playbook or other playbooks in the same style.


#### [Explore Playbook](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/ServiceNow_Related_Tickets_Search.json){: .btn .btn--info}

[![explore](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/ServiceNow_Related_Tickets_Search.png){:height="500px" width="500px"}](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/ServiceNow_Related_Tickets_Search.json)

#### Required field


#### Reference

* [https://d3fend.mitre.org/technique/d3f:IdentifierReputationAnalysis/](https://d3fend.mitre.org/technique/d3f:IdentifierReputationAnalysis/)




[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/ServiceNow_Related_Tickets_Search.yml) \| *version*: **1**