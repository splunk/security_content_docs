---
title: "VirusTotal v3 Identifier Reputation Analysis"
last_modified_at: 2023-01-11
toc: true
toc_label: ""
tags:
  - Investigation
  - Splunk SOAR
  - VirusTotal v3
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

Accepts a URL, IP, Domain, or File_Hash and does reputation analysis on the objects. Generates a global report and a per observable sub-report and normalized score. The score can be customized based on a variety of factors.

- **Type**: Investigation
- **Product**: Splunk SOAR
- **Apps**: [VirusTotal v3](https://splunkbase.splunk.com/apps/#/search/VirusTotal v3/product/soar)
- **Last Updated**: 2023-01-11
- **Author**: Kelby Shelton, Lou Stella, Splunk
- **ID**: fc0edc96-ff2b-48b0-9b4d-63da67d3fe74

#### Associated Detections


#### How To Implement
This input playbook requires the VirusTotal v3 connector to be configured. It is designed to work in conjunction with the Dynamic Identifier Reputation Analysis playbook or other playbooks in the same style.


#### [Explore Playbook](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/VirusTotal_v3_Identifier_Reputation_Analysis.json){: .btn .btn--info}

[![explore](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/VirusTotal_v3_Identifier_Reputation_Analysis.png){:height="500px" width="500px"}](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/VirusTotal_v3_Identifier_Reputation_Analysis.json)

#### Required field


#### Reference

* [https://d3fend.mitre.org/technique/d3f:IdentifierReputationAnalysis/](https://d3fend.mitre.org/technique/d3f:IdentifierReputationAnalysis/)




[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/VirusTotal_v3_Identifier_Reputation_Analysis.yml) \| *version*: **1**