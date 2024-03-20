---
title: "PhishTank URL Reputation Analysis"
last_modified_at: 2023-01-11
toc: true
toc_label: ""
tags:
  - Investigation
  - Splunk SOAR
  - PhishTank
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

Accepts a URL and does reputation analysis on the objects. Generates a global report and a per observable sub-report and normalized score. The score can be customized as desired.

- **Type**: Investigation
- **Product**: Splunk SOAR
- **Apps**: [PhishTank](https://splunkbase.splunk.com/apps?keyword=phishtank&filters=product%3Asoar)
- **Last Updated**: 2023-01-11
- **Author**: Kelby Shelton, Splunk
- **ID**: fc0eab96-ff1b-45b0-9b4d-63ca4783fd64
- **Use-cases**:
  - Enrichment
  - Phishing

#### Associated Detections


#### How To Implement
This input playbook requires the PhishTank connector to be configured. It is designed to work in conjunction with the Dynamic Identifier Reputation Analysis playbook or other playbooks in the same style.


#### [D3FEND](https://d3fend.mitre.org/)

| ID          | Technique   | Definition     | Category       |
| ----------- | ----------- | -------------- | -------------- |
| D3-IRA | [Identifier Reputation Analysis](https://d3fend.mitre.org/technique/d3f:IdentifierReputationAnalysis) | Analyzing the reputation of an identifier. | Identifier Analysis |

#### [Explore Playbook](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/PhishTank_URL_Reputation_Analysis.json){: .btn .btn--info}

[![explore](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/PhishTank_URL_Reputation_Analysis.png){:height="500px" width="500px"}](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/PhishTank_URL_Reputation_Analysis.json)

#### Required field


#### Reference

* [https://d3fend.mitre.org/technique/d3f:IdentifierReputationAnalysis/](https://d3fend.mitre.org/technique/d3f:IdentifierReputationAnalysis/)




[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/PhishTank_URL_Reputation_Analysis.yml) \| *version*: **1**