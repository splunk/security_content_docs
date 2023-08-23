---
title: "DNS Denylisting Dispatch"
last_modified_at: 2023-07-14
toc: true
toc_label: ""
tags:
  - Response
  - Splunk SOAR
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

Accepts a list of domains and blocks them. Generates a global report and list of observables.

- **Type**: Response
- **Product**: Splunk SOAR
- **Apps**: 
- **Last Updated**: 2023-07-14
- **Author**: Patrick Bareiss, Splunk
- **ID**: 7fd9a82f-517a-4d86-bf24-4d4158719dc1
- **Use-cases**:
  - Phishing
  - Endpoint

#### Associated Detections


#### How To Implement
This playbook looks for artifacts and then dispatches the community denylisting playbooks. This playbook takes the output of those playbooks and nicely formats them into notes and tags indicators with their results.


#### [D3FEND](https://d3fend.mitre.org/)

| ID          | Technique   | Definition     | Category       |
| ----------- | ----------- |--------------- |--------------- |
| D3-DNSDL | [DNS Denylisting](https://d3fend.mitre.org/technique/d3f:DNSDenylisting) | Blocking DNS Network Traffic based on criteria such as IP address, domain name, or DNS query type. | Network Isolation |

#### [Explore Playbook](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/DNS_Denylisting_Dispatch.json){: .btn .btn--info}

[![explore](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/DNS_Denylisting_Dispatch.png){:height="500px" width="500px"}](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/DNS_Denylisting_Dispatch.json)

#### Required field


#### Reference

* [https://d3fend.mitre.org/technique/d3f:DNSDenylisting/](https://d3fend.mitre.org/technique/d3f:DNSDenylisting/)




[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/DNS_Denylisting_Dispatch.yml) \| *version*: **1**