---
title: "Cisco Umbrella DNS Denylisting"
last_modified_at: 2023-07-14
toc: true
toc_label: ""
tags:
  - Response
  - Splunk SOAR
  - Cisco Umbrella
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

Accepts a domain or list of domains and block them in Cisco Umbrella. Generates a list of observables with the blocked domains.

- **Type**: Response
- **Product**: Splunk SOAR
- **Apps**: [Cisco Umbrella](https://splunkbase.splunk.com/apps?keyword=cisco+umbrella&filters=product%3Asoar)
- **Last Updated**: 2023-07-14
- **Author**: Patrick Bareiss, Splunk
- **ID**: 3705f371-f355-46d7-979a-3bc4c26e2208
- **Use-cases**:
  - Phishing
  - Endpoint

#### Associated Detections


#### How To Implement
This input playbook requires the Cisco Umbrella connector to be configured. It is designed to work in conjunction with the DNS Denylisting Dispatch playbook or other playbooks in the same style.


#### [D3FEND](https://d3fend.mitre.org/)

| ID          | Technique   | Definition     | Category       |
| ----------- | ----------- |--------------- |--------------- |
| D3-DNSDL | [DNS Denylisting](https://d3fend.mitre.org/technique/d3f:DNSDenylisting) | Blocking DNS Network Traffic based on criteria such as IP address, domain name, or DNS query type. | Network Isolation |

#### [Explore Playbook](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/Cisco_Umbrella_DNS_Denylisting.json){: .btn .btn--info}

[![explore](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/Cisco_Umbrella_DNS_Denylisting.png){:height="500px" width="500px"}](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/Cisco_Umbrella_DNS_Denylisting.json)

#### Required field


#### Reference



[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/Cisco_Umbrella_DNS_Denylisting.yml) \| *version*: **1**