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
- **Apps**: [Cisco Umbrella](https://splunkbase.splunk.com/apps/#/search/Cisco Umbrella/product/soar)
- **Last Updated**: 2023-07-14
- **Author**: Patrick Bareiss, Splunk
- **ID**: 3705f371-f355-46d7-979a-3bc4c26e2208

#### Associated Detections


#### How To Implement
This input playbook requires the Cisco Umbrella connector to be configured. It is designed to work in conjunction with the DNS Denylisting Dispatch playbook or other playbooks in the same style.


#### [Explore Playbook](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/Cisco_Umbrella_DNS_Denylisting.json){: .btn .btn--info}

[![explore](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/Cisco_Umbrella_DNS_Denylisting.png){:height="500px" width="500px"}](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/Cisco_Umbrella_DNS_Denylisting.json)

#### Required field


#### Reference



[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/Cisco_Umbrella_DNS_Denylisting.yml) \| *version*: **1**