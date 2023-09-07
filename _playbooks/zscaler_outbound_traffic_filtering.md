---
title: "ZScaler Outbound Traffic Filtering"
last_modified_at: 2023-03-31
toc: true
toc_label: ""
tags:
  - Response
  - Splunk SOAR
  - Zscaler
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

Accepts a URL or list of URLs and block them in ZScaler. Generates a list of observables with the blocked URLs.

- **Type**: Response
- **Product**: Splunk SOAR
- **Apps**: [Zscaler](https://splunkbase.splunk.com/apps?keyword=zscaler&filters=product%3Asoar)
- **Last Updated**: 2023-03-31
- **Author**: Patrick Bareiss, Splunk
- **ID**: 3e0df448-0546-4b2b-9143-365161cf40f9
- **Use-cases**:
  - Phishing
  - Endpoint

#### Associated Detections


#### How To Implement
This input playbook requires the ZScaler connector to be configured. It is designed to work in conjunction with the Dynamic URL Outbound Traffic Filtering Analysis playbook or other playbooks in the same style.


#### [D3FEND](https://d3fend.mitre.org/)

| ID          | Technique   | Definition     | Category       |
| ----------- | ----------- |--------------- |--------------- |
| D3-OTF | [](https://d3fend.mitre.org/technique/d3f:) |  |  |

#### [Explore Playbook](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/ZScaler_Outbound_Traffic_Filtering.json){: .btn .btn--info}

[![explore](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/ZScaler_Outbound_Traffic_Filtering.png){:height="500px" width="500px"}](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/ZScaler_Outbound_Traffic_Filtering.json)

#### Required field


#### Reference

* [https://d3fend.mitre.org/technique/d3f:OutboundTrafficFiltering/](https://d3fend.mitre.org/technique/d3f:OutboundTrafficFiltering/)




[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/ZScaler_Outbound_Traffic_Filtering.yml) \| *version*: **1**