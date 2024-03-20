---
title: "URL Outbound Traffic Filtering Dispatch"
last_modified_at: 2023-05-22
toc: true
toc_label: ""
tags:
  - Response
  - Splunk SOAR
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

Accepts a list of URLs and blocks them. Generates a global report and list of observables.

- **Type**: Response
- **Product**: Splunk SOAR
- **Apps**: 
- **Last Updated**: 2023-05-22
- **Author**: Patrick Bareiss, Splunk
- **ID**: 83bbe505-4636-4f60-a37b-86f1234d8567
- **Use-cases**:
  - Phishing
  - Endpoint

#### Associated Detections


#### How To Implement
This playbook looks for artifacts and then dispatches the community denylisting playbooks. This playbook takes the output of those playbooks and nicely formats them into notes and tags indicators with their results.


#### [D3FEND](https://d3fend.mitre.org/)

| ID          | Technique   | Definition     | Category       |
| ----------- | ----------- | -------------- | -------------- |
| D3-OTF | [Outbound Traffic Filtering](https://d3fend.mitre.org/technique/d3f:OutboundTrafficFiltering) | Restricting network traffic originating from any location. | Network Isolation |

#### [Explore Playbook](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/URL_Outbound_Traffic_Filtering_Dispatch.json){: .btn .btn--info}

[![explore](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/URL_Outbound_Traffic_Filtering_Dispatch.png){:height="500px" width="500px"}](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/URL_Outbound_Traffic_Filtering_Dispatch.json)

#### Required field


#### Reference

* [https://d3fend.mitre.org/technique/d3f:OutboundTrafficFiltering/](https://d3fend.mitre.org/technique/d3f:OutboundTrafficFiltering/)




[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/URL_Outbound_Traffic_Filtering_Dispatch.yml) \| *version*: **1**