---
title: "Panorama Outbound Traffic Filtering"
last_modified_at: 2023-05-19
toc: true
toc_label: ""
tags:
  - Response
  - Splunk SOAR
  - Panorama
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

Accepts a URL or list of URLs as input. Uses Panorama to block the given URLs in Palo Alto Firewall.

- **Type**: Response
- **Product**: Splunk SOAR
- **Apps**: [Panorama](https://splunkbase.splunk.com/apps/#/search/Panorama/product/soar)
- **Last Updated**: 2023-05-19
- **Author**: Patrick Bareiss, Splunk
- **ID**: 5e3e061f-5206-49ac-88f4-4e818a20b2a9

#### Associated Detections


#### How To Implement
This input playbook requires the Panorama connector to be configured. It is designed to work in conjunction with the Dynamic URL Outbound Traffic Filtering Analysis playbook or other playbooks in the same style.


#### [Explore Playbook](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/Panorama_Outbound_Traffic_Filtering.json){: .btn .btn--info}

[![explore](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/Panorama_Outbound_Traffic_Filtering.png){:height="500px" width="500px"}](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/Panorama_Outbound_Traffic_Filtering.json)

#### Required field


#### Reference

* [https://d3fend.mitre.org/technique/d3f:OutboundTrafficFiltering/](https://d3fend.mitre.org/technique/d3f:OutboundTrafficFiltering/)




[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/Panorama_Outbound_Traffic_Filtering.yml) \| *version*: **1**