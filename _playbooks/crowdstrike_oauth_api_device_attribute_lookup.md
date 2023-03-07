---
title: "Crowdstrike OAuth API Device Attribute Lookup"
last_modified_at: 2023-01-11
toc: true
toc_label: ""
tags:
  - Investigation
  - Splunk SOAR
  - Crowdstrike OAuth API
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

Accepts a user or device and looks up the most recent attributes and groups for that user or device. This playbook produces a normalized output for each user and device.

- **Type**: Investigation
- **Product**: Splunk SOAR
- **Apps**: [Crowdstrike OAuth API](https://splunkbase.splunk.com/apps/#/search/Crowdstrike OAuth API/product/soar)
- **Last Updated**: 2023-01-11
- **Author**: Teoderick Contreras, Splunk
- **ID**: fc0eac01-af2b-4cb0-7b4d-63da67d3fe74

#### Associated Detections


#### How To Implement
This input playbook requires the Crowdstrike OAuth API connector to be configured. It is designed to work in conjunction with the Dynamic Attribute Lookup playbook or other playbooks in the same style.


#### [Explore Playbook](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/Crowdstrike_OAuth_API_Device_Attribute_Lookup.json){: .btn .btn--info}

[![explore](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/Crowdstrike_OAuth_API_Device_Attribute_Lookup.png){:height="500px" width="500px"}](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/Crowdstrike_OAuth_API_Device_Attribute_Lookup.json)

#### Required field


#### Reference



[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/Crowdstrike_OAuth_API_Device_Attribute_Lookup.yml) \| *version*: **1**