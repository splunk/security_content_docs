---
title: "Azure AD Graph User Attribute Lookup"
last_modified_at: 2023-01-11
toc: true
toc_label: ""
tags:
  - Investigation
  - Splunk SOAR
  - Azure AD Graph
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

Accepts a user or device and looks up the most recent attributes and groups for that user or device. This playbook produces a normalized output for each user and device.

- **Type**: Investigation
- **Product**: Splunk SOAR
- **Apps**: [Azure AD Graph](https://splunkbase.splunk.com/apps/#/search/Azure AD Graph/product/soar)
- **Last Updated**: 2023-01-11
- **Author**: Kelby Shelton, Splunk
- **ID**: fc0edc96-aa2b-4cb0-7b4d-63da67e71d74

#### Associated Detections


#### How To Implement
This input playbook requires the Azure AD Graph connector to be configured. It is designed to work in conjunction with the Dynamic Attribute Lookup playbook or other playbooks in the same style.


#### [Explore Playbook](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/Azure_AD_Graph_User_Attribute_Lookup.json){: .btn .btn--info}

[![explore](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/Azure_AD_Graph_User_Attribute_Lookup.png){:height="500px" width="500px"}](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/Azure_AD_Graph_User_Attribute_Lookup.json)

#### Required field


#### Reference



[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/Azure_AD_Graph_User_Attribute_Lookup.yml) \| *version*: **1**