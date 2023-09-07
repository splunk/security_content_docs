---
title: "Azure AD Account Unlocking"
last_modified_at: 2023-06-21
toc: true
toc_label: ""
tags:
  - Response
  - Splunk SOAR
  - Azure AD Graph
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

Accepts user, to be enabled using Azure AD Graph connector. This playbook produces a normalized observables output for each user.

- **Type**: Response
- **Product**: Splunk SOAR
- **Apps**: [Azure AD Graph](https://splunkbase.splunk.com/apps?keyword=azure+ad+graph&filters=product%3Asoar)
- **Last Updated**: 2023-06-21
- **Author**: Lou Stella, Splunk
- **ID**: c3c0157d-7da0-4dcb-8ba7-327ee91f531c
- **Use-cases**:

#### Associated Detections


#### How To Implement
This input playbook requires the Azure AD Graph connector to be configured. It is designed to work in conjunction with the Active Directory Enable Account Dispatch playbook or other playbooks in the same style.


#### [Explore Playbook](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/Azure_AD_Account_Unlocking.json){: .btn .btn--info}

[![explore](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/Azure_AD_Account_Unlocking.png){:height="500px" width="500px"}](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/Azure_AD_Account_Unlocking.json)

#### Required field


#### Reference



[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/Azure_AD_Account_Unlocking.yml) \| *version*: **1**