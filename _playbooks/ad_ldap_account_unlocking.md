---
title: "AD LDAP Account Unlocking"
last_modified_at: 2023-06-21
toc: true
toc_label: ""
tags:
  - Response
  - Splunk SOAR
  - AD LDAP
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

Accepts user, to be unlocked using Microsoft AD LDAP connector. This playbook produces a normalized observable output for each user.

- **Type**: Response
- **Product**: Splunk SOAR
- **Apps**: [AD LDAP](https://splunkbase.splunk.com/apps/#/search/AD LDAP/product/soar)
- **Last Updated**: 2023-06-21
- **Author**: Lou Stella, Splunk
- **ID**: e6f96caf-61ac-4ced-aabc-ba9b19bd9e1f

#### Associated Detections


#### How To Implement
This input playbook requires the Microsoft AD LDAP connector to be configured. It is designed to work in conjunction with the Active Directory Enable Account Dispatch playbook or other playbooks in the same style.


#### [Explore Playbook](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/AD_LDAP_Account_Unlocking.json){: .btn .btn--info}

[![explore](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/AD_LDAP_Account_Unlocking.png){:height="500px" width="500px"}](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/AD_LDAP_Account_Unlocking.json)

#### Required field


#### Reference



[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/AD_LDAP_Account_Unlocking.yml) \| *version*: **1**