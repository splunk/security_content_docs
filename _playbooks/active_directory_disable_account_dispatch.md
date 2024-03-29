---
title: "Active Directory Disable Account Dispatch"
last_modified_at: 2023-05-23
toc: true
toc_label: ""
tags:
  - Investigation
  - Splunk SOAR
  - AD LDAP
  - Azure AD Graph
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

Automatically dispatches input playbooks with the &#39;disable_account&#39; tag. This will produce a merge report and indicator tag for each inputs.

- **Type**: Investigation
- **Product**: Splunk SOAR
- **Apps**: [AD LDAP](https://splunkbase.splunk.com/apps?keyword=ad+ldap&filters=product%3Asoar), [Azure AD Graph](https://splunkbase.splunk.com/apps?keyword=azure+ad+graph&filters=product%3Asoar)
- **Last Updated**: 2023-05-23
- **Author**: Teoderick Contreras, Splunk
- **ID**: 86320591-1bbd-41ab-8990-602a3968fd99
- **Use-cases**:
  - Phishing
  - Endpoint

#### Associated Detections


#### How To Implement
This automatic playbook requires &#34;disable_account&#34; tag be present on each input playbook you want to launch.


#### [D3FEND](https://d3fend.mitre.org/)

| ID          | Technique   | Definition     | Category       |
| ----------- | ----------- | -------------- | -------------- |
| D3-AL | [Account Locking](https://d3fend.mitre.org/technique/d3f:AccountLocking) | The process of temporarily disabling user accounts on a system or domain. | Credential Eviction |

#### [Explore Playbook](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/Active_Directory_Disable_Account_Dispatch.json){: .btn .btn--info}

[![explore](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/Active_Directory_Disable_Account_Dispatch.png){:height="500px" width="500px"}](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/Active_Directory_Disable_Account_Dispatch.json)

#### Required field


#### Reference



[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/Active_Directory_Disable_Account_Dispatch.yml) \| *version*: **1**