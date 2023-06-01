---
title: "Active Directory Disable Account Dispatch"
last_modified_at: 2023-05-23
toc: true
toc_label: ""
tags:
  - Investigation
  - Splunk SOAR
  - microsoft_ad_ldap
  - azure_ad_graph
  - aws_iam
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

Automatically dispatches input playbooks with the &#39;disable_account&#39; tag. This will produce a merge report and indicator tag for each inputs.

- **Type**: Investigation
- **Product**: Splunk SOAR
- **Apps**: [microsoft_ad_ldap](https://splunkbase.splunk.com/apps/#/search/microsoft_ad_ldap/product/soar), [azure_ad_graph](https://splunkbase.splunk.com/apps/#/search/azure_ad_graph/product/soar), [aws_iam](https://splunkbase.splunk.com/apps/#/search/aws_iam/product/soar)
- **Last Updated**: 2023-05-23
- **Author**: Teoderick Contreras, Splunk
- **ID**: 86320591-1bbd-41ab-8990-602a3968fd99

#### Associated Detections


#### How To Implement
This automatic playbook requires &#34;disable_account&#34; tag be present on each input playbook you want to launch.


#### [Explore Playbook](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/Active_Directory_Disable_Account_Dispatch.json){: .btn .btn--info}

[![explore](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/Active_Directory_Disable_Account_Dispatch.png){:height="500px" width="500px"}](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/Active_Directory_Disable_Account_Dispatch.json)

#### Required field


#### Reference



[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/Active_Directory_Disable_Account_Dispatch.yml) \| *version*: **1**