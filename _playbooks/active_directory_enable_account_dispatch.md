---
title: "Active Directory Enable Account Dispatch"
last_modified_at: 2023-05-23
toc: true
toc_label: ""
tags:
  - Response
  - Splunk SOAR
  - microsoft_ad_ldap
  - azure_ad_graph
  - aws_iam
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

Automatically dispatches input playbooks with the &#39;enable_account&#39; tag. This will produce a merge report and indicator tag for each inputs.

- **Type**: Response
- **Product**: Splunk SOAR
- **Apps**: [microsoft_ad_ldap](https://splunkbase.splunk.com/apps?keyword=microsoft_ad_ldap&filters=product%3Asoar), [azure_ad_graph](https://splunkbase.splunk.com/apps?keyword=azure_ad_graph&filters=product%3Asoar), [aws_iam](https://splunkbase.splunk.com/apps?keyword=aws_iam&filters=product%3Asoar)
- **Last Updated**: 2023-05-23
- **Author**: Lou Stella, Splunk
- **ID**: 86320a91-1bde-41ab-8990-602a3768fd99
- **Use-cases**:

#### Associated Detections


#### How To Implement
This automatic playbook requires the &#34;enable_account&#34; tag be present on each input playbook you want to launch.


#### [Explore Playbook](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/Active_Directory_Enable_Account_Dispatch.json){: .btn .btn--info}

[![explore](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/Active_Directory_Enable_Account_Dispatch.png){:height="500px" width="500px"}](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/Active_Directory_Enable_Account_Dispatch.json)

#### Required field


#### Reference



[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/Active_Directory_Enable_Account_Dispatch.yml) \| *version*: **1**