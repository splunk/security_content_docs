---
title: "Splunk Message Identifier Activity Analysis"
last_modified_at: 2023-05-12
toc: true
toc_label: ""
tags:
  - Investigation
  - Splunk SOAR
  - Splunk
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

Accepts an internet message id, and asks Splunk to look for records that have a matching internet message id.  It then produces a normalized output and summary table.

- **Type**: Investigation
- **Product**: Splunk SOAR
- **Apps**: [Splunk](https://splunkbase.splunk.com/apps/#/search/Splunk/product/soar)
- **Last Updated**: 2023-05-12
- **Author**: Lou Stella, Splunk
- **ID**: 5299b9dc-e8c4-46ba-d942-98dae0fa816d

#### Associated Detections


#### How To Implement
This input playbook requires the Splunk connector to be configured. You will also need data populating the Email.All_Email datamodel in the out-of-the-box configuration of this playbook.


#### [Explore Playbook](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/Splunk_Message_Identifier_Activity_Analysis.json){: .btn .btn--info}

[![explore](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/Splunk_Message_Identifier_Activity_Analysis.png){:height="500px" width="500px"}](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/Splunk_Message_Identifier_Activity_Analysis.json)

#### Required field


#### Reference



[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/Splunk_Message_Identifier_Activity_Analysis.yml) \| *version*: **1**