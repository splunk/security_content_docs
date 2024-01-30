---
title: "Splunk Automated Email Investigation"
last_modified_at: 2023-03-24
toc: true
toc_label: ""
tags:
  - Investigation
  - Splunk SOAR
---

[Try in Splunk SOAR](https://www.splunk.com/en_us/software/splunk-security-orchestration-and-automation.html){: .btn .btn--success}

#### Description

Leverages Splunk technologies to determine if a .eml or .msg file in the vault is malicious, whether or not it contained suspect URLs or Files, and who may have interacted with the IoCs (email, URLs, or Files).

- **Type**: Investigation
- **Product**: Splunk SOAR
- **Apps**: 
- **Last Updated**: 2023-03-24
- **Author**: Teoderick Contreras, Splunk; Kelby Shelton, Splunk
- **ID**: c69e3310-a819-4d16-a615-348fa8d88b0b
- **Use-cases**:
  - Phishing

#### Associated Detections


#### How To Implement
Ensure the four input playbooks are loaded onto the system. The input playbooks are designed to be swappable within the same category (e.g., Message Activity Analysis) with minimal to no changes downstream.


#### [D3FEND](https://d3fend.mitre.org/)

| ID          | Technique   | Definition     | Category       |
| ----------- | ----------- |--------------- |--------------- |
| D3-DA | [Dynamic Analysis](https://d3fend.mitre.org/technique/d3f:DynamicAnalysis) | Executing or opening a file in a synthetic &#34;sandbox&#34; environment to determine if the file is a malicious program or if the file exploits another program such as a document reader. | File Analysis |

#### [Explore Playbook](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/Splunk_Attack_Analyzer_Dynamic_Analysis.json){: .btn .btn--info}

[![explore](https://raw.githubusercontent.com/splunk/security_content/develop/playbooks/Splunk_Attack_Analyzer_Dynamic_Analysis.png){:height="500px" width="500px"}](https://splunk.github.io/soar-playbook-viewer/?playbook=https://raw.githubusercontent.com/phantomcyber/playbooks/latest/Splunk_Attack_Analyzer_Dynamic_Analysis.json)

#### Required field


#### Reference



[*source*](https://github.com/splunk/security_content/tree/develop/playbooks/Splunk_Attack_Analyzer_Dynamic_Analysis.yml) \| *version*: **1**