---
title: "Confluence Data Center and Confluence Server Vulnerabilities"
last_modified_at: 2024-01-22
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Web
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic story covers use cases for detecting and investigating potential attacks against Confluence Data Center and Confluence Server.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Web](https://docs.splunk.com/Documentation/CIM/latest/User/Web)
- **Last Updated**: 2024-01-22
- **Author**: Michael Haag, Splunk
- **ID**: 509387a5-ab53-4656-8bb5-4bc8c2c074d9

#### Narrative

The analytic story of Confluence Data Center and Confluence Server encompasses a comprehensive approach to safeguarding these platforms from a variety of threats. By leveraging the analytics created in the project, security teams are equipped to detect, investigate, and respond to potential attacks that target Confluence environments.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Confluence Data Center and Server Privilege Escalation](/web/115bebac-0976-4f7d-a3ec-d1fb45a39a11/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Confluence Pre-Auth RCE via OGNL Injection CVE-2023-22527](/web/f56936c0-ae6f-4eeb-91ff-ecc1448c6105/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Confluence Unauthenticated Remote Code Execution CVE-2022-26134](/web/fcf4bd3f-a79f-4b7a-83bf-2692d60b859c/) | [Server Software Component](/tags/#server-software-component), [Exploit Public-Facing Application](/tags/#exploit-public-facing-application), [External Remote Services](/tags/#external-remote-services) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://confluence.atlassian.com/security/cve-2023-22527-rce-remote-code-execution-vulnerability-in-confluence-data-center-and-confluence-server-1333990257.html](https://confluence.atlassian.com/security/cve-2023-22527-rce-remote-code-execution-vulnerability-in-confluence-data-center-and-confluence-server-1333990257.html)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/confluence_data_center_and_confluence_server_vulnerabilities.yml) \| *version*: **1**