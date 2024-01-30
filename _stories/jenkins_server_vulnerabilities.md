---
title: "Jenkins Server Vulnerabilities"
last_modified_at: 2024-01-29
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

This analytic story provides a comprehensive view of Jenkins server vulnerabilities and associated detection analytics.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Web](https://docs.splunk.com/Documentation/CIM/latest/User/Web)
- **Last Updated**: 2024-01-29
- **Author**: Michael Haag, Splunk
- **ID**: 789e76e6-4b5e-4af3-ab8c-46578d84ccff

#### Narrative

The following analytic story provides a comprehensive view of Jenkins server vulnerabilities and associated detection analytics. Jenkins is a popular open-source automation server that is used to automate tasks associated with building, testing, and deploying software. Jenkins is often used in DevOps environments and is a critical component of the software development lifecycle. As a result, Jenkins servers are often targeted by adversaries to gain access to sensitive information, credentials, and other critical assets. This analytic story provides a comprehensive view of Jenkins server vulnerabilities and associated detection analytics.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Jenkins Arbitrary File Read CVE-2024-23897](/web/c641260d-2b48-4eb1-b1e8-2cc5b8b99ab1/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://www.jenkins.io/security/advisory/2024-01-24/](https://www.jenkins.io/security/advisory/2024-01-24/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/jenkins_server_vulnerabilities.yml) \| *version*: **1**