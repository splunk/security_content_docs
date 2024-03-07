---
title: "JetBrains TeamCity Vulnerabilities"
last_modified_at: 2024-03-04
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

This story provides a high-level overview of JetBrains TeamCity vulnerabilities and how to detect and respond to them using Splunk.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Web](https://docs.splunk.com/Documentation/CIM/latest/User/Web)
- **Last Updated**: 2024-03-04
- **Author**: Michael Haag, Splunk
- **ID**: 3cd841e8-2f64-45e8-b148-7767255db111

#### Narrative

JetBrains TeamCity is a continuous integration and deployment server that allows developers to automate the process of building, testing, and deploying code. It is a popular tool used by many organizations to streamline their development and deployment processes. However, like any software, JetBrains TeamCity is not immune to vulnerabilities.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [JetBrains TeamCity Authentication Bypass CVE-2024-27198](/web/fbcc04c7-8a79-453c-b3a9-c232c423bdd4/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [JetBrains TeamCity Authentication Bypass Suricata CVE-2024-27198](/web/fbcc04c7-8a79-453c-b3a9-c232c423bdd3/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [JetBrains TeamCity Limited Auth Bypass Suricata CVE-2024-27199](/web/a1e68dcd-2e24-4434-bd0e-b3d4de139d58/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [JetBrains TeamCity RCE Attempt](/web/89a58e5f-1365-4793-b45c-770abbb32b6c/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://www.rapid7.com/blog/post/2024/03/04/etr-cve-2024-27198-and-cve-2024-27199-jetbrains-teamcity-multiple-authentication-bypass-vulnerabilities-fixed/](https://www.rapid7.com/blog/post/2024/03/04/etr-cve-2024-27198-and-cve-2024-27199-jetbrains-teamcity-multiple-authentication-bypass-vulnerabilities-fixed/)
* [https://blog.jetbrains.com/teamcity/2024/03/teamcity-2023-11-4-is-out/](https://blog.jetbrains.com/teamcity/2024/03/teamcity-2023-11-4-is-out/)
* [https://blog.jetbrains.com/teamcity/2024/03/additional-critical-security-issues-affecting-teamcity-on-premises-cve-2024-27198-and-cve-2024-27199-update-to-2023-11-4-now/](https://blog.jetbrains.com/teamcity/2024/03/additional-critical-security-issues-affecting-teamcity-on-premises-cve-2024-27198-and-cve-2024-27199-update-to-2023-11-4-now/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/jetbrains_teamcity_vulnerabilities.yml) \| *version*: **1**