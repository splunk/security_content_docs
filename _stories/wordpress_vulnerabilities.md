---
title: "WordPress Vulnerabilities"
last_modified_at: 2024-02-22
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

This analytic story provides a collection of analytics that detect potential exploitation of WordPress vulnerabilities. The analytics are focused on the detection of known vulnerabilities in WordPress plugins and themes.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Web](https://docs.splunk.com/Documentation/CIM/latest/User/Web)
- **Last Updated**: 2024-02-22
- **Author**: Michael Haag, Splunk
- **ID**: baeaee14-e439-4c95-91e8-aaedd8265c1c

#### Narrative

The following collection of analytics are focused on the detection of known vulnerabilities in WordPress plugins and themes. The analytics are focused on the detection of known vulnerabilities in WordPress plugins and themes.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [WordPress Bricks Builder plugin RCE](/web/56a8771a-3fda-4959-b81d-2f266e2f679f/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://attack.mitre.org/techniques/T1190](https://attack.mitre.org/techniques/T1190)
* [https://github.com/Tornad0007/CVE-2024-25600-Bricks-Builder-plugin-for-WordPress/blob/main/exploit.py](https://github.com/Tornad0007/CVE-2024-25600-Bricks-Builder-plugin-for-WordPress/blob/main/exploit.py)
* [https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-25600](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-25600)
* [https://op-c.net/blog/cve-2024-25600-wordpresss-bricks-builder-rce-flaw-under-active-exploitation/](https://op-c.net/blog/cve-2024-25600-wordpresss-bricks-builder-rce-flaw-under-active-exploitation/)
* [https://thehackernews.com/2024/02/wordpress-bricks-theme-under-active.html](https://thehackernews.com/2024/02/wordpress-bricks-theme-under-active.html)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/wordpress_vulnerabilities.yml) \| *version*: **1**