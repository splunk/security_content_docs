---
title: "JetBrains TeamCity Unauthenticated RCE"
last_modified_at: 2023-10-01
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

A critical security vulnerability, CVE-2023-42793, has been discovered affecting all versions of TeamCity On-Premises up to 2023.05.3. This vulnerability allows unauthenticated attackers to execute remote code and gain administrative control of the TeamCity server, posing a significant risk for supply chain attacks. Although the issue has been fixed in version 2023.05.4, servers running older versions remain at risk. A security patch plugin has been released for immediate mitigation, applicable to TeamCity versions 8.0 and above. Organizations are strongly advised to update to the fixed version or apply the security patch, especially if their TeamCity server is publicly accessible. No impact has been reported on TeamCity Cloud as it has been upgraded to the secure version.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Web](https://docs.splunk.com/Documentation/CIM/latest/User/Web)
- **Last Updated**: 2023-10-01
- **Author**: Michael Haag, Splunk
- **ID**: 7ef2d230-9dbb-4d13-9263-a7d8c3aad9bf

#### Narrative

The CVE-2023-42793 vulnerability in TeamCity On-Premises allows an unauthenticated attacker to bypass authentication and gain administrative access through Remote Code Execution (RCE). Specifically, the attacker can send a malicious POST request to /app/rest/users/id:1/tokens/RPC2 to create an administrative token. Once the token is obtained, the attacker has the ability to perform various unauthorized activities, including creating new admin users and executing arbitrary shell commands on the server. \ For Splunk Security Content, the focus should be on identifying suspicious POST requests to /app/rest/users/id:1/tokens/RPC2 and other affected API endpoints, as this is the initial point of exploitation. Monitoring logs for changes to the internal.properties file or the creation of new admin users could also provide crucial indicators of compromise. Furthermore, Splunk can be configured to alert on multiple failed login attempts followed by a successful login from the same IP, which could indicate exploitation attempts.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [JetBrains TeamCity RCE Attempt](/web/89a58e5f-1365-4793-b45c-770abbb32b6c/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://blog.jetbrains.com/teamcity/2023/09/critical-security-issue-affecting-teamcity-on-premises-update-to-2023-05-4-now/](https://blog.jetbrains.com/teamcity/2023/09/critical-security-issue-affecting-teamcity-on-premises-update-to-2023-05-4-now/)
* [https://www.sonarsource.com/blog/teamcity-vulnerability/](https://www.sonarsource.com/blog/teamcity-vulnerability/)
* [https://github.com/rapid7/metasploit-framework/pull/18408](https://github.com/rapid7/metasploit-framework/pull/18408)
* [https://attackerkb.com/topics/1XEEEkGHzt/cve-2023-42793/rapid7-analysis](https://attackerkb.com/topics/1XEEEkGHzt/cve-2023-42793/rapid7-analysis)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/jetbrains_teamcity_unauthenticated_rce.yml) \| *version*: **1**