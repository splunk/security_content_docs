---
title: "Ivanti EPMM Remote Unauthenticated Access"
last_modified_at: 2023-07-31
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

Ivanti, a leading technology company, has disclosed two critical zero-day vulnerabilities in its Endpoint Manager Mobile (EPMM) product, CVE-2023-35078 and CVE-2023-35081. The former allows unauthenticated attackers to obtain sensitive data and modify servers, while the latter lets authenticated administrators remotely write arbitrary files to the server. Both vulnerabilities have been exploited in targeted attacks against government ministries and could be used in conjunction. Organizations are urged to apply immediate patches, as the presence of PoC code for CVE-2023-35078 increases the risk of broader exploitation. While currently leveraged in limited attacks, exploitation is likely to rise, possibly involving state-sponsored actors.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Web](https://docs.splunk.com/Documentation/CIM/latest/User/Web)
- **Last Updated**: 2023-07-31
- **Author**: Michael Haag, Splunk
- **ID**: 7e36ca54-c096-4a39-b724-6fc935164f0c

#### Narrative

Ivanti's Endpoint Manager Mobile (EPMM) product has been discovered to have two critical zero-day vulnerabilities, CVE-2023-35078 and CVE-2023-35081. The former allows remote unauthenticated attackers to access sensitive data and make changes to servers, and has been exploited in targeted attacks against Norwegian government ministries. Further investigation revealed CVE-2023-35081, a high-severity flaw enabling an authenticated attacker with administrator privileges to remotely write arbitrary files to the server. Notably, these vulnerabilities can be exploited together to bypass admin authentication and access control list (ACL) restrictions, leading to malicious file writing and OS command execution. Both have been actively exploited, possibly by state-sponsored actors, prompting urgent advisories from Ivanti and CISA. EPMM, formerly known as MobileIron Core, is widely used by IT teams to manage mobile devices, applications, and content. With thousands of potentially vulnerable internet-exposed systems and the availability of proof-of-concept code for CVE-2023-35078, the risk of broader exploitation is significant. The situation is further complicated by Ivanti's acquisition of products in 2020 that already had known flaws. These vulnerabilities represent a considerable risk to organizations using Ivanti's EPMM, and prompt patching and careful monitoring are essential to mitigate the threat.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Ivanti EPMM Remote Unauthenticated API Access CVE-2023-35078](/web/66b9c9ba-7fb2-4e80-a3a2-496e5e078167/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application), [External Remote Services](/tags/#external-remote-services) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://www.securityweek.com/second-ivanti-epmm-zero-day-vulnerability-exploited-in-targeted-attacks/](https://www.securityweek.com/second-ivanti-epmm-zero-day-vulnerability-exploited-in-targeted-attacks/)
* [https://www.cisa.gov/news-events/alerts/2023/07/28/ivanti-releases-security-updates-epmm-address-cve-2023-35081](https://www.cisa.gov/news-events/alerts/2023/07/28/ivanti-releases-security-updates-epmm-address-cve-2023-35081)
* [https://nvd.nist.gov/vuln/detail/CVE-2023-35078](https://nvd.nist.gov/vuln/detail/CVE-2023-35078)
* [https://forums.ivanti.com/s/article/CVE-2023-35078-Remote-unauthenticated-API-access-vulnerability?language=en_US](https://forums.ivanti.com/s/article/CVE-2023-35078-Remote-unauthenticated-API-access-vulnerability?language=en_US)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/ivanti_epmm_remote_unauthenticated_access.yml) \| *version*: **1**