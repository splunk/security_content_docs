---
title: "Ivanti EPMM Remote Unauthenticated Access"
last_modified_at: 2023-08-08
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

Ivanti, a leading technology company, has disclosed two critical zero-day vulnerabilities in its Endpoint Manager Mobile (EPMM) product, CVE-2023-35078 and CVE-2023-35081. A recent update concerning CVE-2023-35082, closely related to CVE-2023-35078, reveals its impact on more versions of Ivanti's software than initially believed. The former allows unauthenticated attackers to obtain sensitive data, modify servers, and access the API, potentially leading to data breaches or malicious system modifications. Meanwhile, CVE-2023-35081 lets authenticated administrators remotely write arbitrary files to the server. Both vulnerabilities have been exploited in targeted attacks against government ministries and could be used in conjunction. With the presence of PoC code for CVE-2023-35078, the risk of broader exploitation has increased. While initially leveraged in limited attacks, the exploitation is expected to rise, possibly involving state-sponsored actors. Organizations are urged to apply immediate patches and conduct regular system assessments to ensure security.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Web](https://docs.splunk.com/Documentation/CIM/latest/User/Web)
- **Last Updated**: 2023-08-08
- **Author**: Michael Haag, Splunk
- **ID**: 7e36ca54-c096-4a39-b724-6fc935164f0c

#### Narrative

Ivantis Endpoint Manager Mobile (EPMM) product, formerly known as MobileIron Core and extensively utilized by IT teams to manage mobile devices, applications, and content, has been found to harbor several critical vulnerabilities. Specifically, CVE-2023-35078 allows remote unauthenticated attackers to access sensitive data and make changes to servers. This flaw has been leveraged in targeted attacks against Norwegian government ministries. In addition, CVE-2023-35081 permits an authenticated attacker with administrative privileges to remotely write arbitrary files to the server. \
Recently, attention has shifted to CVE-2023-35082, which was initially believed to affect only MobileIron Core 11.2 and below. Subsequent investigations revealed its wider influence, affecting EPMM versions 11.10, 11.9, 11.8, and MobileIron Core 11.7 and earlier. This vulnerability facilitates unauthorized access to the API via the URI path /mifs/asfV3/api/v2/. \
When combined, these vulnerabilities can be exploited to bypass administrative authentication and access control list (ACL) restrictions, leading to malicious file writing and potential OS command execution. Both have been actively exploited, possibly by state-sponsored actors, prompting urgent advisories from Ivanti and Rapid7, alongside CISA. Given the thousands of potentially vulnerable internet-exposed systems and the presence of PoC code for CVE-2023-35078, the risk of extensive exploitation escalates. The situation is further muddled by Ivanti's 2020 acquisition of MobileIron, which had its known issues. Collectively, these vulnerabilities present a significant risk to organizations utilizing Ivanti's EPMM, emphasizing the need for swift patching, vigilant monitoring, and timely application of fixes to counteract potential threats.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Ivanti EPMM Remote Unauthenticated API Access CVE-2023-35078](/web/66b9c9ba-7fb2-4e80-a3a2-496e5e078167/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application), [External Remote Services](/tags/#external-remote-services) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Ivanti EPMM Remote Unauthenticated API Access CVE-2023-35082](/web/e03edeba-4942-470c-a664-27253f3ad351/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application), [External Remote Services](/tags/#external-remote-services) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://www.securityweek.com/second-ivanti-epmm-zero-day-vulnerability-exploited-in-targeted-attacks/](https://www.securityweek.com/second-ivanti-epmm-zero-day-vulnerability-exploited-in-targeted-attacks/)
* [https://www.cisa.gov/news-events/alerts/2023/07/28/ivanti-releases-security-updates-epmm-address-cve-2023-35081](https://www.cisa.gov/news-events/alerts/2023/07/28/ivanti-releases-security-updates-epmm-address-cve-2023-35081)
* [https://nvd.nist.gov/vuln/detail/CVE-2023-35078](https://nvd.nist.gov/vuln/detail/CVE-2023-35078)
* [https://forums.ivanti.com/s/article/CVE-2023-35078-Remote-unauthenticated-API-access-vulnerability?language=en_US](https://forums.ivanti.com/s/article/CVE-2023-35078-Remote-unauthenticated-API-access-vulnerability?language=en_US)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/ivanti_epmm_remote_unauthenticated_access.yml) \| *version*: **2**