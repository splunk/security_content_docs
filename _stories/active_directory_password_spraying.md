---
title: "Active Directory Password Spraying"
last_modified_at: 2021-04-07
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Monitor for activities and techniques associated with Password Spraying attacks within Active Directory environments.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2021-04-07
- **Author**: Mauricio Velazco, Splunk
- **ID**: 3de109da-97d2-11eb-8b6a-acde48001122

#### Narrative

In a password spraying attack, adversaries leverage one or a small list of commonly used / popular passwords against a large volume of usernames to acquire valid account credentials. Unlike a Brute Force attack that targets a specific user or small group of users with a large number of passwords, password spraying follows the opposite aproach and increases the chances of obtaining valid credentials while avoiding account lockouts. This allows adversaries to remain undetected if the target organization does not have the proper monitoring and detection controls in place.\
Password Spraying can be leveraged by adversaries across different stages in an attack. It can be used to obtain an iniial access to an environment but can also be used to escalate privileges when access has been already achieved. In some scenarios, this technique capitalizes on a security policy most organizations implement, password rotation. As enterprise users change their passwords, it is possible some pick predictable, seasonal passwords such as `$CompanyNameWinter`, `Summer2021`, etc.\
Specifically, this Analytic Story is focused on detecting possible Password Spraying attacks against Active Directory environments leveraging Windows Event Logs in the `Account Logon` and `Logon/Logoff` Advanced Audit Policy categories. It presents 16 detection analytics which can aid defenders in identifying instances where one source user, source host or source process attempts to authenticate against a target or targets using a high or statiscally unsual, number of unique users. A user, host or process attempting to authenticate with multiple users is not common behavior for legitimate systems and should be monitored by security teams. Possible false positive scenarios include but are not limited to vulnerability scanners, remote administration tools, multi-user systems and missconfigured systems. These should be easily spotted when first implementing the detection and addded to an allow list or lookup table. The presented detections can also be used in Threat Hunting exercises.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Windows Multiple Disabled Users Failed To Authenticate Wth Kerberos](/endpoint/98f22d82-9d62-11eb-9fcf-acde48001122/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Multiple Invalid Users Fail To Authenticate Using Kerberos](/endpoint/001266a6-9d5b-11eb-829b-acde48001122/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Multiple Invalid Users Failed To Authenticate Using NTLM](/endpoint/57ad5a64-9df7-11eb-a290-acde48001122/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Multiple Users Fail To Authenticate Wth ExplicitCredentials](/endpoint/e61918fa-9ca4-11eb-836c-acde48001122/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Multiple Users Failed To Authenticate From Host Using NTLM](/endpoint/7ed272a4-9c77-11eb-af22-acde48001122/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Multiple Users Failed To Authenticate From Process](/endpoint/9015385a-9c84-11eb-bef2-acde48001122/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Multiple Users Failed To Authenticate Using Kerberos](/endpoint/3a91a212-98a9-11eb-b86a-acde48001122/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Multiple Users Remotely Failed To Authenticate From Host](/endpoint/80f9d53e-9ca1-11eb-b0d6-acde48001122/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Unusual Count Of Disabled Users Failed Auth Using Kerberos](/endpoint/f65aa026-b811-42ab-b4b9-d9088137648f/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Unusual Count Of Invalid Users Fail To Auth Using Kerberos](/endpoint/f122cb2e-d773-4f11-8399-62a3572d8dd7/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Unusual Count Of Invalid Users Failed To Auth Using NTLM](/endpoint/15603165-147d-4a6e-9778-bd0ff39e668f/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Unusual Count Of Users Fail To Auth Wth ExplicitCredentials](/endpoint/14f414cf-3080-4b9b-aaf6-55a4ce947b93/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Unusual Count Of Users Failed To Auth Using Kerberos](/endpoint/bc9cb715-08ba-40c3-9758-6e2b26e455cb/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Unusual Count Of Users Failed To Authenticate From Process](/endpoint/25bdb6cb-2e49-4d34-a93c-d6c567c122fe/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Unusual Count Of Users Failed To Authenticate Using NTLM](/endpoint/6f6c8fd7-6a6b-4af9-a0e9-57cfc47a58b4/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Unusual Count Of Users Remotely Failed To Auth From Host](/endpoint/cf06a0ee-ffa9-4ed3-be77-0670ed9bab52/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://attack.mitre.org/techniques/T1110/003/](https://attack.mitre.org/techniques/T1110/003/)
* [https://www.microsoft.com/security/blog/2020/04/23/protecting-organization-password-spray-attacks/](https://www.microsoft.com/security/blog/2020/04/23/protecting-organization-password-spray-attacks/)
* [https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn452415(v=ws.11)](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn452415(v=ws.11))



[*source*](https://github.com/splunk/security_content/tree/develop/stories/active_directory_password_spraying.yml) \| *version*: **2**