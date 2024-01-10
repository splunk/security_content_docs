---
title: "Office 365 Account Takeover"
last_modified_at: 2023-10-17
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Authentication
  - Risk
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Monitor for activities and anomalies indicative of initial access techniques within Office 365 environments.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Authentication](https://docs.splunk.com/Documentation/CIM/latest/User/Authentication), [Risk](https://docs.splunk.com/Documentation/CIM/latest/User/Risk)
- **Last Updated**: 2023-10-17
- **Author**: Mauricio Velazco, Patrick Bareiss, Splunk
- **ID**: 7dcea963-af44-4db7-a5b9-fd2b543d9bc9

#### Narrative

Office 365 (O365) is Microsoft's cloud-based suite of productivity tools, encompassing email, collaboration platforms, and office applications, all integrated with Azure Active Directory for identity and access management. O365's centralized storage of sensitive data and widespread adoption make it a key asset, yet also a prime target for security threats. The "Office 365 Account Takeover" analytic story focuses on the initial techniques attackers employ to breach or compromise these identities. Initial access, in this context, consists of techniques that use various entry vectors to gain their initial foothold . Identifying these early indicators is crucial for establishing the first line of defense against unauthorized access and potential security incidents within O365 environments.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [High Number of Login Failures from a single source](/cloud/7f398cfb-918d-41f4-8db8-2e2474e02222/) | [Password Guessing](/tags/#password-guessing), [Brute Force](/tags/#brute-force) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 Block User Consent For Risky Apps Disabled](/cloud/12a23592-e3da-4344-8545-205d3290647c/) | [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 Concurrent Sessions From Different Ips](/cloud/58e034de-1f87-4812-9dc3-a4f68c7db930/) | [Browser Session Hijacking](/tags/#browser-session-hijacking) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 Excessive Authentication Failures Alert](/cloud/d441364c-349c-453b-b55f-12eccab67cf9/) | [Brute Force](/tags/#brute-force) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 Excessive SSO logon errors](/cloud/8158ccc4-6038-11eb-ae93-0242ac130002/) | [Modify Authentication Process](/tags/#modify-authentication-process) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 File Permissioned Application Consent Granted by User](/cloud/6c382336-22b8-4023-9b80-1689e799f21f/) | [Steal Application Access Token](/tags/#steal-application-access-token) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 High Number Of Failed Authentications for User](/cloud/31641378-2fa9-42b1-948e-25e281cb98f7/) | [Brute Force](/tags/#brute-force), [Password Guessing](/tags/#password-guessing) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 Mail Permissioned Application Consent Granted by User](/cloud/fddad083-cdf5-419d-83c6-baa85e329595/) | [Steal Application Access Token](/tags/#steal-application-access-token) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 Multi-Source Failed Authentications Spike](/cloud/ea4e2c41-dbfb-4f5f-a7b6-9ac1b7f104aa/) | [Compromise Accounts](/tags/#compromise-accounts), [Cloud Accounts](/tags/#cloud-accounts), [Brute Force](/tags/#brute-force), [Password Spraying](/tags/#password-spraying), [Credential Stuffing](/tags/#credential-stuffing) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 Multiple AppIDs and UserAgents Authentication Spike](/cloud/66adc486-224d-45c1-8e4d-9e7eeaba988f/) | [Valid Accounts](/tags/#valid-accounts) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 Multiple Failed MFA Requests For User](/cloud/fd22124e-dbac-4744-a8ce-be10d8ec3e26/) | [Multi-Factor Authentication Request Generation](/tags/#multi-factor-authentication-request-generation) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 Multiple Users Failing To Authenticate From Ip](/cloud/8d486e2e-3235-4cfe-ac35-0d042e24ecb4/) | [Compromise Accounts](/tags/#compromise-accounts), [Cloud Accounts](/tags/#cloud-accounts), [Brute Force](/tags/#brute-force), [Password Spraying](/tags/#password-spraying), [Credential Stuffing](/tags/#credential-stuffing) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 User Consent Blocked for Risky Application](/cloud/242e4d30-cb59-4051-b0cf-58895e218f40/) | [Steal Application Access Token](/tags/#steal-application-access-token) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 User Consent Denied for OAuth Application](/cloud/2d8679ef-b075-46be-8059-c25116cb1072/) | [Steal Application Access Token](/tags/#steal-application-access-token) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://docs.microsoft.com/en-us/security/compass/incident-response-playbook-password-spray](https://docs.microsoft.com/en-us/security/compass/incident-response-playbook-password-spray)
* [https://www.cisa.gov/uscert/ncas/alerts/aa21-008a](https://www.cisa.gov/uscert/ncas/alerts/aa21-008a)
* [https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-sign-ins-error-codes](https://docs.microsoft.com/azure/active-directory/reports-monitoring/reference-sign-ins-error-codes)
* [https://attack.mitre.org/tactics/TA0001/](https://attack.mitre.org/tactics/TA0001/)
* [https://stealthbits.com/blog/bypassing-mfa-with-pass-the-cookie/](https://stealthbits.com/blog/bypassing-mfa-with-pass-the-cookie/)
* [https://www.microsoft.com/en-us/security/blog/2022/09/22/malicious-oauth-applications-used-to-compromise-email-servers-and-spread-spam/](https://www.microsoft.com/en-us/security/blog/2022/09/22/malicious-oauth-applications-used-to-compromise-email-servers-and-spread-spam/)
* [https://learn.microsoft.com/en-us/defender-cloud-apps/investigate-risky-oauth](https://learn.microsoft.com/en-us/defender-cloud-apps/investigate-risky-oauth)
* [https://www.alteredsecurity.com/post/introduction-to-365-stealer](https://www.alteredsecurity.com/post/introduction-to-365-stealer)
* [https://github.com/AlteredSecurity/365-Stealer](https://github.com/AlteredSecurity/365-Stealer)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/office_365_account_takeover.yml) \| *version*: **1**