---
title: "Compromised User Account"
last_modified_at: 2023-01-19
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Authentication
  - Change
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Monitor for activities and techniques associated with Compromised User Account attacks.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Authentication](https://docs.splunk.com/Documentation/CIM/latest/User/Authentication), [Change](https://docs.splunk.com/Documentation/CIM/latest/User/Change)
- **Last Updated**: 2023-01-19
- **Author**: Mauricio Velazco, Bhavin Patel, Splunk
- **ID**: 19669154-e9d1-4a01-b144-e6592a078092

#### Narrative

Compromised User Account occurs when cybercriminals gain unauthorized access to accounts by using different techniques like brute force, social engineering, phishing & spear phishing, credential stuffing, etc. By posing as the real user, cyber-criminals can change account details, send out phishing emails, steal financial information or sensitive data, or use any stolen information to access further accounts within the organization. This analytic storic groups detections that can help security operations teams identify the potential signs of Compromised User Accounts.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [ASL AWS Concurrent Sessions From Different Ips](/cloud/b3424bbe-3204-4469-887b-ec144483a336/) | [Browser Session Hijacking](/tags/#browser-session-hijacking) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [ASL AWS New MFA Method Registered For User](/cloud/33ae0931-2a03-456b-b1d7-b016c5557fbd/) | [Modify Authentication Process](/tags/#modify-authentication-process), [Multi-Factor Authentication](/tags/#multi-factor-authentication) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [ASL AWS Password Policy Changes](/cloud/5ade5937-11a2-4363-ba6b-39a3ee8d5b1a/) | [Password Policy Discovery](/tags/#password-policy-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [AWS Concurrent Sessions From Different Ips](/cloud/51c04fdb-2746-465a-b86e-b413a09c9085/) | [Browser Session Hijacking](/tags/#browser-session-hijacking) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [AWS Console Login Failed During MFA Challenge](/cloud/55349868-5583-466f-98ab-d3beb321961e/) | [Compromise Accounts](/tags/#compromise-accounts), [Cloud Accounts](/tags/#cloud-accounts), [Multi-Factor Authentication Request Generation](/tags/#multi-factor-authentication-request-generation) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [AWS High Number Of Failed Authentications For User](/cloud/e3236f49-daf3-4b70-b808-9290912ac64d/) | [Password Policy Discovery](/tags/#password-policy-discovery) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [AWS High Number Of Failed Authentications From Ip](/cloud/f75b7f1a-b8eb-4975-a214-ff3e0a944757/) | [Brute Force](/tags/#brute-force), [Password Spraying](/tags/#password-spraying), [Credential Stuffing](/tags/#credential-stuffing) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [AWS Multiple Users Failing To Authenticate From Ip](/cloud/71e1fb89-dd5f-4691-8523-575420de4630/) | [Brute Force](/tags/#brute-force), [Password Spraying](/tags/#password-spraying), [Credential Stuffing](/tags/#credential-stuffing) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [AWS New MFA Method Registered For User](/cloud/4e3c26f2-4fb9-4bd7-ab46-1b76ffa2a23b/) | [Modify Authentication Process](/tags/#modify-authentication-process), [Multi-Factor Authentication](/tags/#multi-factor-authentication) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [AWS Password Policy Changes](/cloud/aee4a575-7064-4e60-b511-246f9baf9895/) | [Password Policy Discovery](/tags/#password-policy-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [AWS Successful Console Authentication From Multiple IPs](/cloud/395e50e1-2b87-4fa3-8632-0dfbdcbcd2cb/) | [Compromise Accounts](/tags/#compromise-accounts), [Unused/Unsupported Cloud Regions](/tags/#unused/unsupported-cloud-regions) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Abnormally High Number Of Cloud Infrastructure API Calls](/cloud/0840ddf1-8c89-46ff-b730-c8d6722478c0/) | [Cloud Accounts](/tags/#cloud-accounts), [Valid Accounts](/tags/#valid-accounts) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD Concurrent Sessions From Different Ips](/cloud/a9126f73-9a9b-493d-96ec-0dd06695490d/) | [Browser Session Hijacking](/tags/#browser-session-hijacking) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD High Number Of Failed Authentications For User](/cloud/630b1694-210a-48ee-a450-6f79e7679f2c/) | [Brute Force](/tags/#brute-force), [Password Guessing](/tags/#password-guessing) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD High Number Of Failed Authentications From Ip](/cloud/e5ab41bf-745d-4f72-a393-2611151afd8e/) | [Brute Force](/tags/#brute-force), [Password Guessing](/tags/#password-guessing), [Password Spraying](/tags/#password-spraying) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD New MFA Method Registered For User](/cloud/2628b087-4189-403f-9044-87403f777a1b/) | [Modify Authentication Process](/tags/#modify-authentication-process), [Multi-Factor Authentication](/tags/#multi-factor-authentication) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD Successful Authentication From Different Ips](/cloud/be6d868d-33b6-4aaa-912e-724fb555b11a/) | [Brute Force](/tags/#brute-force), [Password Guessing](/tags/#password-guessing), [Password Spraying](/tags/#password-spraying) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect AWS Console Login by User from New City](/cloud/121b0b11-f8ac-4ed6-a132-3800ca4fc07a/) | [Compromise Accounts](/tags/#compromise-accounts), [Cloud Accounts](/tags/#cloud-accounts), [Unused/Unsupported Cloud Regions](/tags/#unused/unsupported-cloud-regions) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect AWS Console Login by User from New Country](/cloud/67bd3def-c41c-4bf6-837b-ae196b4257c6/) | [Compromise Accounts](/tags/#compromise-accounts), [Cloud Accounts](/tags/#cloud-accounts), [Unused/Unsupported Cloud Regions](/tags/#unused/unsupported-cloud-regions) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect AWS Console Login by User from New Region](/cloud/9f31aa8e-e37c-46bc-bce1-8b3be646d026/) | [Compromise Accounts](/tags/#compromise-accounts), [Cloud Accounts](/tags/#cloud-accounts), [Unused/Unsupported Cloud Regions](/tags/#unused/unsupported-cloud-regions) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://www.proofpoint.com/us/threat-reference/compromised-account](https://www.proofpoint.com/us/threat-reference/compromised-account)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/compromised_user_account.yml) \| *version*: **1**