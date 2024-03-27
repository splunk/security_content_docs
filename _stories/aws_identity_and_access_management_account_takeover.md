---
title: "AWS Identity and Access Management Account Takeover"
last_modified_at: 2022-08-19
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Authentication
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Identify activity and techniques associated with accessing credential files from AWS resources, monitor unusual authentication related activities to the AWS Console and other services such as RDS.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Authentication](https://docs.splunk.com/Documentation/CIM/latest/User/Authentication)
- **Last Updated**: 2022-08-19
- **Author**: Gowthamaraj Rajendran, Bhavin Patel,  Splunk
- **ID**: 4210b690-293f-411d-a9d8-bcfb2ea5fff9

#### Narrative

Amazon Web Services provides a web service known as Identity and Access Management(IAM) for controlling and securly managing various AWS resources. This is basically the foundation of how users in AWS interact with various resources/services in cloud and vice versa. Account Takeover (ATO) is an attack whereby cybercriminals gain unauthorized access to online accounts by using different techniques like brute force, social engineering, phishing & spear phishing, credential stuffing, etc. Adversaries employ a variety of techniques to steal AWS Cloud credentials like account names, passwords and keys and takeover legitmate user accounts. Usage of legitimate keys will assist the attackers to gain access to other sensitive system and they can also mimic legitimate behaviour making them harder to be detected. Such activity may involve multiple failed login to the console, new console logins and password reset activities.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [ASL AWS Concurrent Sessions From Different Ips](/cloud/b3424bbe-3204-4469-887b-ec144483a336/) | [Browser Session Hijacking](/tags/#browser-session-hijacking) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [ASL AWS Multi-Factor Authentication Disabled](/cloud/4d2df5e0-1092-4817-88a8-79c7fa054668/) | [Compromise Accounts](/tags/#compromise-accounts), [Cloud Accounts](/tags/#cloud-accounts), [Multi-Factor Authentication Request Generation](/tags/#multi-factor-authentication-request-generation), [Modify Authentication Process](/tags/#modify-authentication-process), [Multi-Factor Authentication](/tags/#multi-factor-authentication) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [ASL AWS New MFA Method Registered For User](/cloud/33ae0931-2a03-456b-b1d7-b016c5557fbd/) | [Modify Authentication Process](/tags/#modify-authentication-process), [Multi-Factor Authentication](/tags/#multi-factor-authentication) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [AWS Concurrent Sessions From Different Ips](/cloud/51c04fdb-2746-465a-b86e-b413a09c9085/) | [Browser Session Hijacking](/tags/#browser-session-hijacking) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [AWS Console Login Failed During MFA Challenge](/cloud/55349868-5583-466f-98ab-d3beb321961e/) | [Compromise Accounts](/tags/#compromise-accounts), [Cloud Accounts](/tags/#cloud-accounts), [Multi-Factor Authentication Request Generation](/tags/#multi-factor-authentication-request-generation) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [AWS Credential Access Failed Login](/cloud/a19b354d-0d7f-47f3-8ea6-1a7c36434968/) | [Compromise Accounts](/tags/#compromise-accounts), [Cloud Accounts](/tags/#cloud-accounts), [Brute Force](/tags/#brute-force), [Password Guessing](/tags/#password-guessing) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [AWS Credential Access GetPasswordData](/cloud/4d347c4a-306e-41db-8d10-b46baf71b3e2/) | [Compromise Accounts](/tags/#compromise-accounts), [Cloud Accounts](/tags/#cloud-accounts), [Brute Force](/tags/#brute-force), [Password Guessing](/tags/#password-guessing) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [AWS Credential Access RDS Password reset](/cloud/6153c5ea-ed30-4878-81e6-21ecdb198189/) | [Compromise Accounts](/tags/#compromise-accounts), [Cloud Accounts](/tags/#cloud-accounts), [Brute Force](/tags/#brute-force) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [AWS High Number Of Failed Authentications For User](/cloud/e3236f49-daf3-4b70-b808-9290912ac64d/) | [Password Policy Discovery](/tags/#password-policy-discovery) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [AWS High Number Of Failed Authentications From Ip](/cloud/f75b7f1a-b8eb-4975-a214-ff3e0a944757/) | [Brute Force](/tags/#brute-force), [Password Spraying](/tags/#password-spraying), [Credential Stuffing](/tags/#credential-stuffing) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [AWS Multi-Factor Authentication Disabled](/cloud/374832b1-3603-420c-b456-b373e24d34c0/) | [Compromise Accounts](/tags/#compromise-accounts), [Cloud Accounts](/tags/#cloud-accounts), [Multi-Factor Authentication Request Generation](/tags/#multi-factor-authentication-request-generation), [Modify Authentication Process](/tags/#modify-authentication-process), [Multi-Factor Authentication](/tags/#multi-factor-authentication) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [AWS Multiple Failed MFA Requests For User](/cloud/1fece617-e614-4329-9e61-3ba228c0f353/) | [Compromise Accounts](/tags/#compromise-accounts), [Cloud Accounts](/tags/#cloud-accounts), [Multi-Factor Authentication Request Generation](/tags/#multi-factor-authentication-request-generation) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [AWS Multiple Users Failing To Authenticate From Ip](/cloud/71e1fb89-dd5f-4691-8523-575420de4630/) | [Brute Force](/tags/#brute-force), [Password Spraying](/tags/#password-spraying), [Credential Stuffing](/tags/#credential-stuffing) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [AWS New MFA Method Registered For User](/cloud/4e3c26f2-4fb9-4bd7-ab46-1b76ffa2a23b/) | [Modify Authentication Process](/tags/#modify-authentication-process), [Multi-Factor Authentication](/tags/#multi-factor-authentication) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [AWS Successful Single-Factor Authentication](/cloud/a520b1fe-cc9e-4f56-b762-18354594c52f/) | [Compromise Accounts](/tags/#compromise-accounts), [Cloud Accounts](/tags/#cloud-accounts), [Valid Accounts](/tags/#valid-accounts), [Cloud Accounts](/tags/#cloud-accounts) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [AWS Unusual Number of Failed Authentications From Ip](/cloud/0b5c9c2b-e2cb-4831-b4f1-af125ceb1386/) | [Compromise Accounts](/tags/#compromise-accounts), [Cloud Accounts](/tags/#cloud-accounts), [Brute Force](/tags/#brute-force), [Password Spraying](/tags/#password-spraying), [Credential Stuffing](/tags/#credential-stuffing) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect AWS Console Login by New User](/cloud/bc91a8cd-35e7-4bb2-6140-e756cc46fd71/) | [Compromise Accounts](/tags/#compromise-accounts), [Cloud Accounts](/tags/#cloud-accounts), [Unsecured Credentials](/tags/#unsecured-credentials) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect AWS Console Login by User from New City](/cloud/121b0b11-f8ac-4ed6-a132-3800ca4fc07a/) | [Compromise Accounts](/tags/#compromise-accounts), [Cloud Accounts](/tags/#cloud-accounts), [Unused/Unsupported Cloud Regions](/tags/#unused/unsupported-cloud-regions) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect AWS Console Login by User from New Country](/cloud/67bd3def-c41c-4bf6-837b-ae196b4257c6/) | [Compromise Accounts](/tags/#compromise-accounts), [Cloud Accounts](/tags/#cloud-accounts), [Unused/Unsupported Cloud Regions](/tags/#unused/unsupported-cloud-regions) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect AWS Console Login by User from New Region](/cloud/9f31aa8e-e37c-46bc-bce1-8b3be646d026/) | [Compromise Accounts](/tags/#compromise-accounts), [Cloud Accounts](/tags/#cloud-accounts), [Unused/Unsupported Cloud Regions](/tags/#unused/unsupported-cloud-regions) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://attack.mitre.org/tactics/TA0006/](https://attack.mitre.org/tactics/TA0006/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/aws_identity_and_access_management_account_takeover.yml) \| *version*: **2**