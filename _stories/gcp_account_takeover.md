---
title: "GCP Account Takeover"
last_modified_at: 2022-10-12
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Monitor for activities and techniques associated with Account Takover attacks against Google Cloud Platform tenants.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2022-10-12
- **Author**: Mauricio Velazco, Bhavin Patel, Splunk
- **ID**: 8601caff-414f-4c6d-9a04-75b66778869d

#### Narrative

Account Takeover (ATO) is an attack whereby cybercriminals gain unauthorized access to online accounts by using different techniques like brute force, social engineering, phishing & spear phishing, credential stuffing, etc. By posing as the real user, cyber-criminals can change account details, send out phishing emails, steal financial information or sensitive data, or use any stolen information to access further accounts within the organization. This analytic storic groups detections that can help security operations teams identify the potential compromise of Azure Active Directory accounts.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [GCP Authentication Failed During MFA Challenge](/cloud/345f7e1d-a3fe-4158-abd8-e630f9878323/) | [Valid Accounts](/tags/#valid-accounts), [Cloud Accounts](/tags/#cloud-accounts), [Multi-Factor Authentication Request Generation](/tags/#multi-factor-authentication-request-generation) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GCP Multi-Factor Authentication Disabled](/cloud/b9bc5513-6fc1-4821-85a3-e1d81e451c83/) | [Modify Authentication Process](/tags/#modify-authentication-process) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GCP Multiple Failed MFA Requests For User](/cloud/cbb3cb84-c06f-4393-adcc-5cb6195621f1/) | [Multi-Factor Authentication Request Generation](/tags/#multi-factor-authentication-request-generation), [Valid Accounts](/tags/#valid-accounts), [Cloud Accounts](/tags/#cloud-accounts) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GCP Multiple Users Failing To Authenticate From Ip](/cloud/da20828e-d6fb-4ee5-afb7-d0ac200923d5/) | [Password Spraying](/tags/#password-spraying) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GCP Successful Single-Factor Authentication](/cloud/40e17d88-87da-414e-b253-8dc1e4f9555b/) | [Valid Accounts](/tags/#valid-accounts), [Cloud Accounts](/tags/#cloud-accounts) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GCP Unusual Number of Failed Authentications From Ip](/cloud/bd8097ed-958a-4873-87d9-44f2b4d85705/) | [Password Spraying](/tags/#password-spraying) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://cloud.google.com/gcp](https://cloud.google.com/gcp)
* [https://cloud.google.com/architecture/identity/overview-google-authentication](https://cloud.google.com/architecture/identity/overview-google-authentication)
* [https://attack.mitre.org/techniques/T1586/](https://attack.mitre.org/techniques/T1586/)
* [https://www.imperva.com/learn/application-security/account-takeover-ato/](https://www.imperva.com/learn/application-security/account-takeover-ato/)
* [https://www.barracuda.com/glossary/account-takeover](https://www.barracuda.com/glossary/account-takeover)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/gcp_account_takeover.yml) \| *version*: **1**