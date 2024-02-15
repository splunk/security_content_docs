---
title: "Azure Active Directory Account Takeover"
last_modified_at: 2022-07-14
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

Monitor for activities and techniques associated with Account Takover attacks against Azure Active Directory tenants.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Authentication](https://docs.splunk.com/Documentation/CIM/latest/User/Authentication), [Risk](https://docs.splunk.com/Documentation/CIM/latest/User/Risk)
- **Last Updated**: 2022-07-14
- **Author**: Mauricio Velazco, Splunk
- **ID**: 41514c46-7118-4eab-a9bb-f3bfa4e3bea9

#### Narrative

Azure Active Directory (Azure AD) is Microsofts enterprise cloud-based identity and access management (IAM) service. Azure AD is the backbone of most of Azure services like Office 365. It can sync with on-premise Active Directory environments and provide authentication to other cloud-based systems via the OAuth protocol. According to Microsoft, Azure AD manages more than 1.2 billion identities and processes over 8 billion authentications per day. Account Takeover (ATO) is an attack whereby cybercriminals gain unauthorized access to online accounts by using different techniques like brute force, social engineering, phishing & spear phishing, credential stuffing, etc. By posing as the real user, cyber-criminals can change account details, send out phishing emails, steal financial information or sensitive data, or use any stolen information to access further accounts within the organization. This analytic storic groups detections that can help security operations teams identify the potential compromise of Azure Active Directory accounts.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Azure AD Authentication Failed During MFA Challenge](/cloud/e62c9c2e-bf51-4719-906c-3074618fcc1c/) | [Compromise Accounts](/tags/#compromise-accounts), [Cloud Accounts](/tags/#cloud-accounts), [Valid Accounts](/tags/#valid-accounts), [Cloud Accounts](/tags/#cloud-accounts), [Multi-Factor Authentication Request Generation](/tags/#multi-factor-authentication-request-generation) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD Block User Consent For Risky Apps Disabled](/cloud/875de3d7-09bc-4916-8c0a-0929f4ced3d8/) | [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD Concurrent Sessions From Different Ips](/cloud/a9126f73-9a9b-493d-96ec-0dd06695490d/) | [Browser Session Hijacking](/tags/#browser-session-hijacking) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD Device Code Authentication](/cloud/d68d8732-6f7e-4ee5-a6eb-737f2b990b91/) | [Steal Application Access Token](/tags/#steal-application-access-token), [Phishing](/tags/#phishing), [Spearphishing Link](/tags/#spearphishing-link) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD High Number Of Failed Authentications For User](/cloud/630b1694-210a-48ee-a450-6f79e7679f2c/) | [Brute Force](/tags/#brute-force), [Password Guessing](/tags/#password-guessing) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD High Number Of Failed Authentications From Ip](/cloud/e5ab41bf-745d-4f72-a393-2611151afd8e/) | [Brute Force](/tags/#brute-force), [Password Guessing](/tags/#password-guessing), [Password Spraying](/tags/#password-spraying) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD Multi-Factor Authentication Disabled](/cloud/482dd42a-acfa-486b-a0bb-d6fcda27318e/) | [Compromise Accounts](/tags/#compromise-accounts), [Cloud Accounts](/tags/#cloud-accounts), [Modify Authentication Process](/tags/#modify-authentication-process), [Multi-Factor Authentication](/tags/#multi-factor-authentication) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD Multi-Source Failed Authentications Spike](/cloud/116e11a9-63ea-41eb-a66a-6a13bdc7d2c7/) | [Compromise Accounts](/tags/#compromise-accounts), [Cloud Accounts](/tags/#cloud-accounts), [Brute Force](/tags/#brute-force), [Password Spraying](/tags/#password-spraying), [Credential Stuffing](/tags/#credential-stuffing) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD Multiple AppIDs and UserAgents Authentication Spike](/cloud/5d8bb1f0-f65a-4b4e-af2e-fcdb88276314/) | [Valid Accounts](/tags/#valid-accounts) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD Multiple Denied MFA Requests For User](/cloud/d0895c20-de71-4fd2-b56c-3fcdb888eba1/) | [Multi-Factor Authentication Request Generation](/tags/#multi-factor-authentication-request-generation) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD Multiple Failed MFA Requests For User](/cloud/264ea131-ab1f-41b8-90e0-33ad1a1888ea/) | [Compromise Accounts](/tags/#compromise-accounts), [Cloud Accounts](/tags/#cloud-accounts), [Multi-Factor Authentication Request Generation](/tags/#multi-factor-authentication-request-generation), [Valid Accounts](/tags/#valid-accounts), [Cloud Accounts](/tags/#cloud-accounts) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD Multiple Users Failing To Authenticate From Ip](/cloud/94481a6a-8f59-4c86-957f-55a71e3612a6/) | [Compromise Accounts](/tags/#compromise-accounts), [Cloud Accounts](/tags/#cloud-accounts), [Brute Force](/tags/#brute-force), [Password Spraying](/tags/#password-spraying), [Credential Stuffing](/tags/#credential-stuffing) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD New MFA Method Registered For User](/cloud/2628b087-4189-403f-9044-87403f777a1b/) | [Modify Authentication Process](/tags/#modify-authentication-process), [Multi-Factor Authentication](/tags/#multi-factor-authentication) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD OAuth Application Consent Granted By User](/cloud/10ec9031-015b-4617-b453-c0c1ab729007/) | [Steal Application Access Token](/tags/#steal-application-access-token) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD Service Principal Authentication](/cloud/5a2ec401-60bb-474e-b936-1e66e7aa4060/) | [Cloud Accounts](/tags/#cloud-accounts) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD Successful Authentication From Different Ips](/cloud/be6d868d-33b6-4aaa-912e-724fb555b11a/) | [Brute Force](/tags/#brute-force), [Password Guessing](/tags/#password-guessing), [Password Spraying](/tags/#password-spraying) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD Successful PowerShell Authentication](/cloud/62f10052-d7b3-4e48-b57b-56f8e3ac7ceb/) | [Compromise Accounts](/tags/#compromise-accounts), [Cloud Accounts](/tags/#cloud-accounts), [Valid Accounts](/tags/#valid-accounts), [Cloud Accounts](/tags/#cloud-accounts) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD Successful Single-Factor Authentication](/cloud/a560e7f6-1711-4353-885b-40be53101fcd/) | [Compromise Accounts](/tags/#compromise-accounts), [Cloud Accounts](/tags/#cloud-accounts), [Valid Accounts](/tags/#valid-accounts), [Cloud Accounts](/tags/#cloud-accounts) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD Unusual Number of Failed Authentications From Ip](/cloud/3d8d3a36-93b8-42d7-8d91-c5f24cec223d/) | [Compromise Accounts](/tags/#compromise-accounts), [Cloud Accounts](/tags/#cloud-accounts), [Brute Force](/tags/#brute-force), [Password Spraying](/tags/#password-spraying), [Credential Stuffing](/tags/#credential-stuffing) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD User Consent Blocked for Risky Application](/cloud/06b8ec9a-d3b5-4882-8f16-04b4d10f5eab/) | [Steal Application Access Token](/tags/#steal-application-access-token) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD User Consent Denied for OAuth Application](/cloud/bb093c30-d860-4858-a56e-cd0895d5b49c/) | [Steal Application Access Token](/tags/#steal-application-access-token) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure Active Directory High Risk Sign-in](/cloud/1ecff169-26d7-4161-9a7b-2ac4c8e61bea/) | [Compromise Accounts](/tags/#compromise-accounts), [Cloud Accounts](/tags/#cloud-accounts), [Brute Force](/tags/#brute-force), [Password Spraying](/tags/#password-spraying) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/active-directory-whatis](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/active-directory-whatis)
* [https://azure.microsoft.com/en-us/services/active-directory/#overview](https://azure.microsoft.com/en-us/services/active-directory/#overview)
* [https://attack.mitre.org/techniques/T1586/](https://attack.mitre.org/techniques/T1586/)
* [https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/active-directory-compare-azure-ad-to-ad](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/active-directory-compare-azure-ad-to-ad)
* [https://www.imperva.com/learn/application-security/account-takeover-ato/](https://www.imperva.com/learn/application-security/account-takeover-ato/)
* [https://www.varonis.com/blog/azure-active-directory](https://www.varonis.com/blog/azure-active-directory)
* [https://www.barracuda.com/glossary/account-takeover](https://www.barracuda.com/glossary/account-takeover)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/azure_active_directory_account_takeover.yml) \| *version*: **2**