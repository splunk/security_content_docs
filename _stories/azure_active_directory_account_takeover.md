---
title: "Azure Active Directory Account Takeover"
last_modified_at: 2022-07-14
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Monitor for activities and techniques associated with Account Takover attacks against Azure Active Directory tenants.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2022-07-14
- **Author**: Mauricio Velazco, Splunk
- **ID**: 41514c46-7118-4eab-a9bb-f3bfa4e3bea9

#### Narrative

Azure Active Directory (Azure AD) is Microsofts enterprise cloud-based identity and access management (IAM) service. Azure AD is the backbone of most of Azure services like Office 365. It can sync with on-premise Active Directory environments and provide authentication to other cloud-based systems via the OAuth protocol. According to Microsoft, Azure AD manages more than 1.2 billion identities and processes over 8 billion authentications per day.\ Account Takeover (ATO) is an attack whereby cybercriminals gain unauthorized access to online accounts by using different techniques like brute force, social engineering, phishing & spear phishing, credential stuffing, etc. By posing as the real user, cyber-criminals can change account details, send out phishing emails, steal financial information or sensitive data, or use any stolen information to access further accounts within the organization.\ This analytic storic groups detections that can help security operations teams identify the potential compromise of Azure Active Directory accounts.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Azure AD Authentication Failed During MFA Challenge](/cloud/e62c9c2e-bf51-4719-906c-3074618fcc1c/) | [Valid Accounts](/tags/#valid-accounts), [Cloud Accounts](/tags/#cloud-accounts), [Multi-Factor Authentication Request Generation](/tags/#multi-factor-authentication-request-generation) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD Multiple Users Failing To Authenticate From Ip](/cloud/94481a6a-8f59-4c86-957f-55a71e3612a6/) | [Brute Force](/tags/#brute-force), [Password Spraying](/tags/#password-spraying) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD Successful PowerShell Authentication](/cloud/62f10052-d7b3-4e48-b57b-56f8e3ac7ceb/) | [Valid Accounts](/tags/#valid-accounts), [Cloud Accounts](/tags/#cloud-accounts) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD Successful Single-Factor Authentication](/cloud/a560e7f6-1711-4353-885b-40be53101fcd/) | [Security Account Manager](/tags/#security-account-manager) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD Unusual Number of Failed Authentications From Ip](/cloud/3d8d3a36-93b8-42d7-8d91-c5f24cec223d/) | [Brute Force](/tags/#brute-force), [Password Spraying](/tags/#password-spraying) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure Active Directory High Risk Sign-in](/cloud/1ecff169-26d7-4161-9a7b-2ac4c8e61bea/) | [Brute Force](/tags/#brute-force), [Password Spraying](/tags/#password-spraying) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/active-directory-whatis](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/active-directory-whatis)
* [https://azure.microsoft.com/en-us/services/active-directory/#overview](https://azure.microsoft.com/en-us/services/active-directory/#overview)
* [https://attack.mitre.org/techniques/T1586/](https://attack.mitre.org/techniques/T1586/)
* [https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/active-directory-compare-azure-ad-to-ad](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/active-directory-compare-azure-ad-to-ad)
* [https://www.imperva.com/learn/application-security/account-takeover-ato/](https://www.imperva.com/learn/application-security/account-takeover-ato/)
* [https://www.varonis.com/blog/azure-active-directory](https://www.varonis.com/blog/azure-active-directory)
* [https://www.barracuda.com/glossary/account-takeover](https://www.barracuda.com/glossary/account-takeover)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/azure_active_directory_account_takeover.yml) \| *version*: **2**