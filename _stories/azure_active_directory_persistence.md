---
title: "Azure Active Directory Persistence"
last_modified_at: 2022-08-17
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

Monitor for activities and techniques associated with the execution of Persistence techniques against Azure Active Directory tenants.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Authentication](https://docs.splunk.com/Documentation/CIM/latest/User/Authentication)
- **Last Updated**: 2022-08-17
- **Author**: Mauricio Velazco, Splunk
- **ID**: dca983db-6334-4a0d-be32-80611ca1396c

#### Narrative

Azure Active Directory (Azure AD) is Microsofts enterprise cloud-based identity and access management (IAM) service. Azure AD is the backbone of most of Azure services like Office 365. It can sync with on-premise Active Directory environments and provide authentication to other cloud-based systems via the OAuth protocol. According to Microsoft, Azure AD manages more than 1.2 billion identities and processes over 8 billion authentications per day.\ Persistence consists of techniques that adversaries use to keep access to systems across restarts, changed credentials, and other interruptions that could cut off their access. This analytic storic groups detections that can help security operations teams identify the potential execution of Persistence techniques targeting Azure Active Directory tenants. 

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Azure AD External Guest User Invited](/cloud/c1fb4edb-cab1-4359-9b40-925ffd797fb5/) | [Cloud Account](/tags/#cloud-account) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD Global Administrator Role Assigned](/cloud/825fed20-309d-4fd1-8aaf-cd49c1bb093c/) | [Additional Cloud Roles](/tags/#additional-cloud-roles) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD New Custom Domain Added](/cloud/30c47f45-dd6a-4720-9963-0bca6c8686ef/) | [Domain Policy Modification](/tags/#domain-policy-modification), [Domain Trust Modification](/tags/#domain-trust-modification) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD New Federated Domain Added](/cloud/a87cd633-076d-4ab2-9047-977751a3c1a0/) | [Domain Policy Modification](/tags/#domain-policy-modification), [Domain Trust Modification](/tags/#domain-trust-modification) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD New MFA Method Registered](/cloud/0488e814-eb81-42c3-9f1f-b2244973e3a3/) | [Account Manipulation](/tags/#account-manipulation), [Device Registration](/tags/#device-registration) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD PIM Role Assigned](/cloud/fcd6dfeb-191c-46a0-a29c-c306382145ab/) | [Account Manipulation](/tags/#account-manipulation), [Additional Cloud Roles](/tags/#additional-cloud-roles) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD PIM Role Assignment Activated](/cloud/952e80d0-e343-439b-83f4-808c3e6fbf2e/) | [Account Manipulation](/tags/#account-manipulation), [Additional Cloud Roles](/tags/#additional-cloud-roles) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD Privileged Role Assigned](/cloud/a28f0bc3-3400-4a6e-a2da-89b9e95f0d2a/) | [Account Manipulation](/tags/#account-manipulation), [Additional Cloud Roles](/tags/#additional-cloud-roles) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD Service Principal Created](/cloud/f8ba49e7-ffd3-4b53-8f61-e73974583c5d/) | [Cloud Account](/tags/#cloud-account) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD Service Principal New Client Credentials](/cloud/e3adc0d3-9e4b-4b5d-b662-12cec1adff2a/) | [Account Manipulation](/tags/#account-manipulation), [Additional Cloud Credentials](/tags/#additional-cloud-credentials) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD Service Principal Owner Added](/cloud/7ddf2084-6cf3-4a44-be83-474f7b73c701/) | [Account Manipulation](/tags/#account-manipulation) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD Tenant Wide Admin Consent Granted](/cloud/dc02c0ee-6ac0-4c7f-87ba-8ce43a4e4418/) | [Account Manipulation](/tags/#account-manipulation), [Additional Cloud Roles](/tags/#additional-cloud-roles) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD User Enabled And Password Reset](/cloud/1347b9e8-2daa-4a6f-be73-b421d3d9e268/) | [Account Manipulation](/tags/#account-manipulation) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD User ImmutableId Attribute Updated](/cloud/0c0badad-4536-4a84-a561-5ff760f3c00e/) | [Account Manipulation](/tags/#account-manipulation) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure Automation Account Created](/cloud/860902fd-2e76-46b3-b050-ba548dab576c/) | [Create Account](/tags/#create-account), [Cloud Account](/tags/#cloud-account) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure Automation Runbook Created](/cloud/178d696d-6dc6-4ee8-9d25-93fee34eaf5b/) | [Create Account](/tags/#create-account), [Cloud Account](/tags/#cloud-account) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure Runbook Webhook Created](/cloud/e98944a9-92e4-443c-81b8-a322e33ce75a/) | [Valid Accounts](/tags/#valid-accounts), [Cloud Accounts](/tags/#cloud-accounts) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/active-directory-whatis](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/active-directory-whatis)
* [https://azure.microsoft.com/en-us/services/active-directory/#overview](https://azure.microsoft.com/en-us/services/active-directory/#overview)
* [https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/active-directory-compare-azure-ad-to-ad](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/active-directory-compare-azure-ad-to-ad)
* [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)
* [https://microsoft.github.io/Azure-Threat-Research-Matrix/Persistence/Persistence/](https://microsoft.github.io/Azure-Threat-Research-Matrix/Persistence/Persistence/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/azure_active_directory_persistence.yml) \| *version*: **1**