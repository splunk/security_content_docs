---
title: "Azure Active Directory Privilege Escalation"
last_modified_at: 2023-04-24
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

Monitor for activities and techniques associated with Privilege Escalation attacks within Azure Active Directory tenants.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Authentication](https://docs.splunk.com/Documentation/CIM/latest/User/Authentication)
- **Last Updated**: 2023-04-24
- **Author**: Mauricio Velazco, Splunk
- **ID**: ec78e872-b79c-417d-b256-8fde902522fb

#### Narrative

Privilege Escalation consists of techniques that adversaries use to gain higher-level permissions on a system or network. Adversaries can often enter and explore a network with unprivileged access but require elevated permissions to follow through on their objectives. Common approaches are to take advantage of system weaknesses, misconfigurations or vulnerabilities.\
Azure Active Directory (Azure AD) is Microsofts enterprise cloud-based identity and access management (IAM) service. Azure AD is the backbone of most of Azure services like Office 365 and Microsoft Teams. It can sync with on-premise Active Directory environments and provide authentication to other cloud-based systems via the OAuth protocol. According to Microsoft, Azure AD manages more than 1.2 billion identities and processes over 8 billion authentications per day.\
Privilege escalation attacks in Azure AD typically involve abusing  misconfigurations to gain elevated privileges, such as Global Administrator access. Once an attacker has escalated their privileges and taken full control of a tenant, they may abuse every service that leverages Azure AD including moving laterally to Azure virtual machines to access sensitive data and carry out further attacks. Security teams should monitor for privilege escalation attacks in Azure Active Directory to identify breaches before attackers achieve operational success.\
The following analytic story groups detection opportunities that seek to identify an adversary attempting to escalate privileges in Azure AD tenants.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Azure AD Application Administrator Role Assigned](/cloud/eac4de87-7a56-4538-a21b-277897af6d8d/) | [Account Manipulation](/tags/#account-manipulation), [Additional Cloud Roles](/tags/#additional-cloud-roles) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD Global Administrator Role Assigned](/cloud/825fed20-309d-4fd1-8aaf-cd49c1bb093c/) | [Additional Cloud Roles](/tags/#additional-cloud-roles) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD PIM Role Assigned](/cloud/fcd6dfeb-191c-46a0-a29c-c306382145ab/) | [Account Manipulation](/tags/#account-manipulation), [Additional Cloud Roles](/tags/#additional-cloud-roles) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD PIM Role Assignment Activated](/cloud/952e80d0-e343-439b-83f4-808c3e6fbf2e/) | [Account Manipulation](/tags/#account-manipulation), [Additional Cloud Roles](/tags/#additional-cloud-roles) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD Privileged Authentication Administrator Role Assigned](/cloud/a7da845d-6fae-41cf-b823-6c0b8c55814a/) | [Security Account Manager](/tags/#security-account-manager) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD Privileged Role Assigned to Service Principal](/cloud/5dfaa3d3-e2e4-4053-8252-16d9ee528c41/) | [Account Manipulation](/tags/#account-manipulation), [Additional Cloud Roles](/tags/#additional-cloud-roles) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD Service Principal New Client Credentials](/cloud/e3adc0d3-9e4b-4b5d-b662-12cec1adff2a/) | [Account Manipulation](/tags/#account-manipulation), [Additional Cloud Credentials](/tags/#additional-cloud-credentials) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Azure AD Service Principal Owner Added](/cloud/7ddf2084-6cf3-4a44-be83-474f7b73c701/) | [Account Manipulation](/tags/#account-manipulation) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)
* [https://cloudbrothers.info/en/azure-attack-paths/](https://cloudbrothers.info/en/azure-attack-paths/)
* [https://microsoft.github.io/Azure-Threat-Research-Matrix/PrivilegeEscalation/PrivEsc/](https://microsoft.github.io/Azure-Threat-Research-Matrix/PrivilegeEscalation/PrivEsc/)
* [https://posts.specterops.io/azure-privilege-escalation-via-service-principal-abuse-210ae2be2a5](https://posts.specterops.io/azure-privilege-escalation-via-service-principal-abuse-210ae2be2a5)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/azure_active_directory_privilege_escalation.yml) \| *version*: **1**