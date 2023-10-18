---
title: "Active Directory Privilege Escalation"
last_modified_at: 2023-03-20
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Risk
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Monitor for activities and techniques associated with Privilege Escalation attacks within Active Directory environments.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Risk](https://docs.splunk.com/Documentation/CIM/latest/User/Risk)
- **Last Updated**: 2023-03-20
- **Author**: Mauricio Velazco, Splunk
- **ID**: fa34a5d8-df0a-404c-8237-11f99cba1d5f

#### Narrative

Privilege Escalation consists of techniques that adversaries use to gain higher-level permissions on a system or network. Adversaries can often enter and explore a network with unprivileged access but require elevated permissions to follow through on their objectives. Common approaches are to take advantage of system weaknesses, misconfigurations, and vulnerabilities.\
Active Directory is a central component of most enterprise networks, providing authentication and authorization services for users, computers, and other resources. It stores sensitive information such as passwords, user accounts, and security policies, and is therefore a high-value target for attackers. Privilege escalation attacks in Active Directory typically involve exploiting vulnerabilities or misconfigurations across the network to gain elevated privileges, such as Domain Administrator access. Once an attacker has escalated their privileges and taken full control of a domain, they can easily move laterally throughout the network, access sensitive data, and carry out further attacks. Security teams should monitor for privilege escalation attacks in Active Directory to identify a breach before attackers achieve operational success.\
The following analytic story groups detection opportunities that seek to identify an adversary attempting to escalate privileges in an Active Directory network.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Active Directory Privilege Escalation Identified](/endpoint/583e8a68-f2f7-45be-8fc9-bf725f0e22fd/) | [Domain Policy Modification](/tags/#domain-policy-modification) | [Correlation](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Kerberos Service Ticket Request Using RC4 Encryption](/endpoint/7d90f334-a482-11ec-908c-acde48001122/) | [Steal or Forge Kerberos Tickets](/tags/#steal-or-forge-kerberos-tickets), [Golden Ticket](/tags/#golden-ticket) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Rubeus Command Line Parameters](/endpoint/cca37478-8377-11ec-b59a-acde48001122/) | [Use Alternate Authentication Material](/tags/#use-alternate-authentication-material), [Pass the Ticket](/tags/#pass-the-ticket), [Steal or Forge Kerberos Tickets](/tags/#steal-or-forge-kerberos-tickets), [Kerberoasting](/tags/#kerberoasting), [AS-REP Roasting](/tags/#as-rep-roasting) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [ServicePrincipalNames Discovery with PowerShell](/endpoint/13243068-2d38-11ec-8908-acde48001122/) | [Kerberoasting](/tags/#kerberoasting) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [ServicePrincipalNames Discovery with SetSPN](/endpoint/ae8b3efc-2d2e-11ec-8b57-acde48001122/) | [Kerberoasting](/tags/#kerberoasting) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Computer Account Name Change](/endpoint/35a61ed8-61c4-11ec-bc1e-acde48001122/) | [Valid Accounts](/tags/#valid-accounts), [Domain Accounts](/tags/#domain-accounts) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Kerberos Service Ticket Request](/endpoint/8b1297bc-6204-11ec-b7c4-acde48001122/) | [Valid Accounts](/tags/#valid-accounts), [Domain Accounts](/tags/#domain-accounts) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Ticket Granting Ticket Request](/endpoint/d77d349e-6269-11ec-9cfe-acde48001122/) | [Valid Accounts](/tags/#valid-accounts), [Domain Accounts](/tags/#domain-accounts) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Unusual Number of Computer Service Tickets Requested](/endpoint/ac3b81c0-52f4-11ec-ac44-acde48001122/) | [Valid Accounts](/tags/#valid-accounts) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Unusual Number of Remote Endpoint Authentication Events](/endpoint/acb5dc74-5324-11ec-a36d-acde48001122/) | [Valid Accounts](/tags/#valid-accounts) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Administrative Shares Accessed On Multiple Hosts](/endpoint/d92f2d95-05fb-48a7-910f-4d3d61ab8655/) | [Network Share Discovery](/tags/#network-share-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Admon Default Group Policy Object Modified](/endpoint/83458004-db60-4170-857d-8572f16f070b/) | [Domain Policy Modification](/tags/#domain-policy-modification), [Group Policy Modification](/tags/#group-policy-modification) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Admon Group Policy Object Created](/endpoint/69201633-30d9-48ef-b1b6-e680805f0582/) | [Domain Policy Modification](/tags/#domain-policy-modification), [Group Policy Modification](/tags/#group-policy-modification) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Default Group Policy Object Modified](/endpoint/fe6a6cc4-9e0d-4d66-bcf4-2c7f44860876/) | [Domain Policy Modification](/tags/#domain-policy-modification), [Group Policy Modification](/tags/#group-policy-modification) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Default Group Policy Object Modified with GPME](/endpoint/eaf688b3-bb8f-454d-b105-920a862cd8cb/) | [Domain Policy Modification](/tags/#domain-policy-modification), [Group Policy Modification](/tags/#group-policy-modification) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Default Group Policy Object Modified with GPME](/endpoint/bcb55c13-067b-4648-98f3-627010f72520/) | [Domain Policy Modification](/tags/#domain-policy-modification), [Group Policy Modification](/tags/#group-policy-modification) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows DnsAdmins New Member Added](/endpoint/27e600aa-77f8-4614-bc80-2662a67e2f48/) | [Account Manipulation](/tags/#account-manipulation) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Domain Admin Impersonation Indicator](/endpoint/10381f93-6d38-470a-9c30-d25478e3bd3f/) | [Steal or Forge Kerberos Tickets](/tags/#steal-or-forge-kerberos-tickets) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows File Share Discovery With Powerview](/endpoint/a44c0be1-d7ab-41e4-92fd-aa9af4fe232c/) | [Network Share Discovery](/tags/#network-share-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows File Share Discovery With Powerview](/endpoint/ec4f671e-c736-4f78-a4c0-8fe809e952e5/) | [Unsecured Credentials](/tags/#unsecured-credentials), [Group Policy Preferences](/tags/#group-policy-preferences) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Findstr GPP Discovery](/endpoint/1631ac2d-f2a9-42fa-8a59-d6e210d472f5/) | [Unsecured Credentials](/tags/#unsecured-credentials), [Group Policy Preferences](/tags/#group-policy-preferences) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Findstr GPP Discovery](/endpoint/73ed0f19-080e-4917-b7c6-56e1760a50d4/) | [Unsecured Credentials](/tags/#unsecured-credentials), [Group Policy Preferences](/tags/#group-policy-preferences) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Group Policy Object Created](/endpoint/23add2a8-ea22-4fd4-8bc0-8c0b822373a1/) | [Domain Policy Modification](/tags/#domain-policy-modification), [Group Policy Modification](/tags/#group-policy-modification), [Domain Accounts](/tags/#domain-accounts) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Large Number of Computer Service Tickets Requested](/endpoint/386ad394-c9a7-4b4f-b66f-586252de20f0/) | [Network Share Discovery](/tags/#network-share-discovery), [Valid Accounts](/tags/#valid-accounts) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Local Administrator Credential Stuffing](/endpoint/09555511-aca6-484a-b6ab-72cd03d73c34/) | [Brute Force](/tags/#brute-force), [Credential Stuffing](/tags/#credential-stuffing) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows PowerSploit GPP Discovery](/endpoint/0130a0df-83a1-4647-9011-841e950ff302/) | [Unsecured Credentials](/tags/#unsecured-credentials), [Group Policy Preferences](/tags/#group-policy-preferences) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows PowerSploit GPP Discovery](/endpoint/fdef746e-71fb-41ce-8ab2-b4a5a6b50ca2/) | [Unsecured Credentials](/tags/#unsecured-credentials), [Group Policy Preferences](/tags/#group-policy-preferences) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows PowerView AD Access Control List Enumeration](/endpoint/39405650-c364-4e1e-a740-32a63ef042a6/) | [Domain Accounts](/tags/#domain-accounts), [Permission Groups Discovery](/tags/#permission-groups-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Rapid Authentication On Multiple Hosts](/endpoint/62606c77-d53d-4182-9371-b02cdbbbcef7/) | [Security Account Manager](/tags/#security-account-manager) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Special Privileged Logon On Multiple Hosts](/endpoint/4c461f5a-c2cc-4e86-b132-c262fc9edca7/) | [Account Discovery](/tags/#account-discovery), [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares), [Network Share Discovery](/tags/#network-share-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)
* [https://adsecurity.org/?p=3658](https://adsecurity.org/?p=3658)
* [https://adsecurity.org/?p=2362](https://adsecurity.org/?p=2362)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/active_directory_privilege_escalation.yml) \| *version*: **1**