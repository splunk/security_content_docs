---
title: "Active Directory Kerberos Attacks"
last_modified_at: 2022-02-02
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Authentication
  - Change
  - Endpoint
  - Network_Traffic
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Monitor for activities and techniques associated with Kerberos based attacks within with Active Directory environments.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Authentication](https://docs.splunk.com/Documentation/CIM/latest/User/Authentication), [Change](https://docs.splunk.com/Documentation/CIM/latest/User/Change), [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic)
- **Last Updated**: 2022-02-02
- **Author**: Mauricio Velazco, Splunk
- **ID**: 38b8cf16-8461-11ec-ade1-acde48001122

#### Narrative

Kerberos, initially named after Cerberus, the three-headed dog in Greek mythology, is a network authentication protocol that allows computers and users to prove their identity through a trusted third-party. This trusted third-party issues Kerberos tickets using symmetric encryption to allow users access to services and network resources based on their privilege level. Kerberos is the default authentication protocol used on Windows Active Directory networks since the introduction of Windows Server 2003. With Kerberos being the backbone of Windows authentication, it is commonly abused by adversaries across the different phases of a breach including initial access, privilege escalation, defense evasion, credential access, lateral movement, etc.\ This Analytic Story groups detection use cases in which the Kerberos protocol is abused. Defenders can leverage these analytics to detect and hunt for adversaries engaging in Kerberos based attacks.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Disabled Kerberos Pre-Authentication Discovery With Get-ADUser](/endpoint/114c6bfe-9406-11ec-bcce-acde48001122/) | [Steal or Forge Kerberos Tickets](/tags/#steal-or-forge-kerberos-tickets), [AS-REP Roasting](/tags/#as-rep-roasting) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disabled Kerberos Pre-Authentication Discovery With PowerView](/endpoint/b0b34e2c-90de-11ec-baeb-acde48001122/) | [Steal or Forge Kerberos Tickets](/tags/#steal-or-forge-kerberos-tickets), [AS-REP Roasting](/tags/#as-rep-roasting) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Kerberoasting spn request with RC4 encryption](/endpoint/5cc67381-44fa-4111-8a37-7a230943f027/) | [Steal or Forge Kerberos Tickets](/tags/#steal-or-forge-kerberos-tickets), [Kerberoasting](/tags/#kerberoasting) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Kerberos Pre-Authentication Flag Disabled in UserAccountControl](/endpoint/0cb847ee-9423-11ec-b2df-acde48001122/) | [Steal or Forge Kerberos Tickets](/tags/#steal-or-forge-kerberos-tickets), [AS-REP Roasting](/tags/#as-rep-roasting) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Kerberos Pre-Authentication Flag Disabled with PowerShell](/endpoint/59b51620-94c9-11ec-b3d5-acde48001122/) | [Steal or Forge Kerberos Tickets](/tags/#steal-or-forge-kerberos-tickets), [AS-REP Roasting](/tags/#as-rep-roasting) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Kerberos Service Ticket Request Using RC4 Encryption](/endpoint/7d90f334-a482-11ec-908c-acde48001122/) | [Steal or Forge Kerberos Tickets](/tags/#steal-or-forge-kerberos-tickets), [Golden Ticket](/tags/#golden-ticket) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Kerberos TGT Request Using RC4 Encryption](/endpoint/18916468-9c04-11ec-bdc6-acde48001122/) | [Use Alternate Authentication Material](/tags/#use-alternate-authentication-material) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Kerberos User Enumeration](/endpoint/d82d4af4-a0bd-11ec-9445-3e22fbd008af/) | [Gather Victim Identity Information](/tags/#gather-victim-identity-information), [Email Addresses](/tags/#email-addresses) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Mimikatz PassTheTicket CommandLine Parameters](/endpoint/13bbd574-83ac-11ec-99d4-acde48001122/) | [Use Alternate Authentication Material](/tags/#use-alternate-authentication-material), [Pass the Ticket](/tags/#pass-the-ticket) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [PetitPotam Suspicious Kerberos TGT Request](/endpoint/e3ef244e-0a67-11ec-abf2-acde48001122/) | [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Rubeus Command Line Parameters](/endpoint/cca37478-8377-11ec-b59a-acde48001122/) | [Use Alternate Authentication Material](/tags/#use-alternate-authentication-material), [Pass the Ticket](/tags/#pass-the-ticket), [Steal or Forge Kerberos Tickets](/tags/#steal-or-forge-kerberos-tickets), [Kerberoasting](/tags/#kerberoasting), [AS-REP Roasting](/tags/#as-rep-roasting) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Rubeus Kerberos Ticket Exports Through Winlogon Access](/endpoint/5ed8c50a-8869-11ec-876f-acde48001122/) | [Use Alternate Authentication Material](/tags/#use-alternate-authentication-material), [Pass the Ticket](/tags/#pass-the-ticket) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [ServicePrincipalNames Discovery with PowerShell](/endpoint/13243068-2d38-11ec-8908-acde48001122/) | [Kerberoasting](/tags/#kerberoasting) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [ServicePrincipalNames Discovery with SetSPN](/endpoint/ae8b3efc-2d2e-11ec-8b57-acde48001122/) | [Kerberoasting](/tags/#kerberoasting) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Kerberos Service Ticket Request](/endpoint/8b1297bc-6204-11ec-b7c4-acde48001122/) | [Valid Accounts](/tags/#valid-accounts), [Domain Accounts](/tags/#domain-accounts) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Ticket Granting Ticket Request](/endpoint/d77d349e-6269-11ec-9cfe-acde48001122/) | [Valid Accounts](/tags/#valid-accounts), [Domain Accounts](/tags/#domain-accounts) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Unknown Process Using The Kerberos Protocol](/endpoint/c91a0852-9fbb-11ec-af44-acde48001122/) | [Use Alternate Authentication Material](/tags/#use-alternate-authentication-material) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Unusual Number of Computer Service Tickets Requested](/endpoint/ac3b81c0-52f4-11ec-ac44-acde48001122/) | [Valid Accounts](/tags/#valid-accounts) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Unusual Number of Kerberos Service Tickets Requested](/endpoint/eb3e6702-8936-11ec-98fe-acde48001122/) | [Steal or Forge Kerberos Tickets](/tags/#steal-or-forge-kerberos-tickets), [Kerberoasting](/tags/#kerberoasting) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Computer Account Created by Computer Account](/endpoint/97a8dc5f-8a7c-4fed-9e3e-ec407fd0268a/) | [Steal or Forge Kerberos Tickets](/tags/#steal-or-forge-kerberos-tickets) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Computer Account Requesting Kerberos Ticket](/endpoint/fb3b2bb3-75a4-4279-848a-165b42624770/) | [Steal or Forge Kerberos Tickets](/tags/#steal-or-forge-kerberos-tickets) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Computer Account With SPN](/endpoint/9a3e57e7-33f4-470e-b25d-165baa6e8357/) | [Steal or Forge Kerberos Tickets](/tags/#steal-or-forge-kerberos-tickets) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Domain Admin Impersonation Indicator](/endpoint/10381f93-6d38-470a-9c30-d25478e3bd3f/) | [Steal or Forge Kerberos Tickets](/tags/#steal-or-forge-kerberos-tickets) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Get-AdComputer Unconstrained Delegation Discovery](/endpoint/c8640777-469f-4638-ab44-c34a3233ffac/) | [Remote System Discovery](/tags/#remote-system-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Kerberos Local Successful Logon](/endpoint/8309c3a8-4d34-48ae-ad66-631658214653/) | [Steal or Forge Kerberos Tickets](/tags/#steal-or-forge-kerberos-tickets) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Multiple Disabled Users Failed To Authenticate Wth Kerberos](/endpoint/98f22d82-9d62-11eb-9fcf-acde48001122/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Multiple Invalid Users Fail To Authenticate Using Kerberos](/endpoint/001266a6-9d5b-11eb-829b-acde48001122/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Multiple Users Failed To Authenticate Using Kerberos](/endpoint/3a91a212-98a9-11eb-b86a-acde48001122/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows PowerShell Disabled Kerberos Pre-Authentication Discovery Get-ADUser](/endpoint/d57b4d91-fc91-4482-a325-47693cced1eb/) | [Steal or Forge Kerberos Tickets](/tags/#steal-or-forge-kerberos-tickets), [AS-REP Roasting](/tags/#as-rep-roasting) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows PowerShell Disabled Kerberos Pre-Authentication Discovery With PowerView](/endpoint/dc3f2af7-ca69-47ce-a122-9f9787e19417/) | [Steal or Forge Kerberos Tickets](/tags/#steal-or-forge-kerberos-tickets), [AS-REP Roasting](/tags/#as-rep-roasting) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows PowerView Constrained Delegation Discovery](/endpoint/86dc8176-6e6c-42d6-9684-5444c6557ab3/) | [Remote System Discovery](/tags/#remote-system-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows PowerView Kerberos Service Ticket Request](/endpoint/970455a1-4ac2-47e1-a9a5-9e75443ddcb9/) | [Steal or Forge Kerberos Tickets](/tags/#steal-or-forge-kerberos-tickets), [Kerberoasting](/tags/#kerberoasting) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows PowerView SPN Discovery](/endpoint/a7093c28-796c-4ebb-9997-e2c18b870837/) | [Steal or Forge Kerberos Tickets](/tags/#steal-or-forge-kerberos-tickets), [Kerberoasting](/tags/#kerberoasting) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows PowerView Unconstrained Delegation Discovery](/endpoint/fbf9e47f-e531-4fea-942d-5c95af7ed4d6/) | [Remote System Discovery](/tags/#remote-system-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Unusual Count Of Disabled Users Failed Auth Using Kerberos](/endpoint/f65aa026-b811-42ab-b4b9-d9088137648f/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Unusual Count Of Invalid Users Fail To Auth Using Kerberos](/endpoint/f122cb2e-d773-4f11-8399-62a3572d8dd7/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Unusual Count Of Users Failed To Auth Using Kerberos](/endpoint/bc9cb715-08ba-40c3-9758-6e2b26e455cb/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://en.wikipedia.org/wiki/Kerberos_(protocol)](https://en.wikipedia.org/wiki/Kerberos_(protocol))
* [https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/2a32282e-dd48-4ad9-a542-609804b02cc9](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/2a32282e-dd48-4ad9-a542-609804b02cc9)
* [https://m0chan.github.io/2019/07/31/How-To-Attack-Kerberos-101.html](https://m0chan.github.io/2019/07/31/How-To-Attack-Kerberos-101.html)
* [https://stealthbits.com/blog/cracking-active-directory-passwords-with-as-rep-roasting/](https://stealthbits.com/blog/cracking-active-directory-passwords-with-as-rep-roasting/)
* [https://attack.mitre.org/techniques/T1558/003/](https://attack.mitre.org/techniques/T1558/003/)
* [https://attack.mitre.org/techniques/T1550/003/](https://attack.mitre.org/techniques/T1550/003/)
* [https://attack.mitre.org/techniques/T1558/004/](https://attack.mitre.org/techniques/T1558/004/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/active_directory_kerberos_attacks.yml) \| *version*: **1**