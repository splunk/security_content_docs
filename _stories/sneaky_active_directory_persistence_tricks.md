---
title: "Sneaky Active Directory Persistence Tricks"
last_modified_at: 2024-03-14
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

Monitor for activities and techniques associated with Windows Active Directory persistence techniques.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Authentication](https://docs.splunk.com/Documentation/CIM/latest/User/Authentication), [Change](https://docs.splunk.com/Documentation/CIM/latest/User/Change), [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic)
- **Last Updated**: 2024-03-14
- **Author**: Dean Luxton, Mauricio Velazco, Splunk
- **ID**: f676c4c1-c769-4ecb-9611-5fd85b497c56

#### Narrative

Persistence consists of techniques that adversaries use to keep access to systems across restarts, changed credentials, and other interruptions that could cut off their access. Active Directory is a centralized and hierarchical database that stores information about users, computers, and other resources on a network. It provides secure and efficient management of these resources and enables administrators to enforce security policies and delegate administrative tasks.\
In 2015 Active Directory security researcher Sean Metcalf published a blog post titled `Sneaky Active Directory Persistence Tricks`. In this blog post, Sean described several methods through which an attacker could persist administrative access on an Active Directory network after having Domain Admin level rights for a short period of time. At the time of writing, 8 years after the initial blog post, most of these techniques are still possible since they abuse legitimate administrative functionality and not software vulnerabilities. Security engineers defending Active Directory networks should be aware of these technique available to adversaries post exploitation and deploy both preventive and detective security controls for them.\
This analytic story groups detection opportunities for most of the techniques described on Seans blog post as well as other high impact attacks against Active Directory networks and Domain Controllers like DCSync and DCShadow. For some of these detection opportunities, it is necessary to enable the necessary GPOs and SACLs required, otherwise the event codes will not trigger. Each detection includes a list of requirements for enabling logging.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Registry Keys Used For Persistence](/endpoint/f5f6af30-7aa7-4295-bfe9-07fe87c01a4b/) | [Registry Run Keys / Startup Folder](/tags/#registry-run-keys-/-startup-folder), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows AD AdminSDHolder ACL Modified](/endpoint/00d877c3-7b7b-443d-9562-6b231e2abab9/) | [Event Triggered Execution](/tags/#event-triggered-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows AD Cross Domain SID History Addition](/endpoint/41bbb371-28ba-439c-bb5c-d9930c28365d/) | [SID-History Injection](/tags/#sid-history-injection), [Access Token Manipulation](/tags/#access-token-manipulation) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows AD DSRM Account Changes](/endpoint/08cb291e-ea77-48e8-a95a-0799319bf056/) | [Account Manipulation](/tags/#account-manipulation) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows AD DSRM Password Reset](/endpoint/d1ab841c-36a6-46cf-b50f-b2b04b31182a/) | [Account Manipulation](/tags/#account-manipulation) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows AD Domain Controller Audit Policy Disabled](/endpoint/fc3ccef1-60a4-4239-bd66-b279511b4d14/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows AD Domain Controller Promotion](/endpoint/e633a0ef-2a6e-4ed7-b925-5ff999e5d1f0/) | [Rogue Domain Controller](/tags/#rogue-domain-controller) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows AD Domain Replication ACL Addition](/endpoint/8c372853-f459-4995-afdc-280c114d33ab/) | [Domain Policy Modification](/tags/#domain-policy-modification) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows AD Privileged Account SID History Addition](/endpoint/6b521149-b91c-43aa-ba97-c2cac59ec830/) | [SID-History Injection](/tags/#sid-history-injection), [Access Token Manipulation](/tags/#access-token-manipulation) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows AD Replication Request Initiated by User Account](/endpoint/51307514-1236-49f6-8686-d46d93cc2821/) | [DCSync](/tags/#dcsync), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows AD Replication Request Initiated from Unsanctioned Location](/endpoint/50998483-bb15-457b-a870-965080d9e3d3/) | [DCSync](/tags/#dcsync), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows AD Replication Service Traffic](/network/c6e24183-a5f4-4b2a-ad01-2eb456d09b67/) | [OS Credential Dumping](/tags/#os-credential-dumping), [DCSync](/tags/#dcsync), [Rogue Domain Controller](/tags/#rogue-domain-controller) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows AD Rogue Domain Controller Network Activity](/network/c4aeeeef-da7f-4338-b3ba-553cbcbe2138/) | [Rogue Domain Controller](/tags/#rogue-domain-controller) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows AD SID History Attribute Modified](/endpoint/1155e47d-307f-4247-beab-71071e3a458c/) | [Access Token Manipulation](/tags/#access-token-manipulation), [SID-History Injection](/tags/#sid-history-injection) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows AD Same Domain SID History Addition](/endpoint/5fde0b7c-df7a-40b1-9b3a-294c00f0289d/) | [SID-History Injection](/tags/#sid-history-injection), [Access Token Manipulation](/tags/#access-token-manipulation) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows AD ServicePrincipalName Added To Domain Account](/endpoint/8a1259cb-0ea7-409c-8bfe-74bad89259f9/) | [Account Manipulation](/tags/#account-manipulation) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows AD Short Lived Domain Account ServicePrincipalName](/endpoint/b681977c-d90c-4efc-81a5-c58f945fb541/) | [Account Manipulation](/tags/#account-manipulation) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows AD Short Lived Domain Controller SPN Attribute](/endpoint/57e27f27-369c-4df8-af08-e8c7ee8373d4/) | [Rogue Domain Controller](/tags/#rogue-domain-controller) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows AD Short Lived Server Object](/endpoint/193769d3-1e33-43a9-970e-ad4a88256cdb/) | [Rogue Domain Controller](/tags/#rogue-domain-controller) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Admon Default Group Policy Object Modified](/endpoint/83458004-db60-4170-857d-8572f16f070b/) | [Domain Policy Modification](/tags/#domain-policy-modification), [Group Policy Modification](/tags/#group-policy-modification) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Admon Group Policy Object Created](/endpoint/69201633-30d9-48ef-b1b6-e680805f0582/) | [Domain Policy Modification](/tags/#domain-policy-modification), [Group Policy Modification](/tags/#group-policy-modification) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Default Group Policy Object Modified](/endpoint/fe6a6cc4-9e0d-4d66-bcf4-2c7f44860876/) | [Domain Policy Modification](/tags/#domain-policy-modification), [Group Policy Modification](/tags/#group-policy-modification) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Default Group Policy Object Modified with GPME](/endpoint/eaf688b3-bb8f-454d-b105-920a862cd8cb/) | [Domain Policy Modification](/tags/#domain-policy-modification), [Group Policy Modification](/tags/#group-policy-modification) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Group Policy Object Created](/endpoint/23add2a8-ea22-4fd4-8bc0-8c0b822373a1/) | [Domain Policy Modification](/tags/#domain-policy-modification), [Group Policy Modification](/tags/#group-policy-modification), [Domain Accounts](/tags/#domain-accounts) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Security Support Provider Reg Query](/endpoint/31302468-93c9-4eca-9ae3-2d41f53a4e2b/) | [Security Support Provider](/tags/#security-support-provider), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://adsecurity.org/?p=1929](https://adsecurity.org/?p=1929)
* [https://www.youtube.com/watch?v=Lz6haohGAMc&feature=youtu.be](https://www.youtube.com/watch?v=Lz6haohGAMc&feature=youtu.be)
* [https://adsecurity.org/wp-content/uploads/2015/09/DEFCON23-2015-Metcalf-RedvsBlue-ADAttackAndDefense-Final.pdf](https://adsecurity.org/wp-content/uploads/2015/09/DEFCON23-2015-Metcalf-RedvsBlue-ADAttackAndDefense-Final.pdf)
* [https://attack.mitre.org/tactics/TA0003/](https://attack.mitre.org/tactics/TA0003/)
* [https://www.dcshadow.com](https://www.dcshadow.com)
* [https://gist.github.com/gentilkiwi/dcc132457408cf11ad2061340dcb53c2](https://gist.github.com/gentilkiwi/dcc132457408cf11ad2061340dcb53c2)
* [https://www.linkedin.com/pulse/mimikatz-dcsync-event-log-detections-john-dwyer](https://www.linkedin.com/pulse/mimikatz-dcsync-event-log-detections-john-dwyer)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/sneaky_active_directory_persistence_tricks.yml) \| *version*: **2**