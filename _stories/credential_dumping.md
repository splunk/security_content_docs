---
title: "Credential Dumping"
last_modified_at: 2020-02-04
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Authentication
  - Endpoint
  - Endpoint_Processes
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Uncover activity consistent with credential dumping, a technique wherein attackers compromise systems and attempt to obtain and exfiltrate passwords. The threat actors use these pilfered credentials to further escalate privileges and spread throughout a target environment. The included searches in this Analytic Story are designed to identify attempts to credential dumping.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Authentication](https://docs.splunk.com/Documentation/CIM/latest/User/Authentication), [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Endpoint_Processes](https://docs.splunk.com/Documentation/CIM/latest/User/EndpointProcesses)
- **Last Updated**: 2020-02-04
- **Author**: Rico Valdez, Splunk
- **ID**: 854d78bf-d0e2-4f4e-b05c-640905f86d7a

#### Narrative

Credential dumping&#151;gathering credentials from a target system, often hashed or encrypted&#151;is a common attack technique. Even though the credentials may not be in plain text, an attacker can still exfiltrate the data and set to cracking it offline, on their own systems. The threat actors target a variety of sources to extract them, including the Security Accounts Manager (SAM), Local Security Authority (LSA), NTDS from Domain Controllers, or the Group Policy Preference (GPP) files.\
Once attackers obtain valid credentials, they use them to move throughout a target network with ease, discovering new systems and identifying assets of interest. Credentials obtained in this manner typically include those of privileged users, which may provide access to more sensitive information and system operations.\
The detection searches in this Analytic Story monitor access to the Local Security Authority Subsystem Service (LSASS) process, the usage of shadowcopies for credential dumping and some other techniques for credential dumping.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Access LSASS Memory for Dump Creation](/endpoint/fb4c31b0-13e8-4155-8aa5-24de4b8d6717/) | [LSASS Memory](/tags/#lsass-memory), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Attempted Credential Dump From Registry via Reg exe](/endpoint/e9fb4a59-c5fb-440a-9f24-191fbc6b2911/) | [Security Account Manager](/tags/#security-account-manager), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Attempted Credential Dump From Registry via Reg exe](/endpoint/14038953-e5f2-4daf-acff-5452062baf03/) | [OS Credential Dumping](/tags/#os-credential-dumping), [Security Account Manager](/tags/#security-account-manager) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Create Remote Thread into LSASS](/endpoint/67d4dbef-9564-4699-8da8-03a151529edc/) | [LSASS Memory](/tags/#lsass-memory), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Creation of Shadow Copy](/endpoint/eb120f5f-b879-4a63-97c1-93352b5df844/) | [NTDS](/tags/#ntds), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Creation of Shadow Copy with wmic and powershell](/endpoint/2ed8b538-d284-449a-be1d-82ad1dbd186b/) | [NTDS](/tags/#ntds), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Creation of lsass Dump with Taskmgr](/endpoint/b2fbe95a-9c62-4c12-8a29-24b97e84c0cd/) | [LSASS Memory](/tags/#lsass-memory), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Credential Dumping via Copy Command from Shadow Copy](/endpoint/d8c406fe-23d2-45f3-a983-1abe7b83ff3b/) | [NTDS](/tags/#ntds), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Credential Dumping via Symlink to Shadow Copy](/endpoint/c5eac648-fae0-4263-91a6-773df1f4c903/) | [NTDS](/tags/#ntds), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Copy of ShadowCopy with Script Block Logging](/endpoint/9251299c-ea5b-11eb-a8de-acde48001122/) | [Security Account Manager](/tags/#security-account-manager), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Credential Dumping through LSASS access](/endpoint/2c365e57-4414-4540-8dc0-73ab10729996/) | [LSASS Memory](/tags/#lsass-memory), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Mimikatz Using Loaded Images](/endpoint/29e307ba-40af-4ab2-91b2-3c6b392bbba0/) | [LSASS Memory](/tags/#lsass-memory), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Dump LSASS via comsvcs DLL](/endpoint/8943b567-f14d-4ee8-a0bb-2121d4ce3184/) | [LSASS Memory](/tags/#lsass-memory), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Dump LSASS via procdump](/endpoint/3742ebfe-64c2-11eb-ae93-0242ac130002/) | [LSASS Memory](/tags/#lsass-memory), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Dump LSASS via procdump Rename](/deprecated/21276daa-663d-11eb-ae93-0242ac130002/) | [LSASS Memory](/tags/#lsass-memory) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Enable WDigest UseLogonCredential Registry](/endpoint/0c7d8ffe-25b1-11ec-9f39-acde48001122/) | [Modify Registry](/tags/#modify-registry), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Esentutl SAM Copy](/endpoint/d372f928-ce4f-11eb-a762-acde48001122/) | [Security Account Manager](/tags/#security-account-manager), [OS Credential Dumping](/tags/#os-credential-dumping) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Extraction of Registry Hives](/endpoint/8bbb7d58-b360-11eb-ba21-acde48001122/) | [Security Account Manager](/tags/#security-account-manager), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Ntdsutil Export NTDS](/endpoint/da63bc76-61ae-11eb-ae93-0242ac130002/) | [NTDS](/tags/#ntds), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Potential password in username](/endpoint/5ced34b4-ab32-4bb0-8f22-3b8f186f0a38/) | [Local Accounts](/tags/#local-accounts), [Credentials In Files](/tags/#credentials-in-files) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [SAM Database File Access Attempt](/endpoint/57551656-ebdb-11eb-afdf-acde48001122/) | [Security Account Manager](/tags/#security-account-manager), [OS Credential Dumping](/tags/#os-credential-dumping) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [SecretDumps Offline NTDS Dumping Tool](/endpoint/5672819c-be09-11eb-bbfb-acde48001122/) | [NTDS](/tags/#ntds), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Set Default PowerShell Execution Policy To Unrestricted or Bypass](/endpoint/c2590137-0b08-4985-9ec5-6ae23d92f63d/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Unsigned Image Loaded by LSASS](/deprecated/56ef054c-76ef-45f9-af4a-a634695dcd65/) | [LSASS Memory](/tags/#lsass-memory) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows AD Replication Request Initiated by User Account](/endpoint/51307514-1236-49f6-8686-d46d93cc2821/) | [DCSync](/tags/#dcsync), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows AD Replication Request Initiated from Unsanctioned Location](/endpoint/50998483-bb15-457b-a870-965080d9e3d3/) | [DCSync](/tags/#dcsync), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Credential Dumping LSASS Memory Createdump](/endpoint/b3b7ce35-fce5-4c73-85f4-700aeada81a9/) | [LSASS Memory](/tags/#lsass-memory) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Hunting System Account Targeting Lsass](/endpoint/1c6abb08-73d1-11ec-9ca0-acde48001122/) | [LSASS Memory](/tags/#lsass-memory), [OS Credential Dumping](/tags/#os-credential-dumping) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Mimikatz Binary Execution](/endpoint/a9e0d6d3-9676-4e26-994d-4e0406bb4467/) | [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Non-System Account Targeting Lsass](/endpoint/b1ce9a72-73cf-11ec-981b-acde48001122/) | [LSASS Memory](/tags/#lsass-memory), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows OS Credential Dumping with Ntdsutil Export NTDS](/endpoint/dad9ddec-a72a-47be-87b6-a0f7ba98ed6e/) | [NTDS](/tags/#ntds), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows OS Credential Dumping with Procdump](/endpoint/e102e297-dbe6-4a19-b319-5c08f4c19a06/) | [LSASS Memory](/tags/#lsass-memory), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Possible Credential Dumping](/endpoint/e4723b92-7266-11ec-af45-acde48001122/) | [LSASS Memory](/tags/#lsass-memory), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Rundll32 Comsvcs Memory Dump](/endpoint/76bb9e35-f314-4c3d-a385-83c72a13ce4e/) | [NTDS](/tags/#ntds), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://attack.mitre.org/wiki/Technique/T1003](https://attack.mitre.org/wiki/Technique/T1003)
* [https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for.html](https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for.html)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/credential_dumping.yml) \| *version*: **3**