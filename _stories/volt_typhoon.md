---
title: "Volt Typhoon"
last_modified_at: 2023-05-25
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

This analytic story contains detections that allow security analysts to detect and investigate unusual activities that might relate to the "Volt Typhoon" group targeting critical infrastructure organizations in United States and Guam. The affected organizations include the communications, manufacturing, utility, transportation, construction, maritime, government, information technology, and education sectors. This Analytic story looks for suspicious process execution, lolbin execution, command-line activity, lsass dump and many more.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Risk](https://docs.splunk.com/Documentation/CIM/latest/User/Risk)
- **Last Updated**: 2023-05-25
- **Author**: Teoderick Contreras, Splunk
- **ID**: f73010e4-49eb-44ef-9f3f-2c25a1ae5415

#### Narrative

Volt Typhoon is a state sponsored group typically focuses on espionage and information gathering.\ Based on Microsoft Threat Intelligence, This threat actor group puts strong emphasis on stealth in this campaign by relying almost exclusively on living-off-the-land techniques and hands-on-keyboard activity. \ They issue commands via the command line to :\ (1) collect data, including credentials from local and network systems, \ (2) put the data into an archive file to stage it for exfiltration, and then \ (3) use the stolen valid credentials to maintain persistence. \ In addition, Volt Typhoon tries to blend into normal network activity by routing traffic through compromised small office and home office (SOHO) network equipment, including routers, firewalls, and VPN hardware. They have also been observed using custom versions of open-source tools to establish a command and control (C2) channel over proxy to further stay under the radar.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Cmdline Tool Not Executed In CMD Shell](/endpoint/6c3f7dd8-153c-11ec-ac2d-acde48001122/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [JavaScript](/tags/#javascript) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Creation of Shadow Copy](/endpoint/eb120f5f-b879-4a63-97c1-93352b5df844/) | [NTDS](/tags/#ntds), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Creation of Shadow Copy with wmic and powershell](/endpoint/2ed8b538-d284-449a-be1d-82ad1dbd186b/) | [NTDS](/tags/#ntds), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect PsExec With accepteula Flag](/endpoint/27c3a83d-cada-47c6-9042-67baf19d2574/) | [Remote Services](/tags/#remote-services), [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Dump LSASS via comsvcs DLL](/endpoint/8943b567-f14d-4ee8-a0bb-2121d4ce3184/) | [LSASS Memory](/tags/#lsass-memory), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Elevated Group Discovery With Net](/endpoint/a23a0e20-0b1b-4a07-82e5-ec5f70811e7a/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Domain Groups](/tags/#domain-groups) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Executables Or Script Creation In Suspicious Path](/endpoint/a7e3f0f0-ae42-11eb-b245-acde48001122/) | [Masquerading](/tags/#masquerading) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Extraction of Registry Hives](/endpoint/8bbb7d58-b360-11eb-ba21-acde48001122/) | [Security Account Manager](/tags/#security-account-manager), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Impacket Lateral Movement Commandline Parameters](/endpoint/8ce07472-496f-11ec-ab3b-3e22fbd008af/) | [Remote Services](/tags/#remote-services), [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares), [Distributed Component Object Model](/tags/#distributed-component-object-model), [Windows Management Instrumentation](/tags/#windows-management-instrumentation), [Windows Service](/tags/#windows-service) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Impacket Lateral Movement WMIExec Commandline Parameters](/endpoint/d6e464e4-5c6a-474e-82d2-aed616a3a492/) | [Remote Services](/tags/#remote-services), [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares), [Distributed Component Object Model](/tags/#distributed-component-object-model), [Windows Management Instrumentation](/tags/#windows-management-instrumentation), [Windows Service](/tags/#windows-service) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Impacket Lateral Movement smbexec CommandLine Parameters](/endpoint/bb3c1bac-6bdf-4aa0-8dc9-068b8b712a76/) | [Remote Services](/tags/#remote-services), [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares), [Distributed Component Object Model](/tags/#distributed-component-object-model), [Windows Management Instrumentation](/tags/#windows-management-instrumentation), [Windows Service](/tags/#windows-service) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Malicious PowerShell Process - Encoded Command](/endpoint/c4db14d9-7909-48b4-a054-aa14d89dbb19/) | [Obfuscated Files or Information](/tags/#obfuscated-files-or-information) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Malicious PowerShell Process - Execution Policy Bypass](/endpoint/9be56c82-b1cc-4318-87eb-d138afaaca39/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Net Localgroup Discovery](/endpoint/54f5201e-155b-11ec-a6e2-acde48001122/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Local Groups](/tags/#local-groups) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Network Connection Discovery With Arp](/endpoint/ae008c0f-83bd-4ed4-9350-98d4328e15d2/) | [System Network Connections Discovery](/tags/#system-network-connections-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Network Connection Discovery With Netstat](/endpoint/2cf5cc25-f39a-436d-a790-4857e5995ede/) | [System Network Connections Discovery](/tags/#system-network-connections-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Ntdsutil Export NTDS](/endpoint/da63bc76-61ae-11eb-ae93-0242ac130002/) | [NTDS](/tags/#ntds), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Processes launching netsh](/endpoint/b89919ed-fe5f-492c-b139-95dbb162040e/) | [Disable or Modify System Firewall](/tags/#disable-or-modify-system-firewall), [Impair Defenses](/tags/#impair-defenses) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Remote WMI Command Attempt](/endpoint/272df6de-61f1-4784-877c-1fbc3e2d0838/) | [Windows Management Instrumentation](/tags/#windows-management-instrumentation) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Copy on System32](/endpoint/ce633e56-25b2-11ec-9e76-acde48001122/) | [Rename System Utilities](/tags/#rename-system-utilities), [Masquerading](/tags/#masquerading) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Process File Path](/endpoint/9be25988-ad82-11eb-a14f-acde48001122/) | [Create or Modify System Process](/tags/#create-or-modify-system-process) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Common Abused Cmd Shell Risk Behavior](/endpoint/e99fcc4f-c6b0-4443-aa2a-e3c85126ec9a/) | [File and Directory Permissions Modification](/tags/#file-and-directory-permissions-modification), [System Network Connections Discovery](/tags/#system-network-connections-discovery), [System Owner/User Discovery](/tags/#system-owner/user-discovery), [System Shutdown/Reboot](/tags/#system-shutdown/reboot), [System Network Configuration Discovery](/tags/#system-network-configuration-discovery), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | [Correlation](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows DNS Gather Network Info](/endpoint/347e0892-e8f3-4512-afda-dc0e3fa996f3/) | [DNS](/tags/#dns) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Ldifde Directory Object Behavior](/endpoint/35cd29ca-f08c-4489-8815-f715c45460d3/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer), [Domain Groups](/tags/#domain-groups) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Mimikatz Binary Execution](/endpoint/a9e0d6d3-9676-4e26-994d-4e0406bb4467/) | [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Multiple Disabled Users Failed To Authenticate Wth Kerberos](/endpoint/98f22d82-9d62-11eb-9fcf-acde48001122/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Multiple Disabled Users Failed To Authenticate Wth Kerberos](/endpoint/98f22d82-9d62-11eb-9fcf-acde48001122/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Multiple Invalid Users Fail To Authenticate Using Kerberos](/endpoint/001266a6-9d5b-11eb-829b-acde48001122/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Multiple Invalid Users Failed To Authenticate Using NTLM](/endpoint/57ad5a64-9df7-11eb-a290-acde48001122/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Multiple Users Fail To Authenticate Wth ExplicitCredentials](/endpoint/e61918fa-9ca4-11eb-836c-acde48001122/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Multiple Users Failed To Authenticate From Host Using NTLM](/endpoint/7ed272a4-9c77-11eb-af22-acde48001122/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Multiple Users Failed To Authenticate From Process](/endpoint/9015385a-9c84-11eb-bef2-acde48001122/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Multiple Users Failed To Authenticate Using Kerberos](/endpoint/3a91a212-98a9-11eb-b86a-acde48001122/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Multiple Users Remotely Failed To Authenticate From Host](/endpoint/80f9d53e-9ca1-11eb-b0d6-acde48001122/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Proxy Via Netsh](/endpoint/c137bfe8-6036-4cff-b77b-4e327dd0a1cf/) | [Internal Proxy](/tags/#internal-proxy), [Proxy](/tags/#proxy) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Proxy Via Registry](/endpoint/0270455b-1385-4579-9ac5-e77046c508ae/) | [Internal Proxy](/tags/#internal-proxy), [Proxy](/tags/#proxy) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Unusual Count Of Disabled Users Failed Auth Using Kerberos](/endpoint/f65aa026-b811-42ab-b4b9-d9088137648f/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Unusual Count Of Invalid Users Fail To Auth Using Kerberos](/endpoint/f122cb2e-d773-4f11-8399-62a3572d8dd7/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Unusual Count Of Invalid Users Failed To Auth Using NTLM](/endpoint/15603165-147d-4a6e-9778-bd0ff39e668f/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Unusual Count Of Users Fail To Auth Wth ExplicitCredentials](/endpoint/14f414cf-3080-4b9b-aaf6-55a4ce947b93/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Unusual Count Of Users Failed To Auth Using Kerberos](/endpoint/bc9cb715-08ba-40c3-9758-6e2b26e455cb/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Unusual Count Of Users Failed To Authenticate From Process](/endpoint/25bdb6cb-2e49-4d34-a93c-d6c567c122fe/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Unusual Count Of Users Failed To Authenticate Using NTLM](/endpoint/6f6c8fd7-6a6b-4af9-a0e9-57cfc47a58b4/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Unusual Count Of Users Remotely Failed To Auth From Host](/endpoint/cf06a0ee-ffa9-4ed3-be77-0670ed9bab52/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows WMI Process Call Create](/endpoint/0661c2de-93de-11ec-9833-acde48001122/) | [Windows Management Instrumentation](/tags/#windows-management-instrumentation) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon-targets-us-critical-infrastructure-with-living-off-the-land-techniques/](https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon-targets-us-critical-infrastructure-with-living-off-the-land-techniques/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/volt_typhoon.yml) \| *version*: **1**