---
title: "Prestige Ransomware"
last_modified_at: 2022-11-30
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Leverage searches that allow you to detect and investigate unusual activities that might relate to the Prestige Ransomware

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-11-30
- **Author**: Teoderick Contreras, Splunk
- **ID**: 8b8d8506-b931-450c-b794-f24184ca1deb

#### Narrative

This story addresses Prestige ransomware. This ransomware payload seen by Microsoft Threat Intelligence Center(MSTIC) as a ransomware campaign targeting organization in the transportation and logistic industries in some countries. This ransomware campaign highlight the destructive attack to its target organization that directly supplies or transporting military and humanitarian services or assistance. MSTIC observed this ransomware has similarities in terms of its deployment techniques with CaddyWiper and HermeticWiper which is also known malware campaign impacted multiple targeted critical infrastructure organizations. This analytic story will provide techniques and analytics that may help SOC or security researchers to monitor this threat.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Change Default File Association](/endpoint/462d17d8-1f71-11ec-ad07-acde48001122/) | [Change Default File Association](/tags/#change-default-file-association), [Event Triggered Execution](/tags/#event-triggered-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Common Ransomware Extensions](/endpoint/a9e5c5db-db11-43ca-86a8-c852d1b2c0ec/) | [Data Destruction](/tags/#data-destruction) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Create or delete windows shares using net exe](/endpoint/743a322c-9a68-4a0f-9c17-85d9cce2a27c/) | [Indicator Removal](/tags/#indicator-removal), [Network Share Connection Removal](/tags/#network-share-connection-removal) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Deleting Shadow Copies](/endpoint/b89919ed-ee5f-492c-b139-95dbb162039e/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Domain Group Discovery With Net](/endpoint/f2f14ac7-fa81-471a-80d5-7eb65c3c7349/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Domain Groups](/tags/#domain-groups) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Dump LSASS via comsvcs DLL](/endpoint/8943b567-f14d-4ee8-a0bb-2121d4ce3184/) | [LSASS Memory](/tags/#lsass-memory), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Excessive Usage Of Cacls App](/endpoint/0bdf6092-af17-11eb-939a-acde48001122/) | [File and Directory Permissions Modification](/tags/#file-and-directory-permissions-modification) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Excessive Usage Of Net App](/endpoint/45e52536-ae42-11eb-b5c6-acde48001122/) | [Account Access Removal](/tags/#account-access-removal) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Executable File Written in Administrative SMB Share](/endpoint/f63c34fe-a435-11eb-935a-acde48001122/) | [Remote Services](/tags/#remote-services), [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Impacket Lateral Movement Commandline Parameters](/endpoint/8ce07472-496f-11ec-ab3b-3e22fbd008af/) | [Remote Services](/tags/#remote-services), [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares), [Distributed Component Object Model](/tags/#distributed-component-object-model), [Windows Management Instrumentation](/tags/#windows-management-instrumentation), [Windows Service](/tags/#windows-service) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Impacket Lateral Movement WMIExec Commandline Parameters](/endpoint/d6e464e4-5c6a-474e-82d2-aed616a3a492/) | [Remote Services](/tags/#remote-services), [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares), [Distributed Component Object Model](/tags/#distributed-component-object-model), [Windows Management Instrumentation](/tags/#windows-management-instrumentation), [Windows Service](/tags/#windows-service) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Impacket Lateral Movement smbexec CommandLine Parameters](/endpoint/bb3c1bac-6bdf-4aa0-8dc9-068b8b712a76/) | [Remote Services](/tags/#remote-services), [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares), [Distributed Component Object Model](/tags/#distributed-component-object-model), [Windows Management Instrumentation](/tags/#windows-management-instrumentation), [Windows Service](/tags/#windows-service) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Net Localgroup Discovery](/endpoint/54f5201e-155b-11ec-a6e2-acde48001122/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Local Groups](/tags/#local-groups) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Network Connection Discovery With Arp](/endpoint/ae008c0f-83bd-4ed4-9350-98d4328e15d2/) | [System Network Connections Discovery](/tags/#system-network-connections-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Network Connection Discovery With Net](/endpoint/640337e5-6e41-4b7f-af06-9d9eab5e1e2d/) | [System Network Connections Discovery](/tags/#system-network-connections-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Network Connection Discovery With Netstat](/endpoint/2cf5cc25-f39a-436d-a790-4857e5995ede/) | [System Network Connections Discovery](/tags/#system-network-connections-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Network Discovery Using Route Windows App](/endpoint/dd83407e-439f-11ec-ab8e-acde48001122/) | [System Network Configuration Discovery](/tags/#system-network-configuration-discovery), [Internet Connection Discovery](/tags/#internet-connection-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Ntdsutil Export NTDS](/endpoint/da63bc76-61ae-11eb-ae93-0242ac130002/) | [NTDS](/tags/#ntds), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Recon AVProduct Through Pwh or WMI](/endpoint/28077620-c9f6-11eb-8785-acde48001122/) | [Gather Victim Host Information](/tags/#gather-victim-host-information) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Scheduled Task Deleted Or Created via CMD](/endpoint/d5af132c-7c17-439c-9d31-13d55340f36c/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Schtasks scheduling job on remote system](/endpoint/1297fb80-f42a-4b4a-9c8a-88c066237cf6/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Process File Path](/endpoint/9be25988-ad82-11eb-a14f-acde48001122/) | [Create or Modify System Process](/tags/#create-or-modify-system-process) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [WBAdmin Delete System Backups](/endpoint/cd5aed7e-5cea-11eb-ae93-0242ac130002/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [WinEvent Scheduled Task Created Within Public Path](/endpoint/5d9c6eee-988c-11eb-8253-acde48001122/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [WinEvent Windows Task Scheduler Event Action Started](/endpoint/b3632472-310b-11ec-9aab-acde48001122/) | [Scheduled Task](/tags/#scheduled-task) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Cached Domain Credentials Reg Query](/endpoint/40ccb8e0-1785-466e-901e-6a8b75c04ecd/) | [Cached Domain Credentials](/tags/#cached-domain-credentials), [OS Credential Dumping](/tags/#os-credential-dumping) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Change Default File Association For No File Ext](/endpoint/dbdf52ad-d6a1-4b68-975f-0a10939d8e38/) | [Change Default File Association](/tags/#change-default-file-association), [Event Triggered Execution](/tags/#event-triggered-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows ClipBoard Data via Get-ClipBoard](/endpoint/ab73289e-2246-4de0-a14b-67006c72a893/) | [Clipboard Data](/tags/#clipboard-data) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Credentials from Password Stores Query](/endpoint/db02d6b4-5d5b-4c33-8d8f-f0577516a8c7/) | [Credentials from Password Stores](/tags/#credentials-from-password-stores) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Credentials in Registry Reg Query](/endpoint/a8b3124e-2278-4b73-ae9c-585117079fb2/) | [Credentials in Registry](/tags/#credentials-in-registry), [Unsecured Credentials](/tags/#unsecured-credentials) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Indirect Command Execution Via Series Of Forfiles](/endpoint/bfdaabe7-3db8-48c5-80c1-220f9b8f22be/) | [Indirect Command Execution](/tags/#indirect-command-execution) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Information Discovery Fsutil](/endpoint/2181f261-93e6-4166-a5a9-47deac58feff/) | [System Information Discovery](/tags/#system-information-discovery) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Modify Registry Reg Restore](/endpoint/d0072bd2-6d73-4c1b-bc77-ded6d2da3a4e/) | [Query Registry](/tags/#query-registry) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Password Managers Discovery](/endpoint/a3b3bc96-1c4f-4eba-8218-027cac739a48/) | [Password Managers](/tags/#password-managers) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Private Keys Discovery](/endpoint/5c1c2877-06c0-40ee-a1a2-db71f1372b5b/) | [Private Keys](/tags/#private-keys), [Unsecured Credentials](/tags/#unsecured-credentials) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Query Registry Reg Save](/endpoint/cbee60c1-b776-456f-83c2-faa56bdbe6c6/) | [Query Registry](/tags/#query-registry) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Security Support Provider Reg Query](/endpoint/31302468-93c9-4eca-9ae3-2d41f53a4e2b/) | [Security Support Provider](/tags/#security-support-provider), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Service Stop Via Net  and SC Application](/endpoint/827af04b-0d08-479b-9b84-b7d4644e4b80/) | [Service Stop](/tags/#service-stop) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Steal or Forge Kerberos Tickets Klist](/endpoint/09d88404-1e29-46cb-806c-1eedbc85ad5d/) | [Steal or Forge Kerberos Tickets](/tags/#steal-or-forge-kerberos-tickets) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows System Network Config Discovery Display DNS](/endpoint/e24f0a0e-41a9-419f-9999-eacab15efc36/) | [System Network Configuration Discovery](/tags/#system-network-configuration-discovery) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows System Network Connections Discovery Netsh](/endpoint/abfb7cc5-c275-4a97-9029-62cd8d4ffeca/) | [System Network Connections Discovery](/tags/#system-network-connections-discovery) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows System User Discovery Via Quser](/endpoint/0c3f3e09-e47a-410e-856f-a02a5c5fafb0/) | [System Owner/User Discovery](/tags/#system-owner/user-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows WMI Process And Service List](/endpoint/ef3c5ef2-3f6d-4087-aa75-49bf746dc907/) | [Windows Management Instrumentation](/tags/#windows-management-instrumentation) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://www.microsoft.com/en-us/security/blog/2022/10/14/new-prestige-ransomware-impacts-organizations-in-ukraine-and-poland/](https://www.microsoft.com/en-us/security/blog/2022/10/14/new-prestige-ransomware-impacts-organizations-in-ukraine-and-poland/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/prestige_ransomware.yml) \| *version*: **1**