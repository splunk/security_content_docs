---
title: "Active Directory Lateral Movement"
last_modified_at: 2021-12-09
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Authentication
  - Endpoint
  - Network_Traffic
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Detect and investigate tactics, techniques, and procedures around how attackers move laterally within an Active Directory environment. Since lateral movement is often a necessary step in a breach, it is important for cyber defenders to deploy detection coverage.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Authentication](https://docs.splunk.com/Documentation/CIM/latest/User/Authentication), [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic)
- **Last Updated**: 2021-12-09
- **Author**: David Dorsey, Mauricio Velazco Splunk
- **ID**: 399d65dc-1f08-499b-a259-aad9051f38ad

#### Narrative

Once attackers gain a foothold within an enterprise, they will seek to expand their accesses and leverage techniques that facilitate lateral movement. Attackers will often spend quite a bit of time and effort moving laterally. Because lateral movement renders an attacker the most vulnerable to detection, it's an excellent focus for detection and investigation.\
Indications of lateral movement in an Active Directory network can include the abuse of system utilities (such as `psexec.exe`), unauthorized use of remote desktop services, `file/admin$` shares, WMI, PowerShell, Service Control Manager, the DCOM protocol, WinRM or the abuse of scheduled tasks. Organizations must be extra vigilant in detecting lateral movement techniques and look for suspicious activity in and around high-value strategic network assets, such as Active Directory, which are often considered the primary target or "crown jewels" to a persistent threat actor.\
An adversary can use lateral movement for multiple purposes, including remote execution of tools, pivoting to additional systems, obtaining access to specific information or files, access to additional credentials, exfiltrating data, or delivering a secondary effect. Adversaries may use legitimate credentials alongside inherent network and operating-system functionality to remotely connect to other systems and remain under the radar of network defenders.\
If there is evidence of lateral movement, it is imperative for analysts to collect evidence of the associated offending hosts. For example, an attacker might leverage host A to gain access to host B. From there, the attacker may try to move laterally to host C. In this example, the analyst should gather as much information as possible from all three hosts. \
 It is also important to collect authentication logs for each host, to ensure that the offending accounts are well-documented. Analysts should account for all processes to ensure that the attackers did not install unauthorized software.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Detect Activity Related to Pass the Hash Attacks](/endpoint/f5939373-8054-40ad-8c64-cec478a22a4b/) | [Use Alternate Authentication Material](/tags/#use-alternate-authentication-material), [Pass the Hash](/tags/#pass-the-hash) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect PsExec With accepteula Flag](/endpoint/27c3a83d-cada-47c6-9042-67baf19d2574/) | [Remote Services](/tags/#remote-services), [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Renamed PSExec](/endpoint/683e6196-b8e8-11eb-9a79-acde48001122/) | [System Services](/tags/#system-services), [Service Execution](/tags/#service-execution) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Executable File Written in Administrative SMB Share](/endpoint/f63c34fe-a435-11eb-935a-acde48001122/) | [Remote Services](/tags/#remote-services), [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Impacket Lateral Movement Commandline Parameters](/endpoint/8ce07472-496f-11ec-ab3b-3e22fbd008af/) | [Remote Services](/tags/#remote-services), [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares), [Distributed Component Object Model](/tags/#distributed-component-object-model), [Windows Management Instrumentation](/tags/#windows-management-instrumentation), [Windows Service](/tags/#windows-service) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Interactive Session on Remote Endpoint with PowerShell](/endpoint/a4e8f3a4-48b2-11ec-bcfc-3e22fbd008af/) | [Remote Services](/tags/#remote-services), [Windows Remote Management](/tags/#windows-remote-management) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Mmc LOLBAS Execution Process Spawn](/endpoint/f6601940-4c74-11ec-b9b7-3e22fbd008af/) | [Remote Services](/tags/#remote-services), [Distributed Component Object Model](/tags/#distributed-component-object-model), [MMC](/tags/#mmc) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Possible Lateral Movement PowerShell Spawn](/endpoint/cb909b3e-512b-11ec-aa31-3e22fbd008af/) | [Remote Services](/tags/#remote-services), [Distributed Component Object Model](/tags/#distributed-component-object-model), [Windows Remote Management](/tags/#windows-remote-management), [Windows Management Instrumentation](/tags/#windows-management-instrumentation), [Scheduled Task](/tags/#scheduled-task), [Windows Service](/tags/#windows-service), [PowerShell](/tags/#powershell), [MMC](/tags/#mmc) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Potential Pass the Token or Hash Observed at the Destination Device](/deprecated/82e76b80-5cdb-4899-9b43-85dbe777b36d/) | [Use Alternate Authentication Material](/tags/#use-alternate-authentication-material), [Pass the Hash](/tags/#pass-the-hash) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Potential Pass the Token or Hash Observed by an Event Collecting Device](/deprecated/1058ba3e-a698-49bc-a1e5-7cedece4ea87/) | [Use Alternate Authentication Material](/tags/#use-alternate-authentication-material), [Pass the Hash](/tags/#pass-the-hash) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Randomly Generated Scheduled Task Name](/endpoint/9d22a780-5165-11ec-ad4f-3e22fbd008af/) | [Scheduled Task/Job](/tags/#scheduled-task/job), [Scheduled Task](/tags/#scheduled-task) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Randomly Generated Windows Service Name](/endpoint/2032a95a-5165-11ec-a2c3-3e22fbd008af/) | [Create or Modify System Process](/tags/#create-or-modify-system-process), [Windows Service](/tags/#windows-service) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Remote Desktop Network Traffic](/network/272b8407-842d-4b3d-bead-a704584003d3/) | [Remote Desktop Protocol](/tags/#remote-desktop-protocol), [Remote Services](/tags/#remote-services) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Remote Desktop Process Running On System](/endpoint/f5939373-8054-40ad-8c64-cec478a22a4a/) | [Remote Desktop Protocol](/tags/#remote-desktop-protocol), [Remote Services](/tags/#remote-services) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Remote Process Instantiation via DCOM and PowerShell](/endpoint/d4f42098-4680-11ec-ad07-3e22fbd008af/) | [Remote Services](/tags/#remote-services), [Distributed Component Object Model](/tags/#distributed-component-object-model) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Remote Process Instantiation via DCOM and PowerShell Script Block](/endpoint/fa1c3040-4680-11ec-a618-3e22fbd008af/) | [Remote Services](/tags/#remote-services), [Distributed Component Object Model](/tags/#distributed-component-object-model) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Remote Process Instantiation via WMI](/endpoint/d25d2c3d-d9d8-40ec-8fdf-e86fe155a3da/) | [Windows Management Instrumentation](/tags/#windows-management-instrumentation) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Remote Process Instantiation via WMI and PowerShell](/endpoint/112638b4-4634-11ec-b9ab-3e22fbd008af/) | [Windows Management Instrumentation](/tags/#windows-management-instrumentation) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Remote Process Instantiation via WMI and PowerShell Script Block](/endpoint/2a048c14-4634-11ec-a618-3e22fbd008af/) | [Windows Management Instrumentation](/tags/#windows-management-instrumentation) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Remote Process Instantiation via WinRM and PowerShell](/endpoint/ba24cda8-4716-11ec-8009-3e22fbd008af/) | [Remote Services](/tags/#remote-services), [Windows Remote Management](/tags/#windows-remote-management) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Remote Process Instantiation via WinRM and PowerShell Script Block](/endpoint/7d4c618e-4716-11ec-951c-3e22fbd008af/) | [Remote Services](/tags/#remote-services), [Windows Remote Management](/tags/#windows-remote-management) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Remote Process Instantiation via WinRM and Winrs](/endpoint/0dd296a2-4338-11ec-ba02-3e22fbd008af/) | [Remote Services](/tags/#remote-services), [Windows Remote Management](/tags/#windows-remote-management) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Scheduled Task Creation on Remote Endpoint using At](/endpoint/4be54858-432f-11ec-8209-3e22fbd008af/) | [Scheduled Task/Job](/tags/#scheduled-task/job), [At](/tags/#at) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Scheduled Task Initiation on Remote Endpoint](/endpoint/95cf4608-4302-11ec-8194-3e22fbd008af/) | [Scheduled Task/Job](/tags/#scheduled-task/job), [Scheduled Task](/tags/#scheduled-task) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Schtasks scheduling job on remote system](/endpoint/1297fb80-f42a-4b4a-9c8a-88c066237cf6/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Services LOLBAS Execution Process Spawn](/endpoint/ba9e1954-4c04-11ec-8b74-3e22fbd008af/) | [Create or Modify System Process](/tags/#create-or-modify-system-process), [Windows Service](/tags/#windows-service) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Short Lived Scheduled Task](/endpoint/6fa31414-546e-11ec-adfa-acde48001122/) | [Scheduled Task](/tags/#scheduled-task) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Svchost LOLBAS Execution Process Spawn](/endpoint/09e5c72a-4c0d-11ec-aa29-3e22fbd008af/) | [Scheduled Task/Job](/tags/#scheduled-task/job), [Scheduled Task](/tags/#scheduled-task) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Unusual Number of Computer Service Tickets Requested](/endpoint/ac3b81c0-52f4-11ec-ac44-acde48001122/) | [Valid Accounts](/tags/#valid-accounts) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Unusual Number of Remote Endpoint Authentication Events](/endpoint/acb5dc74-5324-11ec-a36d-acde48001122/) | [Valid Accounts](/tags/#valid-accounts) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [WinEvent Scheduled Task Created Within Public Path](/endpoint/5d9c6eee-988c-11eb-8253-acde48001122/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Service Created With Suspicious Service Path](/endpoint/429141be-8311-11eb-adb6-acde48001122/) | [System Services](/tags/#system-services), [Service Execution](/tags/#service-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Service Created Within Public Path](/endpoint/3abb2eda-4bb8-11ec-9ae4-3e22fbd008af/) | [Create or Modify System Process](/tags/#create-or-modify-system-process), [Windows Service](/tags/#windows-service) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Service Creation Using Registry Entry](/endpoint/25212358-948e-11ec-ad47-acde48001122/) | [Services Registry Permissions Weakness](/tags/#services-registry-permissions-weakness) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Service Creation on Remote Endpoint](/endpoint/e0eea4fa-4274-11ec-882b-3e22fbd008af/) | [Create or Modify System Process](/tags/#create-or-modify-system-process), [Windows Service](/tags/#windows-service) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Service Initiation on Remote Endpoint](/endpoint/3f519894-4276-11ec-ab02-3e22fbd008af/) | [Create or Modify System Process](/tags/#create-or-modify-system-process), [Windows Service](/tags/#windows-service) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Wmiprsve LOLBAS Execution Process Spawn](/endpoint/95a455f0-4c04-11ec-b8ac-3e22fbd008af/) | [Windows Management Instrumentation](/tags/#windows-management-instrumentation) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Wsmprovhost LOLBAS Execution Process Spawn](/endpoint/2eed004c-4c0d-11ec-93e8-3e22fbd008af/) | [Remote Services](/tags/#remote-services), [Windows Remote Management](/tags/#windows-remote-management) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://www.fireeye.com/blog/executive-perspective/2015/08/malware_lateral_move.html](https://www.fireeye.com/blog/executive-perspective/2015/08/malware_lateral_move.html)
* [http://www.irongeek.com/i.php?page=videos/derbycon7/t405-hunting-lateral-movement-for-fun-and-profit-mauricio-velazco](http://www.irongeek.com/i.php?page=videos/derbycon7/t405-hunting-lateral-movement-for-fun-and-profit-mauricio-velazco)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/active_directory_lateral_movement.yml) \| *version*: **3**