---
title: "Industroyer2"
last_modified_at: 2022-04-21
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

Leverage searches that allow you to detect and investigate unusual activities that might relate to the Industroyer2 attack, including file writes associated with its payload, lateral movement, persistence, privilege escalation and data destruction.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-04-21
- **Author**: Teoderick Contreras, Splunk
- **ID**: 7ff7db2b-b001-498e-8fe8-caf2dbc3428a

#### Narrative

Industroyer2 is part of continuous attack to ukraine targeting energy facilities. This malware is a windows binary that implement IEC-104 protocol to communicate with industrial equipments. This attack consist of several destructive linux script component to wipe or delete several linux critical files, powershell for domain enumeration and caddywiper to wipe boot sector of the targeted host.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [AdsiSearcher Account Discovery](/endpoint/de7fcadc-04f3-11ec-a241-acde48001122/) | [Domain Account](/tags/#domain-account), [Account Discovery](/tags/#account-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Attempted Credential Dump From Registry via Reg exe](/endpoint/e9fb4a59-c5fb-440a-9f24-191fbc6b2911/) | [Security Account Manager](/tags/#security-account-manager), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Dump LSASS via comsvcs DLL](/endpoint/8943b567-f14d-4ee8-a0bb-2121d4ce3184/) | [LSASS Memory](/tags/#lsass-memory), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Executable File Written in Administrative SMB Share](/endpoint/f63c34fe-a435-11eb-935a-acde48001122/) | [Remote Services](/tags/#remote-services), [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Executables Or Script Creation In Suspicious Path](/endpoint/a7e3f0f0-ae42-11eb-b245-acde48001122/) | [Masquerading](/tags/#masquerading) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Impacket Lateral Movement Commandline Parameters](/endpoint/8ce07472-496f-11ec-ab3b-3e22fbd008af/) | [Remote Services](/tags/#remote-services), [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares), [Distributed Component Object Model](/tags/#distributed-component-object-model), [Windows Management Instrumentation](/tags/#windows-management-instrumentation), [Windows Service](/tags/#windows-service) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Impacket Lateral Movement WMIExec Commandline Parameters](/endpoint/d6e464e4-5c6a-474e-82d2-aed616a3a492/) | [Remote Services](/tags/#remote-services), [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares), [Distributed Component Object Model](/tags/#distributed-component-object-model), [Windows Management Instrumentation](/tags/#windows-management-instrumentation), [Windows Service](/tags/#windows-service) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Impacket Lateral Movement smbexec CommandLine Parameters](/endpoint/bb3c1bac-6bdf-4aa0-8dc9-068b8b712a76/) | [Remote Services](/tags/#remote-services), [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares), [Distributed Component Object Model](/tags/#distributed-component-object-model), [Windows Management Instrumentation](/tags/#windows-management-instrumentation), [Windows Service](/tags/#windows-service) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Adding Crontab Using List Parameter](/endpoint/52f6d751-1fd4-4c74-a4c9-777ecfeb5c58/) | [Cron](/tags/#cron), [Scheduled Task/Job](/tags/#scheduled-task/job) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux DD File Overwrite](/endpoint/9b6aae5e-8d85-11ec-b2ae-acde48001122/) | [Data Destruction](/tags/#data-destruction) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Deleting Critical Directory Using RM Command](/endpoint/33f89303-cc6f-49ad-921d-2eaea38a6f7a/) | [Data Destruction](/tags/#data-destruction) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Disable Services](/endpoint/f2e08a38-6689-4df4-ad8c-b51c16262316/) | [Service Stop](/tags/#service-stop) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux High Frequency Of File Deletion In Boot Folder](/endpoint/e27fbc5d-0445-4c4a-bc39-87f060d5c602/) | [Data Destruction](/tags/#data-destruction), [File Deletion](/tags/#file-deletion), [Indicator Removal](/tags/#indicator-removal) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Shred Overwrite Command](/endpoint/c1952cf1-643c-4965-82de-11c067cbae76/) | [Data Destruction](/tags/#data-destruction) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Stdout Redirection To Dev Null File](/endpoint/de62b809-a04d-46b5-9a15-8298d330f0c8/) | [Disable or Modify System Firewall](/tags/#disable-or-modify-system-firewall), [Impair Defenses](/tags/#impair-defenses) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Stop Services](/endpoint/d05204a5-9f1c-4946-a7f3-4fa58d76d5fd/) | [Service Stop](/tags/#service-stop) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux System Network Discovery](/endpoint/535cb214-8b47-11ec-a2c7-acde48001122/) | [System Network Configuration Discovery](/tags/#system-network-configuration-discovery) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Recon Using WMI Class](/endpoint/018c1972-ca07-11eb-9473-acde48001122/) | [Gather Victim Host Information](/tags/#gather-victim-host-information), [PowerShell](/tags/#powershell) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Schtasks Run Task On Demand](/endpoint/bb37061e-af1f-11eb-a159-acde48001122/) | [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Process File Path](/endpoint/9be25988-ad82-11eb-a14f-acde48001122/) | [Create or Modify System Process](/tags/#create-or-modify-system-process) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [WinEvent Scheduled Task Created Within Public Path](/endpoint/5d9c6eee-988c-11eb-8253-acde48001122/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [WinEvent Windows Task Scheduler Event Action Started](/endpoint/b3632472-310b-11ec-9aab-acde48001122/) | [Scheduled Task](/tags/#scheduled-task) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Hidden Schedule Task Settings](/endpoint/0b730470-5fe8-4b13-93a7-fe0ad014d0cc/) | [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Linked Policies In ADSI Discovery](/endpoint/510ea428-4731-4d2f-8829-a28293e427aa/) | [Domain Account](/tags/#domain-account), [Account Discovery](/tags/#account-discovery) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Processes Killed By Industroyer2 Malware](/endpoint/d8bea5ca-9d4a-4249-8b56-64a619109835/) | [Service Stop](/tags/#service-stop) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Root Domain linked policies Discovery](/endpoint/80ffaede-1f12-49d5-a86e-b4b599b68b3c/) | [Domain Account](/tags/#domain-account), [Account Discovery](/tags/#account-discovery) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://cert.gov.ua/article/39518](https://cert.gov.ua/article/39518)
* [https://www.welivesecurity.com/2022/04/12/industroyer2-industroyer-reloaded/](https://www.welivesecurity.com/2022/04/12/industroyer2-industroyer-reloaded/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/industroyer2.yml) \| *version*: **1**