---
title: "Sandworm Tools"
last_modified_at: 2022-04-05
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

This analytic story features detections that enable security analysts to identify and investigate unusual activities potentially related to the destructive malware and tools employed by the "Sandworm" group. This analytic story focuses on monitoring suspicious process executions, command-line activities, Master Boot Record (MBR) wiping, data destruction, and other related indicators.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-04-05
- **Author**: Teoderick Contreras, Splunk
- **ID**: 54146850-9d26-4877-a611-2db33231e63e

#### Narrative

The Sandworm group's tools are part of destructive malware operations designed to disrupt or attack Ukraine's National Information Agencies. This operation campaign consists of several malware components, including scripts, native Windows executables (LOLBINs), data wiper malware that overwrites or destroys the Master Boot Record (MBR), and file wiping using sdelete.exe on targeted hosts.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Detect Mimikatz Using Loaded Images](/deprecated/29e307ba-40af-4ab2-91b2-3c6b392bbba0/) | [LSASS Memory](/tags/#lsass-memory), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Mimikatz With PowerShell Script Block Logging](/endpoint/8148c29c-c952-11eb-9255-acde48001122/) | [OS Credential Dumping](/tags/#os-credential-dumping), [PowerShell](/tags/#powershell) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect PsExec With accepteula Flag](/endpoint/27c3a83d-cada-47c6-9042-67baf19d2574/) | [Remote Services](/tags/#remote-services), [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Renamed PSExec](/endpoint/683e6196-b8e8-11eb-9a79-acde48001122/) | [System Services](/tags/#system-services), [Service Execution](/tags/#service-execution) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Icacls Deny Command](/endpoint/cf8d753e-a8fe-11eb-8f58-acde48001122/) | [File and Directory Permissions Modification](/tags/#file-and-directory-permissions-modification) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Iptables Firewall Modification](/endpoint/309d59dc-1e1b-49b2-9800-7cf18d12f7b7/) | [Disable or Modify System Firewall](/tags/#disable-or-modify-system-firewall), [Impair Defenses](/tags/#impair-defenses) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Kworker Process In Writable Process Path](/endpoint/1cefb270-74a5-4e27-aa0c-2b6fa7c5b4ed/) | [Masquerade Task or Service](/tags/#masquerade-task-or-service), [Masquerading](/tags/#masquerading) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Local Account Discovery with Net](/endpoint/5d0d4830-0133-11ec-bae3-acde48001122/) | [Account Discovery](/tags/#account-discovery), [Local Account](/tags/#local-account) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Malicious PowerShell Process - Encoded Command](/endpoint/c4db14d9-7909-48b4-a054-aa14d89dbb19/) | [Obfuscated Files or Information](/tags/#obfuscated-files-or-information) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Mimikatz PassTheTicket CommandLine Parameters](/endpoint/13bbd574-83ac-11ec-99d4-acde48001122/) | [Use Alternate Authentication Material](/tags/#use-alternate-authentication-material), [Pass the Ticket](/tags/#pass-the-ticket) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Permission Modification using Takeown App](/endpoint/fa7ca5c6-c9d8-11eb-bce9-acde48001122/) | [File and Directory Permissions Modification](/tags/#file-and-directory-permissions-modification) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Scheduled Task Deleted Or Created via CMD](/endpoint/d5af132c-7c17-439c-9d31-13d55340f36c/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Copy on System32](/endpoint/ce633e56-25b2-11ec-9e76-acde48001122/) | [Rename System Utilities](/tags/#rename-system-utilities), [Masquerading](/tags/#masquerading) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [WinEvent Windows Task Scheduler Event Action Started](/endpoint/b3632472-310b-11ec-9aab-acde48001122/) | [Scheduled Task](/tags/#scheduled-task) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows DNS Gather Network Info](/endpoint/347e0892-e8f3-4512-afda-dc0e3fa996f3/) | [DNS](/tags/#dns) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows High File Deletion Frequency](/endpoint/45b125c4-866f-11eb-a95a-acde48001122/) | [Data Destruction](/tags/#data-destruction) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Mimikatz Binary Execution](/endpoint/a9e0d6d3-9676-4e26-994d-4e0406bb4467/) | [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Mimikatz Crypto Export File Extensions](/endpoint/3a9a6806-16a8-4cda-8d73-b49d10a05b16/) | [Steal or Forge Authentication Certificates](/tags/#steal-or-forge-authentication-certificates) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows System Shutdown CommandLine](/endpoint/4fee57b8-d825-4bf3-9ea8-bf405cdb614c/) | [System Shutdown/Reboot](/tags/#system-shutdown/reboot) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://cert.gov.ua/article/3718487](https://cert.gov.ua/article/3718487)
* [https://attack.mitre.org/groups/G0034/](https://attack.mitre.org/groups/G0034/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/sandworm_tools.yml) \| *version*: **1**