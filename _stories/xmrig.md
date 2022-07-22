---
title: "XMRig"
last_modified_at: 2021-05-07
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Endpoint_Processes
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Leverage searches that allow you to detect and investigate unusual activities that might relate to the xmrig monero, including looking for file writes associated with its payload, process command-line, defense evasion (killing services, deleting users, modifying files or folder permission, killing other malware or other coin miner) and hacking tools including Telegram as mean of command and control (C2) to download other files. Adversaries may leverage the resources of co-opted systems in order to solve resource intensive problems which may impact system and/or hosted service availability. One common purpose for Resource Hijacking is to validate transactions of cryptocurrency networks and earn virtual currency. Adversaries may consume enough system resources to negatively impact and/or cause affected machines to become unresponsive. (1) Servers and cloud-based (2) systems are common targets because of the high potential for available resources, but user endpoint systems may also be compromised and used for Resource Hijacking and cryptocurrency mining.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Endpoint_Processes](https://docs.splunk.com/Documentation/CIM/latest/User/EndpointProcesses)
- **Last Updated**: 2021-05-07
- **Author**: Teoderick Contreras, Rod Soto Splunk
- **ID**: 06723e6a-6bd8-4817-ace2-5fb8a7b06628

#### Narrative

XMRig is a high performance, open source, cross platform RandomX, KawPow, CryptoNight and AstroBWT unified CPU/GPU miner. This monero is seen in the wild on May 2017.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Attacker Tools On Endpoint](/endpoint/a51bfe1a-94f0-48cc-b4e4-16a110145893/) | [Match Legitimate Name or Location](/tags/#match-legitimate-name-or-location), [Masquerading](/tags/#masquerading), [OS Credential Dumping](/tags/#os-credential-dumping), [Active Scanning](/tags/#active-scanning) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Attempt To Delete Services](/endpoint/a0c8c292-d01a-11eb-aa18-acde48001122/) | [Service Stop](/tags/#service-stop), [Create or Modify System Process](/tags/#create-or-modify-system-process), [Windows Service](/tags/#windows-service) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Attempt To Disable Services](/endpoint/afb31de4-d023-11eb-98d5-acde48001122/) | [Service Stop](/tags/#service-stop) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Delete A Net User](/endpoint/8776d79c-d26e-11eb-9a56-acde48001122/) | [Account Access Removal](/tags/#account-access-removal) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Deleting Of Net Users](/endpoint/1c8c6f66-acce-11eb-aafb-acde48001122/) | [Account Access Removal](/tags/#account-access-removal) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Deny Permission using Cacls Utility](/endpoint/b76eae28-cd25-11eb-9c92-acde48001122/) | [File and Directory Permissions Modification](/tags/#file-and-directory-permissions-modification) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disable Net User Account](/endpoint/ba858b08-d26c-11eb-af9b-acde48001122/) | [Service Stop](/tags/#service-stop), [Valid Accounts](/tags/#valid-accounts) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disable Windows App Hotkeys](/endpoint/1490f224-ad8b-11eb-8c4f-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disabling Net User Account](/endpoint/c0325326-acd6-11eb-98c2-acde48001122/) | [Account Access Removal](/tags/#account-access-removal) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Download Files Using Telegram](/endpoint/58194e28-ae5e-11eb-8912-acde48001122/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Enumerate Users Local Group Using Telegram](/endpoint/fcd74532-ae54-11eb-a5ab-acde48001122/) | [Account Discovery](/tags/#account-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Excessive Attempt To Disable Services](/endpoint/8fa2a0f0-acd9-11eb-8994-acde48001122/) | [Service Stop](/tags/#service-stop) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Excessive Service Stop Attempt](/endpoint/ae8d3f4a-acd7-11eb-8846-acde48001122/) | [Service Stop](/tags/#service-stop) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Excessive Usage Of Cacls App](/endpoint/0bdf6092-af17-11eb-939a-acde48001122/) | [File and Directory Permissions Modification](/tags/#file-and-directory-permissions-modification) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Excessive Usage Of Net App](/endpoint/45e52536-ae42-11eb-b5c6-acde48001122/) | [Account Access Removal](/tags/#account-access-removal) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Excessive Usage Of Taskkill](/endpoint/fe5bca48-accb-11eb-a67c-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Executables Or Script Creation In Suspicious Path](/endpoint/a7e3f0f0-ae42-11eb-b245-acde48001122/) | [Masquerading](/tags/#masquerading) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Grant Permission Using Cacls Utility](/endpoint/c6da561a-cd29-11eb-ae65-acde48001122/) | [File and Directory Permissions Modification](/tags/#file-and-directory-permissions-modification) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Hide User Account From Sign-In Screen](/endpoint/834ba832-ad89-11eb-937d-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [ICACLS Grant Command](/endpoint/b1b1e316-accc-11eb-a9b4-acde48001122/) | [File and Directory Permissions Modification](/tags/#file-and-directory-permissions-modification) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Icacls Deny Command](/endpoint/cf8d753e-a8fe-11eb-8f58-acde48001122/) | [File and Directory Permissions Modification](/tags/#file-and-directory-permissions-modification) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Modify ACL permission To Files Or Folder](/endpoint/7e8458cc-acca-11eb-9e3f-acde48001122/) | [File and Directory Permissions Modification](/tags/#file-and-directory-permissions-modification) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Modify ACLs Permission Of Files Or Folders](/endpoint/9ae9a48a-cdbe-11eb-875a-acde48001122/) | [File and Directory Permissions Modification](/tags/#file-and-directory-permissions-modification) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Process Kill Base On File Path](/endpoint/5ffaa42c-acdb-11eb-9ad3-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Schtasks Run Task On Demand](/endpoint/bb37061e-af1f-11eb-a159-acde48001122/) | [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Driver Loaded Path](/endpoint/f880acd4-a8f1-11eb-a53b-acde48001122/) | [Windows Service](/tags/#windows-service), [Create or Modify System Process](/tags/#create-or-modify-system-process) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Process File Path](/endpoint/9be25988-ad82-11eb-a14f-acde48001122/) | [Create or Modify System Process](/tags/#create-or-modify-system-process) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [XMRIG Driver Loaded](/endpoint/90080fa6-a8df-11eb-91e4-acde48001122/) | [Windows Service](/tags/#windows-service), [Create or Modify System Process](/tags/#create-or-modify-system-process) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://github.com/xmrig/xmrig](https://github.com/xmrig/xmrig)
* [https://www.getmonero.org/resources/user-guides/mine-to-pool.html](https://www.getmonero.org/resources/user-guides/mine-to-pool.html)
* [https://thedfirreport.com/2020/04/20/sqlserver-or-the-miner-in-the-basement/](https://thedfirreport.com/2020/04/20/sqlserver-or-the-miner-in-the-basement/)
* [https://blog.checkpoint.com/2021/03/11/february-2021s-most-wanted-malware-trickbot-takes-over-following-emotet-shutdown/](https://blog.checkpoint.com/2021/03/11/february-2021s-most-wanted-malware-trickbot-takes-over-following-emotet-shutdown/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/xmrig.yml) \| *version*: **1**