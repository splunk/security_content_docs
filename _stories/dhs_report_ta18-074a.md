---
title: "DHS Report TA18-074A"
last_modified_at: 2020-01-22
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Network_Traffic
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Monitor for suspicious activities associated with DHS Technical Alert US-CERT TA18-074A. Some of the activities that adversaries used in these compromises included spearfishing attacks, malware, watering-hole domains, many and more.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic)
- **Last Updated**: 2020-01-22
- **Author**: Rico Valdez, Splunk
- **ID**: 0c016e5c-88be-4e2c-8c6c-c2b55b4fb4ef

#### Narrative

The frequency of nation-state cyber attacks has increased significantly over the last decade. Employing numerous tactics and techniques, these attacks continue to escalate in complexity. \
There is a wide range of motivations for these state-sponsored hacks, including stealing valuable corporate, military, or diplomatic data&#1151;all of which could confer advantages in various arenas. They may also target critical infrastructure. \
One joint Technical Alert (TA) issued by the Department of Homeland and the FBI in mid-March of 2018 attributed some cyber activity targeting utility infrastructure to operatives sponsored by the Russian government. The hackers executed spearfishing attacks, installed malware, employed watering-hole domains, and more. While they caused no physical damage, the attacks provoked fears that a nation-state could turn off water, redirect power, or compromise a nuclear power plant.\
Suspicious activities--spikes in SMB traffic, processes that launch netsh (to modify the network configuration), suspicious registry modifications, and many more--may all be events you may wish to investigate further. While the use of these technique may be an indication that a nation-state actor is attempting to compromise your environment, it is important to note that these techniques are often employed by other groups, as well.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Create local admin accounts using net exe](/endpoint/b89919ed-fe5f-492c-b139-151bb162040e/) | [Local Account](/tags/#local-account), [Create Account](/tags/#create-account) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect New Local Admin account](/endpoint/b25f6f62-0712-43c1-b203-083231ffd97d/) | [Local Account](/tags/#local-account), [Create Account](/tags/#create-account) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Outbound SMB Traffic](/network/1bed7774-304a-4e8f-9d72-d80e45ff492b/) | [File Transfer Protocols](/tags/#file-transfer-protocols), [Application Layer Protocol](/tags/#application-layer-protocol) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect PsExec With accepteula Flag](/endpoint/27c3a83d-cada-47c6-9042-67baf19d2574/) | [Remote Services](/tags/#remote-services), [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Renamed PSExec](/endpoint/683e6196-b8e8-11eb-9a79-acde48001122/) | [System Services](/tags/#system-services), [Service Execution](/tags/#service-execution) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [First time seen command line argument](/deprecated/a1b6e73f-98d5-470f-99ac-77aacd578473/) | [PowerShell](/tags/#powershell), [Windows Command Shell](/tags/#windows-command-shell) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Malicious PowerShell Process - Execution Policy Bypass](/endpoint/9be56c82-b1cc-4318-87eb-d138afaaca39/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Processes launching netsh](/endpoint/b89919ed-fe5f-492c-b139-95dbb162040e/) | [Disable or Modify System Firewall](/tags/#disable-or-modify-system-firewall), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Registry Keys Used For Persistence](/endpoint/f5f6af30-7aa7-4295-bfe9-07fe87c01a4b/) | [Registry Run Keys / Startup Folder](/tags/#registry-run-keys-/-startup-folder), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [SMB Traffic Spike](/network/7f5fb3e1-4209-4914-90db-0ec21b936378/) | [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares), [Remote Services](/tags/#remote-services) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [SMB Traffic Spike - MLTK](/network/d25773ba-9ad8-48d1-858e-07ad0bbeb828/) | [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares), [Remote Services](/tags/#remote-services) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Sc exe Manipulating Windows Services](/endpoint/f0c693d8-2a89-4ce7-80b4-98fea4c3ea6d/) | [Windows Service](/tags/#windows-service), [Create or Modify System Process](/tags/#create-or-modify-system-process) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Scheduled Task Deleted Or Created via CMD](/endpoint/d5af132c-7c17-439c-9d31-13d55340f36c/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Single Letter Process On Endpoint](/endpoint/a4214f0b-e01c-41bc-8cc4-d2b71e3056b4/) | [User Execution](/tags/#user-execution), [Malicious File](/tags/#malicious-file) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Reg exe Process](/endpoint/a6b3ab4e-dd77-4213-95fa-fc94701995e0/) | [Modify Registry](/tags/#modify-registry) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://www.us-cert.gov/ncas/alerts/TA18-074A](https://www.us-cert.gov/ncas/alerts/TA18-074A)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/dhs_report_ta18-074a.yml) \| *version*: **2**