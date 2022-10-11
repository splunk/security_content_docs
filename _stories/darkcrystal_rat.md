---
title: "DarkCrystal RAT"
last_modified_at: 2022-07-26
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

Leverage searches that allow you to detect and investigate unusual activities that might relate to the DcRat malware including ddos, spawning more process, botnet c2 communication, defense evasion and etc. The DcRat malware is known commercial backdoor that was first released in 2018. This tool was sold in underground forum and known to be one of the cheapest commercial RATs. DcRat is modular and bespoke plugin framework make it a very flexible option, helpful for a range of nefearious uses.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Endpoint_Processes](https://docs.splunk.com/Documentation/CIM/latest/User/EndpointProcesses)
- **Last Updated**: 2022-07-26
- **Author**: Teoderick Contreras, Splunk
- **ID**: 639e6006-0885-4847-9394-ddc2902629bf

#### Narrative

Adversaries may use this technique to maximize the impact on the target organization in operations where network wide availability interruption is the goal.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Any Powershell DownloadFile](/endpoint/1a93b7ea-7af7-11eb-adb5-acde48001122/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell), [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [CMD Carry Out String Command Parameter](/endpoint/54a6ed00-3256-11ec-b031-acde48001122/) | [Windows Command Shell](/tags/#windows-command-shell), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Executables Or Script Creation In Suspicious Path](/endpoint/a7e3f0f0-ae42-11eb-b245-acde48001122/) | [Masquerading](/tags/#masquerading) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Malicious PowerShell Process - Encoded Command](/endpoint/c4db14d9-7909-48b4-a054-aa14d89dbb19/) | [Obfuscated Files or Information](/tags/#obfuscated-files-or-information) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Malicious PowerShell Process - Execution Policy Bypass](/endpoint/9be56c82-b1cc-4318-87eb-d138afaaca39/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Office Document Executing Macro Code](/endpoint/b12c89bc-9d06-11eb-a592-acde48001122/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Office Product Spawn CMD Process](/endpoint/b8b19420-e892-11eb-9244-acde48001122/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Mshta](/tags/#mshta) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Scheduled Task Deleted Or Created via CMD](/endpoint/d5af132c-7c17-439c-9d31-13d55340f36c/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Process File Path](/endpoint/9be25988-ad82-11eb-a14f-acde48001122/) | [Create or Modify System Process](/tags/#create-or-modify-system-process) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Scheduled Task from Public Directory](/endpoint/7feb7972-7ac3-11eb-bac8-acde48001122/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [WinEvent Windows Task Scheduler Event Action Started](/endpoint/b3632472-310b-11ec-9aab-acde48001122/) | [Scheduled Task](/tags/#scheduled-task) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Command Shell DCRat ForkBomb Payload](/endpoint/2bb1a362-7aa8-444a-92ed-1987e8da83e1/) | [Windows Command Shell](/tags/#windows-command-shell), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Gather Victim Host Information Camera](/endpoint/e4df4676-ea41-4397-b160-3ee0140dc332/) | [Hardware](/tags/#hardware), [Gather Victim Host Information](/tags/#gather-victim-host-information) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Gather Victim Network Info Through Ip Check Web Services](/endpoint/70f7c952-0758-46d6-9148-d8969c4481d1/) | [IP Addresses](/tags/#ip-addresses), [Gather Victim Network Information](/tags/#gather-victim-network-information) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows High File Deletion Frequency](/endpoint/45b125c4-866f-11eb-a95a-acde48001122/) | [Data Destruction](/tags/#data-destruction) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Ingress Tool Transfer Using Explorer](/endpoint/76753bab-f116-4ea3-8fb9-89b638be58a9/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Ingress Tool Transfer Using Explorer](/endpoint/695bfad6-9662-4f9e-a576-bf02a951aa60/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows System LogOff Commandline](/endpoint/74a8133f-93e7-4b71-9bd3-13a66124fd57/) | [System Shutdown/Reboot](/tags/#system-shutdown/reboot) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows System Reboot CommandLine](/endpoint/97fc2b60-c8eb-4711-93f7-d26fade3686f/) | [System Shutdown/Reboot](/tags/#system-shutdown/reboot) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows System Shutdown CommandLine](/endpoint/4fee57b8-d825-4bf3-9ea8-bf405cdb614c/) | [System Shutdown/Reboot](/tags/#system-shutdown/reboot) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows System Time Discovery W32tm Delay](/endpoint/b2cc69e7-11ba-42dc-a269-59c069a48870/) | [System Time Discovery](/tags/#system-time-discovery) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Winword Spawning Cmd](/endpoint/6fcbaedc-a37b-11eb-956b-acde48001122/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Winword Spawning PowerShell](/endpoint/b2c950b8-9be2-11eb-8658-acde48001122/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://www.mandiant.com/resources/analyzing-dark-crystal-rat-backdoor](https://www.mandiant.com/resources/analyzing-dark-crystal-rat-backdoor)
* [https://malpedia.caad.fkie.fraunhofer.de/details/win.dcrat](https://malpedia.caad.fkie.fraunhofer.de/details/win.dcrat)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/darkcrystal_rat.yml) \| *version*: **1**