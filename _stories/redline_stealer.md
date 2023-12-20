---
title: "RedLine Stealer"
last_modified_at: 2023-04-24
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Updates
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Leverage searches that allow you to detect and investigate unusual activities that might relate to the Redline Stealer trojan, including looking for file writes associated with its payload, screencapture, registry modification, persistence and data collection..

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Updates](https://docs.splunk.com/Documentation/CIM/latest/User/Updates)
- **Last Updated**: 2023-04-24
- **Author**: Teoderick Contreras, Splunk
- **ID**: 12e31e8b-671b-4d6e-b362-a682812a71eb

#### Narrative

RedLine Stealer is a malware available on underground forum and subscription basis that are compiled or written in C#. This malware is capable of harvesting sensitive information from browsers such as saved credentials, auto file data, browser cookies and credit card information. It also gathers system information of the targeted or compromised host like username, location IP, RAM size available, hardware configuration and software installed. The current version of this malware contains features to steal wallet and crypto currency information.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [CMD Carry Out String Command Parameter](/endpoint/54a6ed00-3256-11ec-b031-acde48001122/) | [Windows Command Shell](/tags/#windows-command-shell), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disable Windows Behavior Monitoring](/endpoint/79439cae-9200-11eb-a4d3-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disabling Defender Services](/endpoint/911eacdc-317f-11ec-ad30-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Executables Or Script Creation In Suspicious Path](/endpoint/a7e3f0f0-ae42-11eb-b245-acde48001122/) | [Masquerading](/tags/#masquerading) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Non Chrome Process Accessing Chrome Default Dir](/endpoint/81263de4-160a-11ec-944f-acde48001122/) | [Credentials from Password Stores](/tags/#credentials-from-password-stores), [Credentials from Web Browsers](/tags/#credentials-from-web-browsers) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Non Firefox Process Access Firefox Profile Dir](/endpoint/e6fc13b0-1609-11ec-b533-acde48001122/) | [Credentials from Password Stores](/tags/#credentials-from-password-stores), [Credentials from Web Browsers](/tags/#credentials-from-web-browsers) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Registry Keys Used For Persistence](/endpoint/f5f6af30-7aa7-4295-bfe9-07fe87c01a4b/) | [Registry Run Keys / Startup Folder](/tags/#registry-run-keys-/-startup-folder), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Scheduled Task Deleted Or Created via CMD](/endpoint/d5af132c-7c17-439c-9d31-13d55340f36c/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Schtasks scheduling job on remote system](/endpoint/1297fb80-f42a-4b4a-9c8a-88c066237cf6/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Process File Path](/endpoint/9be25988-ad82-11eb-a14f-acde48001122/) | [Create or Modify System Process](/tags/#create-or-modify-system-process) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Boot or Logon Autostart Execution In Startup Folder](/endpoint/99d157cb-923f-4a00-aee9-1f385412146f/) | [Registry Run Keys / Startup Folder](/tags/#registry-run-keys-/-startup-folder), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Credentials from Password Stores Chrome Extension Access](/endpoint/2e65afe0-9a75-4487-bd87-ada9a9f1b9af/) | [Query Registry](/tags/#query-registry) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Credentials from Password Stores Chrome LocalState Access](/endpoint/3b1d09a8-a26f-473e-a510-6c6613573657/) | [Query Registry](/tags/#query-registry) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Credentials from Password Stores Chrome Login Data Access](/endpoint/0d32ba37-80fc-4429-809c-0ba15801aeaf/) | [Query Registry](/tags/#query-registry) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows DisableAntiSpyware Registry](/endpoint/23150a40-9301-4195-b802-5bb4f43067fb/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Event For Service Disabled](/endpoint/9c2620a8-94a1-11ec-b40c-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Modify Registry Auto Minor Updates](/endpoint/be498b9f-d804-4bbf-9fc0-d5448466b313/) | [Modify Registry](/tags/#modify-registry) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Modify Registry Auto Update Notif](/endpoint/4d1409df-40c7-4b11-aec4-bd0e709dfc12/) | [Modify Registry](/tags/#modify-registry) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Modify Registry Disable WinDefender Notifications](/endpoint/8e207707-ad40-4eb3-b865-3a52aec91f26/) | [Modify Registry](/tags/#modify-registry) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Modify Registry Do Not Connect To Win Update](/endpoint/e09c598e-8dd0-4e73-b740-4b96b689199e/) | [Modify Registry](/tags/#modify-registry) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Modify Registry No Auto Reboot With Logon User](/endpoint/6a12fa9f-580d-4627-8c7f-313e359bdc6a/) | [Modify Registry](/tags/#modify-registry) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Modify Registry No Auto Update](/endpoint/fbd4f333-17bb-4eab-89cb-860fa2e0600e/) | [Modify Registry](/tags/#modify-registry) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Modify Registry Tamper Protection](/endpoint/12094335-88fc-4c3a-b55f-e62dd8c93c23/) | [Modify Registry](/tags/#modify-registry) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Modify Registry USeWuServer](/endpoint/c427bafb-0b2c-4b18-ad85-c03c6fed9e75/) | [Modify Registry](/tags/#modify-registry) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Modify Registry UpdateServiceUrlAlternate](/endpoint/ca4e94fb-7969-4d63-8630-3625809a1f70/) | [Modify Registry](/tags/#modify-registry) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Modify Registry WuServer](/endpoint/a02ad386-e26d-44ce-aa97-6a46cee31439/) | [Modify Registry](/tags/#modify-registry) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Modify Registry wuStatusServer](/endpoint/073e69d0-68b2-4142-aa90-a7ee6f590676/) | [Modify Registry](/tags/#modify-registry) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Query Registry Browser List Application](/endpoint/45ebd21c-f4bf-4ced-bd49-d25b6526cebb/) | [Query Registry](/tags/#query-registry) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Query Registry UnInstall Program List](/endpoint/535fd4fc-7151-4062-9d7e-e896bea77bf6/) | [Query Registry](/tags/#query-registry) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Scheduled Task with Highest Privileges](/endpoint/2f15e1a4-0fc2-49dd-919e-cbbe60699218/) | [Scheduled Task/Job](/tags/#scheduled-task/job), [Scheduled Task](/tags/#scheduled-task) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Service Stop Win Updates](/endpoint/0dc25c24-6fcf-456f-b08b-dd55a183e4de/) | [Service Stop](/tags/#service-stop) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://malpedia.caad.fkie.fraunhofer.de/details/win.redline_stealer](https://malpedia.caad.fkie.fraunhofer.de/details/win.redline_stealer)
* [https://blogs.blackberry.com/en/2021/10/threat-thursday-redline-infostealer-update](https://blogs.blackberry.com/en/2021/10/threat-thursday-redline-infostealer-update)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/redline_stealer.yml) \| *version*: **1**