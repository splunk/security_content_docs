---
title: "Windows Persistence Techniques"
last_modified_at: 2018-05-31
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

Monitor for activities and techniques associated with maintaining persistence on a Windows system--a sign that an adversary may have compromised your environment.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2018-05-31
- **Author**: Bhavin Patel, Splunk
- **ID**: 30874d4f-20a1-488f-85ec-5d52ef74e3f9

#### Narrative

Maintaining persistence is one of the first steps taken by attackers after the initial compromise. Attackers leverage various custom and built-in tools to ensure survivability and persistent access within a compromised enterprise. This Analytic Story provides searches to help you identify various behaviors used by attackers to maintain persistent access to a Windows environment.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Active Setup Registry Autostart](/endpoint/f64579c0-203f-11ec-abcc-acde48001122/) | [Active Setup](/tags/#active-setup), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Certutil exe certificate extraction](/endpoint/337a46be-600f-11eb-ae93-0242ac130002/) |  | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Change Default File Association](/endpoint/462d17d8-1f71-11ec-ad07-acde48001122/) | [Change Default File Association](/tags/#change-default-file-association), [Event Triggered Execution](/tags/#event-triggered-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Path Interception By Creation Of program exe](/endpoint/cbef820c-e1ff-407f-887f-0a9240a2d477/) | [Path Interception by Unquoted Path](/tags/#path-interception-by-unquoted-path), [Hijack Execution Flow](/tags/#hijack-execution-flow) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [ETW Registry Disabled](/endpoint/8ed523ac-276b-11ec-ac39-acde48001122/) | [Indicator Blocking](/tags/#indicator-blocking), [Trusted Developer Utilities Proxy Execution](/tags/#trusted-developer-utilities-proxy-execution), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Hiding Files And Directories With Attrib exe](/endpoint/6e5a3ae4-90a3-462d-9aa6-0119f638c0f1/) | [File and Directory Permissions Modification](/tags/#file-and-directory-permissions-modification), [Windows File and Directory Permissions Modification](/tags/#windows-file-and-directory-permissions-modification) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Hiding Files And Directories With Attrib exe](/endpoint/028e4406-6176-11ec-aec2-acde48001122/) | [Windows File and Directory Permissions Modification](/tags/#windows-file-and-directory-permissions-modification), [File and Directory Permissions Modification](/tags/#file-and-directory-permissions-modification) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Logon Script Event Trigger Execution](/endpoint/4c38c264-1f74-11ec-b5fa-acde48001122/) | [Boot or Logon Initialization Scripts](/tags/#boot-or-logon-initialization-scripts), [Logon Script (Windows)](/tags/#logon-script-(windows)) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Monitor Registry Keys for Print Monitors](/endpoint/f5f6af30-7ba7-4295-bfe9-07de87c01bbc/) | [Port Monitors](/tags/#port-monitors), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Print Processor Registry Autostart](/endpoint/1f5b68aa-2037-11ec-898e-acde48001122/) | [Print Processors](/tags/#print-processors), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Reg exe Manipulating Windows Services Registry Keys](/endpoint/8470d755-0c13-45b3-bd63-387a373c10cf/) | [Services Registry Permissions Weakness](/tags/#services-registry-permissions-weakness), [Hijack Execution Flow](/tags/#hijack-execution-flow) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Reg exe used to hide files directories via registry keys](/deprecated/61a7d1e6-f5d4-41d9-a9be-39a1ffe69459/) | [Hidden Files and Directories](/tags/#hidden-files-and-directories) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Registry Keys Used For Persistence](/endpoint/f5f6af30-7aa7-4295-bfe9-07fe87c01a4b/) | [Registry Run Keys / Startup Folder](/tags/#registry-run-keys-/-startup-folder), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Registry Keys for Creating SHIM Databases](/endpoint/f5f6af30-7aa7-4295-bfe9-07fe87c01bbb/) | [Application Shimming](/tags/#application-shimming), [Event Triggered Execution](/tags/#event-triggered-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Remote Registry Key modifications](/deprecated/c9f4b923-f8af-4155-b697-1354f5dcbc5e/) |  | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Sc exe Manipulating Windows Services](/endpoint/f0c693d8-2a89-4ce7-80b4-98fea4c3ea6d/) | [Windows Service](/tags/#windows-service), [Create or Modify System Process](/tags/#create-or-modify-system-process) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Schedule Task with HTTP Command Arguments](/endpoint/523c2684-a101-11eb-916b-acde48001122/) | [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Schedule Task with Rundll32 Command Trigger](/endpoint/75b00fd8-a0ff-11eb-8b31-acde48001122/) | [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Scheduled Task Deleted Or Created via CMD](/endpoint/d5af132c-7c17-439c-9d31-13d55340f36c/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Schtasks used for forcing a reboot](/endpoint/1297fb80-f42a-4b4a-9c8a-88c066437cf6/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Screensaver Event Trigger Execution](/endpoint/58cea3ec-1f6d-11ec-8560-acde48001122/) | [Event Triggered Execution](/tags/#event-triggered-execution), [Screensaver](/tags/#screensaver) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Shim Database File Creation](/endpoint/6e4c4588-ba2f-42fa-97e6-9f6f548eaa33/) | [Application Shimming](/tags/#application-shimming), [Event Triggered Execution](/tags/#event-triggered-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Shim Database Installation With Suspicious Parameters](/endpoint/404620de-46d8-48b6-90cc-8a8d7b0876a3/) | [Application Shimming](/tags/#application-shimming), [Event Triggered Execution](/tags/#event-triggered-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Scheduled Task from Public Directory](/endpoint/7feb7972-7ac3-11eb-bac8-acde48001122/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Time Provider Persistence Registry](/endpoint/5ba382c4-2105-11ec-8d8f-acde48001122/) | [Time Providers](/tags/#time-providers), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [WinEvent Scheduled Task Created Within Public Path](/endpoint/5d9c6eee-988c-11eb-8253-acde48001122/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [WinEvent Scheduled Task Created to Spawn Shell](/endpoint/203ef0ea-9bd8-11eb-8201-acde48001122/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [WinEvent Windows Task Scheduler Event Action Started](/endpoint/b3632472-310b-11ec-9aab-acde48001122/) | [Scheduled Task](/tags/#scheduled-task) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows AD DSRM Account Changes](/endpoint/08cb291e-ea77-48e8-a95a-0799319bf056/) | [Account Manipulation](/tags/#account-manipulation) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows AD Same Domain SID History Addition](/endpoint/5fde0b7c-df7a-40b1-9b3a-294c00f0289d/) | [SID-History Injection](/tags/#sid-history-injection), [Access Token Manipulation](/tags/#access-token-manipulation) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Event Triggered Image File Execution Options Injection](/endpoint/f7abfab9-12ea-44e8-8745-475f9ca6e0a4/) | [Image File Execution Options Injection](/tags/#image-file-execution-options-injection) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Mshta Execution In Registry](/endpoint/e13ceade-b673-4d34-adc4-4d9c01729753/) | [Mshta](/tags/#mshta) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Registry Delete Task SD](/endpoint/ffeb7893-ff06-446f-815b-33ca73224e92/) | [Scheduled Task](/tags/#scheduled-task), [Impair Defenses](/tags/#impair-defenses) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Scheduled Task Service Spawned Shell](/endpoint/d8120352-3b62-4e3c-8cb6-7b47584dd5e8/) | [Scheduled Task](/tags/#scheduled-task), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Schtasks Create Run As System](/endpoint/41a0e58e-884c-11ec-9976-acde48001122/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Service Creation Using Registry Entry](/endpoint/25212358-948e-11ec-ad47-acde48001122/) | [Services Registry Permissions Weakness](/tags/#services-registry-permissions-weakness) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [http://www.fuzzysecurity.com/tutorials/19.html](http://www.fuzzysecurity.com/tutorials/19.html)
* [https://www.fireeye.com/blog/threat-research/2010/07/malware-persistence-windows-registry.html](https://www.fireeye.com/blog/threat-research/2010/07/malware-persistence-windows-registry.html)
* [http://resources.infosecinstitute.com/common-malware-persistence-mechanisms/](http://resources.infosecinstitute.com/common-malware-persistence-mechanisms/)
* [https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html](https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html)
* [https://www.youtube.com/watch?v=dq2Hv7J9fvk](https://www.youtube.com/watch?v=dq2Hv7J9fvk)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/windows_persistence_techniques.yml) \| *version*: **2**