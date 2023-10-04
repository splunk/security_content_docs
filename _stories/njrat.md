---
title: "NjRAT"
last_modified_at: 2023-09-07
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

NjRat is a notorious remote access trojan (RAT) predominantly wielded by malicious operators to infiltrate and wield remote control over compromised systems. This analytical story harnesses targeted search methodologies to uncover and investigate activities that could be indicative of NjRAT's presence. These activities include tracking file write operations for dropped files, scrutinizing registry modifications aimed at establishing persistence mechanisms, monitoring suspicious processes, self-deletion behaviors, browser credential parsing, firewall configuration alterations, spread itself via removable drive and an array of other potentially malicious actions.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2023-09-07
- **Author**: Teoderick Contreras, Splunk
- **ID**: f6d52454-6cf3-4759-9627-5868a3e2b2b1

#### Narrative

NjRat is also known as Bladabindi malware that was first discovered in the wild in 2012. Since then this malware remain active and uses different campaign to spred its malware. While its primary infection vectors are phishing attacks and drive-by downloads, it also has "worm" capability to spread itself via infected removable drives. This RAT has various of capabilities including keylogging, webcam access, browser credential parsing, file upload and downloads, file and process list, service list, shell command execution, registry modification, screen capture, view the desktop of the infected computer and many more. NjRat does not target any industry in particular, but attacking a wide variety of individuals and organizations to gather sensitive information.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Allow Inbound Traffic By Firewall Rule Registry](/endpoint/0a46537c-be02-11eb-92ca-acde48001122/) | [Remote Desktop Protocol](/tags/#remote-desktop-protocol), [Remote Services](/tags/#remote-services) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Allow Network Discovery In Firewall](/endpoint/ccd6a38c-d40b-11eb-85a5-acde48001122/) | [Disable or Modify Cloud Firewall](/tags/#disable-or-modify-cloud-firewall), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [CMD Carry Out String Command Parameter](/endpoint/54a6ed00-3256-11ec-b031-acde48001122/) | [Windows Command Shell](/tags/#windows-command-shell), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disable Registry Tool](/endpoint/cd2cf33c-9201-11eb-a10a-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses), [Modify Registry](/tags/#modify-registry) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disabling CMD Application](/endpoint/ff86077c-9212-11eb-a1e6-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses), [Modify Registry](/tags/#modify-registry) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disabling SystemRestore In Registry](/endpoint/f4f837e2-91fb-11eb-8bf6-acde48001122/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disabling Task Manager](/endpoint/dac279bc-9202-11eb-b7fb-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Excessive Usage Of Taskkill](/endpoint/fe5bca48-accb-11eb-a67c-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Executables Or Script Creation In Suspicious Path](/endpoint/a7e3f0f0-ae42-11eb-b245-acde48001122/) | [Masquerading](/tags/#masquerading) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Firewall Allowed Program Enable](/endpoint/9a8f63a8-43ac-11ec-904c-acde48001122/) | [Disable or Modify System Firewall](/tags/#disable-or-modify-system-firewall), [Impair Defenses](/tags/#impair-defenses) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Non Chrome Process Accessing Chrome Default Dir](/endpoint/81263de4-160a-11ec-944f-acde48001122/) | [Credentials from Password Stores](/tags/#credentials-from-password-stores), [Credentials from Web Browsers](/tags/#credentials-from-web-browsers) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Non Firefox Process Access Firefox Profile Dir](/endpoint/e6fc13b0-1609-11ec-b533-acde48001122/) | [Credentials from Password Stores](/tags/#credentials-from-password-stores), [Credentials from Web Browsers](/tags/#credentials-from-web-browsers) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Powershell Fileless Script Contains Base64 Encoded Content](/endpoint/8acbc04c-c882-11eb-b060-acde48001122/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [Obfuscated Files or Information](/tags/#obfuscated-files-or-information), [PowerShell](/tags/#powershell) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Registry Keys Used For Persistence](/endpoint/f5f6af30-7aa7-4295-bfe9-07fe87c01a4b/) | [Registry Run Keys / Startup Folder](/tags/#registry-run-keys-/-startup-folder), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Scheduled Task Deleted Or Created via CMD](/endpoint/d5af132c-7c17-439c-9d31-13d55340f36c/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Abused Web Services](/endpoint/01f0aef4-8591-4daa-a53d-0ed49823b681/) | [Web Service](/tags/#web-service) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Admin Permission Discovery](/endpoint/e08620cb-9488-4052-832d-97bcc0afd414/) | [Local Groups](/tags/#local-groups) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Boot or Logon Autostart Execution In Startup Folder](/endpoint/99d157cb-923f-4a00-aee9-1f385412146f/) | [Registry Run Keys / Startup Folder](/tags/#registry-run-keys-/-startup-folder), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Credentials from Password Stores Chrome LocalState Access](/endpoint/3b1d09a8-a26f-473e-a510-6c6613573657/) | [Query Registry](/tags/#query-registry) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Credentials from Password Stores Chrome Login Data Access](/endpoint/0d32ba37-80fc-4429-809c-0ba15801aeaf/) | [Query Registry](/tags/#query-registry) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Delete or Modify System Firewall](/endpoint/b188d11a-eba7-419d-b8b6-cc265b4f2c4f/) | [Impair Defenses](/tags/#impair-defenses), [Disable or Modify System Firewall](/tags/#disable-or-modify-system-firewall) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Disable or Modify Tools Via Taskkill](/endpoint/a43ae66f-c410-4b3d-8741-9ce1ad17ddb0/) | [Impair Defenses](/tags/#impair-defenses), [Disable or Modify Tools](/tags/#disable-or-modify-tools) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Executable in Loaded Modules](/endpoint/3e27af56-fcf0-4113-988d-24969b062be7/) | [Shared Modules](/tags/#shared-modules) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Modify Registry With MD5 Reg Key Name](/endpoint/4662c6b1-0754-455e-b9ff-3ee730af3ba8/) | [Modify Registry](/tags/#modify-registry) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Njrat Fileless Storage via Registry](/endpoint/a5fffbbd-271f-4980-94ed-4fbf17f0af1c/) | [Fileless Storage](/tags/#fileless-storage), [Obfuscated Files or Information](/tags/#obfuscated-files-or-information) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Raw Access To Disk Volume Partition](/endpoint/a85aa37e-9647-11ec-90c5-acde48001122/) | [Disk Structure Wipe](/tags/#disk-structure-wipe), [Disk Wipe](/tags/#disk-wipe) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Raw Access To Master Boot Record Drive](/endpoint/7b83f666-900c-11ec-a2d9-acde48001122/) | [Disk Structure Wipe](/tags/#disk-structure-wipe), [Disk Wipe](/tags/#disk-wipe) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Replication Through Removable Media](/endpoint/60df805d-4605-41c8-bbba-57baa6a4eb97/) | [Replication Through Removable Media](/tags/#replication-through-removable-media) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows System LogOff Commandline](/endpoint/74a8133f-93e7-4b71-9bd3-13a66124fd57/) | [System Shutdown/Reboot](/tags/#system-shutdown/reboot) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows System Reboot CommandLine](/endpoint/97fc2b60-c8eb-4711-93f7-d26fade3686f/) | [System Shutdown/Reboot](/tags/#system-shutdown/reboot) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows System Shutdown CommandLine](/endpoint/4fee57b8-d825-4bf3-9ea8-bf405cdb614c/) | [System Shutdown/Reboot](/tags/#system-shutdown/reboot) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Time Based Evasion](/endpoint/34502357-deb1-499a-8261-ffe144abf561/) | [Virtualization/Sandbox Evasion](/tags/#virtualization/sandbox-evasion), [Time Based Evasion](/tags/#time-based-evasion) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Unsigned DLL Side-Loading](/endpoint/5a83ce44-8e0f-4786-a775-8249a525c879/) | [DLL Side-Loading](/tags/#dll-side-loading) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows User Execution Malicious URL Shortcut File](/endpoint/5c7ee6ad-baf4-44fb-b2f0-0cfeddf82dbc/) | [Malicious File](/tags/#malicious-file), [User Execution](/tags/#user-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Wscript Or Cscript Suspicious Child Process](/endpoint/1f35e1da-267b-11ec-90a9-acde48001122/) | [Process Injection](/tags/#process-injection), [Create or Modify System Process](/tags/#create-or-modify-system-process), [Parent PID Spoofing](/tags/#parent-pid-spoofing), [Access Token Manipulation](/tags/#access-token-manipulation) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://www.checkpoint.com/cyber-hub/threat-prevention/what-is-malware/what-is-njrat-malware/#:~:text=NJRat%20%E2%80%94%20also%20known%20as%20Bladabindi,malware%20variant%20in%20March%202023.](https://www.checkpoint.com/cyber-hub/threat-prevention/what-is-malware/what-is-njrat-malware/#:~:text=NJRat%20%E2%80%94%20also%20known%20as%20Bladabindi,malware%20variant%20in%20March%202023.)
* [https://malpedia.caad.fkie.fraunhofer.de/details/win.njrat](https://malpedia.caad.fkie.fraunhofer.de/details/win.njrat)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/njrat.yml) \| *version*: **2**