---
title: "Hermetic Wiper"
last_modified_at: 2022-03-02
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Email
  - Endpoint
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

This analytic story contains detections that allow security analysts to detect and investigate unusual activities that might relate to the destructive malware targeting Ukrainian organizations also known as "Hermetic Wiper". This analytic story looks for abuse of Regsvr32, executables written in administrative SMB Share, suspicious processes, disabling of memory crash dump and more.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Email](https://docs.splunk.com/Documentation/CIM/latest/User/Email), [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-03-02
- **Author**: Teoderick Contreras, Rod Soto, Michael Haag, Splunk
- **ID**: b7511c2e-9a10-11ec-99e3-acde48001122

#### Narrative

Hermetic Wiper is destructive malware operation found by Sentinel One targeting multiple organizations in Ukraine. This malicious payload corrupts Master Boot Records, uses signed drivers and manipulates NTFS attributes for file destruction.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Active Setup Registry Autostart](/endpoint/f64579c0-203f-11ec-abcc-acde48001122/) | [Active Setup](/tags/#active-setup), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Any Powershell DownloadFile](/endpoint/1a93b7ea-7af7-11eb-adb5-acde48001122/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell), [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Any Powershell DownloadString](/endpoint/4d015ef2-7adf-11eb-95da-acde48001122/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell), [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [CMD Carry Out String Command Parameter](/endpoint/54a6ed00-3256-11ec-b031-acde48001122/) | [Windows Command Shell](/tags/#windows-command-shell), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Change Default File Association](/endpoint/462d17d8-1f71-11ec-ad07-acde48001122/) | [Change Default File Association](/tags/#change-default-file-association), [Event Triggered Execution](/tags/#event-triggered-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Child Processes of Spoolsv exe](/endpoint/aa0c4aeb-5b18-41c4-8c07-f1442d7599df/) | [Exploitation for Privilege Escalation](/tags/#exploitation-for-privilege-escalation) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Empire with PowerShell Script Block Logging](/endpoint/bc1dc6b8-c954-11eb-bade-acde48001122/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Mimikatz With PowerShell Script Block Logging](/endpoint/8148c29c-c952-11eb-9255-acde48001122/) | [OS Credential Dumping](/tags/#os-credential-dumping), [PowerShell](/tags/#powershell) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [ETW Registry Disabled](/endpoint/8ed523ac-276b-11ec-ac39-acde48001122/) | [Indicator Blocking](/tags/#indicator-blocking), [Trusted Developer Utilities Proxy Execution](/tags/#trusted-developer-utilities-proxy-execution), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Email Attachments With Lots Of Spaces](/application/56e877a6-1455-4479-ada6-0550dc1e22f8/) |  | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Executable File Written in Administrative SMB Share](/endpoint/f63c34fe-a435-11eb-935a-acde48001122/) | [Remote Services](/tags/#remote-services), [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Executables Or Script Creation In Suspicious Path](/endpoint/a7e3f0f0-ae42-11eb-b245-acde48001122/) | [Masquerading](/tags/#masquerading) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Kerberoasting spn request with RC4 encryption](/endpoint/5cc67381-44fa-4111-8a37-7a230943f027/) | [Steal or Forge Kerberos Tickets](/tags/#steal-or-forge-kerberos-tickets), [Kerberoasting](/tags/#kerberoasting) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Java Spawning Shell](/endpoint/7b09db8a-5c20-11ec-9945-acde48001122/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Logon Script Event Trigger Execution](/endpoint/4c38c264-1f74-11ec-b5fa-acde48001122/) | [Boot or Logon Initialization Scripts](/tags/#boot-or-logon-initialization-scripts), [Logon Script (Windows)](/tags/#logon-script-(windows)) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [MSI Module Loaded by Non-System Binary](/endpoint/ccb98a66-5851-11ec-b91c-acde48001122/) | [DLL Side-Loading](/tags/#dll-side-loading), [Hijack Execution Flow](/tags/#hijack-execution-flow) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Malicious PowerShell Process - Encoded Command](/endpoint/c4db14d9-7909-48b4-a054-aa14d89dbb19/) | [Obfuscated Files or Information](/tags/#obfuscated-files-or-information) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Malicious PowerShell Process With Obfuscation Techniques](/endpoint/cde75cf6-3c7a-4dd6-af01-27cdb4511fd4/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Overwriting Accessibility Binaries](/endpoint/13c2f6c3-10c5-4deb-9ba1-7c4460ebe4ae/) | [Event Triggered Execution](/tags/#event-triggered-execution), [Accessibility Features](/tags/#accessibility-features) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Possible Lateral Movement PowerShell Spawn](/endpoint/cb909b3e-512b-11ec-aa31-3e22fbd008af/) | [Remote Services](/tags/#remote-services), [Distributed Component Object Model](/tags/#distributed-component-object-model), [Windows Remote Management](/tags/#windows-remote-management), [Windows Management Instrumentation](/tags/#windows-management-instrumentation), [Scheduled Task](/tags/#scheduled-task), [Windows Service](/tags/#windows-service), [PowerShell](/tags/#powershell), [MMC](/tags/#mmc) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [PowerShell - Connect To Internet With Hidden Window](/endpoint/ee18ed37-0802-4268-9435-b3b91aaa18db/) | [PowerShell](/tags/#powershell), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [PowerShell 4104 Hunting](/endpoint/d6f2b006-0041-11ec-8885-acde48001122/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [PowerShell Domain Enumeration](/endpoint/e1866ce2-ca22-11eb-8e44-acde48001122/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [PowerShell Loading DotNET into Memory via Reflection](/endpoint/85bc3f30-ca28-11eb-bd21-acde48001122/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Powershell Enable SMB1Protocol Feature](/endpoint/afed80b2-d34b-11eb-a952-acde48001122/) | [Obfuscated Files or Information](/tags/#obfuscated-files-or-information), [Indicator Removal from Tools](/tags/#indicator-removal-from-tools) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Powershell Execute COM Object](/endpoint/65711630-f9bf-11eb-8d72-acde48001122/) | [Component Object Model Hijacking](/tags/#component-object-model-hijacking), [Event Triggered Execution](/tags/#event-triggered-execution), [PowerShell](/tags/#powershell) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Powershell Fileless Process Injection via GetProcAddress](/endpoint/a26d9db4-c883-11eb-9d75-acde48001122/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [Process Injection](/tags/#process-injection), [PowerShell](/tags/#powershell) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Powershell Fileless Script Contains Base64 Encoded Content](/endpoint/8acbc04c-c882-11eb-b060-acde48001122/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [Obfuscated Files or Information](/tags/#obfuscated-files-or-information), [PowerShell](/tags/#powershell) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Powershell Processing Stream Of Data](/endpoint/0d718b52-c9f1-11eb-bc61-acde48001122/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Powershell Using memory As Backing Store](/endpoint/c396a0c4-c9f2-11eb-b4f5-acde48001122/) | [PowerShell](/tags/#powershell), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Print Processor Registry Autostart](/endpoint/1f5b68aa-2037-11ec-898e-acde48001122/) | [Print Processors](/tags/#print-processors), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Recon AVProduct Through Pwh or WMI](/endpoint/28077620-c9f6-11eb-8785-acde48001122/) | [Gather Victim Host Information](/tags/#gather-victim-host-information) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Recon Using WMI Class](/endpoint/018c1972-ca07-11eb-9473-acde48001122/) | [Gather Victim Host Information](/tags/#gather-victim-host-information), [PowerShell](/tags/#powershell) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Registry Keys Used For Privilege Escalation](/endpoint/c9f4b923-f8af-4155-b697-1354f5bcbc5e/) | [Image File Execution Options Injection](/tags/#image-file-execution-options-injection), [Event Triggered Execution](/tags/#event-triggered-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Regsvr32 Silent and Install Param Dll Loading](/endpoint/f421c250-24e7-11ec-bc43-acde48001122/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Regsvr32](/tags/#regsvr32) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Runas Execution in CommandLine](/endpoint/4807e716-43a4-11ec-a0e7-acde48001122/) | [Access Token Manipulation](/tags/#access-token-manipulation), [Token Impersonation/Theft](/tags/#token-impersonation/theft) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Screensaver Event Trigger Execution](/endpoint/58cea3ec-1f6d-11ec-8560-acde48001122/) | [Event Triggered Execution](/tags/#event-triggered-execution), [Screensaver](/tags/#screensaver) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Set Default PowerShell Execution Policy To Unrestricted or Bypass](/endpoint/c2590137-0b08-4985-9ec5-6ae23d92f63d/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Email Attachment Extensions](/application/473bd65f-06ca-4dfe-a2b8-ba04ab4a0084/) | [Spearphishing Attachment](/tags/#spearphishing-attachment), [Phishing](/tags/#phishing) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Powershell Command-Line Arguments](/deprecated/2cdb91d2-542c-497f-b252-be495e71f38c/) | [PowerShell](/tags/#powershell) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Process File Path](/endpoint/9be25988-ad82-11eb-a14f-acde48001122/) | [Create or Modify System Process](/tags/#create-or-modify-system-process) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Time Provider Persistence Registry](/endpoint/5ba382c4-2105-11ec-8d8f-acde48001122/) | [Time Providers](/tags/#time-providers), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Uncommon Processes On Endpoint](/deprecated/29ccce64-a10c-4389-a45f-337cb29ba1f7/) | [Malicious File](/tags/#malicious-file) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Unloading AMSI via Reflection](/endpoint/a21e3484-c94d-11eb-b55b-acde48001122/) | [Impair Defenses](/tags/#impair-defenses), [PowerShell](/tags/#powershell), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [W3WP Spawning Shell](/endpoint/0f03423c-7c6a-11eb-bc47-acde48001122/) | [Server Software Component](/tags/#server-software-component), [Web Shell](/tags/#web-shell) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [WMI Recon Running Process Or Services](/endpoint/b5cd5526-cce7-11eb-b3bd-acde48001122/) | [Gather Victim Host Information](/tags/#gather-victim-host-information) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Disable Memory Crash Dump](/endpoint/59e54602-9680-11ec-a8a6-acde48001122/) | [Data Destruction](/tags/#data-destruction) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows File Without Extension In Critical Folder](/endpoint/0dbcac64-963c-11ec-bf04-acde48001122/) | [Data Destruction](/tags/#data-destruction) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Modify Show Compress Color And Info Tip Registry](/endpoint/b7548c2e-9a10-11ec-99e3-acde48001122/) | [Modify Registry](/tags/#modify-registry) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Raw Access To Disk Volume Partition](/endpoint/a85aa37e-9647-11ec-90c5-acde48001122/) | [Disk Structure Wipe](/tags/#disk-structure-wipe), [Disk Wipe](/tags/#disk-wipe) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Raw Access To Master Boot Record Drive](/endpoint/7b83f666-900c-11ec-a2d9-acde48001122/) | [Disk Structure Wipe](/tags/#disk-structure-wipe), [Disk Wipe](/tags/#disk-wipe) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://www.sentinelone.com/labs/hermetic-wiper-ukraine-under-attack/](https://www.sentinelone.com/labs/hermetic-wiper-ukraine-under-attack/)
* [https://www.cisa.gov/uscert/ncas/alerts/aa22-057a](https://www.cisa.gov/uscert/ncas/alerts/aa22-057a)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/hermetic_wiper.yml) \| *version*: **1**