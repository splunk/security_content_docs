---
title: "BlackByte Ransomware"
last_modified_at: 2023-07-10
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Network_Traffic
  - Risk
  - Web
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Leverage searches that allow you to detect and investigate unusual activities that might relate to the BlackByte ransomware, including looking for file writes associated with BlackByte, persistence, initial access, account registry modification and more.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic), [Risk](https://docs.splunk.com/Documentation/CIM/latest/User/Risk), [Web](https://docs.splunk.com/Documentation/CIM/latest/User/Web)
- **Last Updated**: 2023-07-10
- **Author**: Teoderick Contreras, Splunk
- **ID**: b18259ac-0746-45d7-bd1f-81d65274a80b

#### Narrative

BlackByte ransomware campaigns targeting business operations, involve the use of ransomware payloads, infection chain to collect and exfiltrate data and drop payload on the targeted system. BlackByte Ransomware operates by infiltrating a system through various methods, such as malicious email attachments, exploit kits, or compromised websites. Once inside a system, it begins encrypting files using strong encryption algorithms, rendering them unusable. After completing the encryption process, BlackByte Ransomware typically leaves a ransom note that explains the situation to the victim and provides instructions on how to pay the ransom to obtain the decryption key.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Allow File And Printing Sharing In Firewall](/endpoint/ce27646e-d411-11eb-8a00-acde48001122/) | [Disable or Modify Cloud Firewall](/tags/#disable-or-modify-cloud-firewall), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Allow Network Discovery In Firewall](/endpoint/ccd6a38c-d40b-11eb-85a5-acde48001122/) | [Disable or Modify Cloud Firewall](/tags/#disable-or-modify-cloud-firewall), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Anomalous usage of 7zip](/endpoint/9364ee8e-a39a-11eb-8f1d-acde48001122/) | [Archive via Utility](/tags/#archive-via-utility), [Archive Collected Data](/tags/#archive-collected-data) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [CMD Echo Pipe - Escalation](/endpoint/eb277ba0-b96b-11eb-b00e-acde48001122/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [Windows Command Shell](/tags/#windows-command-shell), [Windows Service](/tags/#windows-service), [Create or Modify System Process](/tags/#create-or-modify-system-process) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Cobalt Strike Named Pipes](/endpoint/5876d429-0240-4709-8b93-ea8330b411b5/) | [Process Injection](/tags/#process-injection) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [DLLHost with no Command Line Arguments with Network](/endpoint/f1c07594-a141-11eb-8407-acde48001122/) | [Process Injection](/tags/#process-injection) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Exchange Web Shell](/endpoint/8c14eeee-2af1-4a4b-bda8-228da0f4862a/) | [Server Software Component](/tags/#server-software-component), [Web Shell](/tags/#web-shell), [Exploit Public-Facing Application](/tags/#exploit-public-facing-application), [External Remote Services](/tags/#external-remote-services) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect PsExec With accepteula Flag](/endpoint/27c3a83d-cada-47c6-9042-67baf19d2574/) | [Remote Services](/tags/#remote-services), [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Regsvr32 Application Control Bypass](/endpoint/070e9b80-6252-11eb-ae93-0242ac130002/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Regsvr32](/tags/#regsvr32) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Renamed PSExec](/endpoint/683e6196-b8e8-11eb-9a79-acde48001122/) | [System Services](/tags/#system-services), [Service Execution](/tags/#service-execution) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Webshell Exploit Behavior](/endpoint/22597426-6dbd-49bd-bcdc-4ec19857192f/) | [Server Software Component](/tags/#server-software-component), [Web Shell](/tags/#web-shell) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disabling Firewall with Netsh](/endpoint/6860a62c-9203-11eb-9e05-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Excessive File Deletion In WinDefender Folder](/endpoint/b5baa09a-7a05-11ec-8da4-acde48001122/) | [Data Destruction](/tags/#data-destruction) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Excessive Service Stop Attempt](/endpoint/ae8d3f4a-acd7-11eb-8846-acde48001122/) | [Service Stop](/tags/#service-stop) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Exchange PowerShell Abuse via SSRF](/endpoint/29228ab4-0762-11ec-94aa-acde48001122/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application), [External Remote Services](/tags/#external-remote-services) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Exchange PowerShell Module Usage](/endpoint/2d10095e-05ae-11ec-8fdf-acde48001122/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Executables Or Script Creation In Suspicious Path](/endpoint/a7e3f0f0-ae42-11eb-b245-acde48001122/) | [Masquerading](/tags/#masquerading) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Firewall Allowed Program Enable](/endpoint/9a8f63a8-43ac-11ec-904c-acde48001122/) | [Disable or Modify System Firewall](/tags/#disable-or-modify-system-firewall), [Impair Defenses](/tags/#impair-defenses) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GPUpdate with no Command Line Arguments with Network](/endpoint/2c853856-a140-11eb-a5b5-acde48001122/) | [Process Injection](/tags/#process-injection) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [High Process Termination Frequency](/endpoint/17cd75b2-8666-11eb-9ab4-acde48001122/) | [Data Encrypted for Impact](/tags/#data-encrypted-for-impact) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [MS Exchange Mailbox Replication service writing Active Server Pages](/endpoint/985f322c-57a5-11ec-b9ac-acde48001122/) | [Server Software Component](/tags/#server-software-component), [Web Shell](/tags/#web-shell), [Exploit Public-Facing Application](/tags/#exploit-public-facing-application), [External Remote Services](/tags/#external-remote-services) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Ping Sleep Batch Command](/endpoint/ce058d6c-79f2-11ec-b476-acde48001122/) | [Virtualization/Sandbox Evasion](/tags/#virtualization/sandbox-evasion), [Time Based Evasion](/tags/#time-based-evasion) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [ProxyShell ProxyNotShell Behavior Detected](/web/c32fab32-6aaf-492d-bfaf-acbed8e50cdf/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application), [External Remote Services](/tags/#external-remote-services) | [Correlation](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Registry Keys Used For Persistence](/endpoint/f5f6af30-7aa7-4295-bfe9-07fe87c01a4b/) | [Registry Run Keys / Startup Folder](/tags/#registry-run-keys-/-startup-folder), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Resize ShadowStorage volume](/endpoint/bc760ca6-8336-11eb-bcbb-acde48001122/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Rundll32 with no Command Line Arguments with Network](/endpoint/35307032-a12d-11eb-835f-acde48001122/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Rundll32](/tags/#rundll32) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [SearchProtocolHost with no Command Line with Network](/endpoint/b690df8c-a145-11eb-a38b-acde48001122/) | [Process Injection](/tags/#process-injection) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Services Escalate Exe](/endpoint/c448488c-b7ec-11eb-8253-acde48001122/) | [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious DLLHost no Command Line Arguments](/endpoint/ff61e98c-0337-4593-a78f-72a676c56f26/) | [Process Injection](/tags/#process-injection) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Driver Loaded Path](/endpoint/f880acd4-a8f1-11eb-a53b-acde48001122/) | [Windows Service](/tags/#windows-service), [Create or Modify System Process](/tags/#create-or-modify-system-process) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious GPUpdate no Command Line Arguments](/endpoint/f308490a-473a-40ef-ae64-dd7a6eba284a/) | [Process Injection](/tags/#process-injection) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious MSBuild Rename](/endpoint/4006adac-5937-11eb-ae93-0242ac130002/) | [Masquerading](/tags/#masquerading), [Trusted Developer Utilities Proxy Execution](/tags/#trusted-developer-utilities-proxy-execution), [Rename System Utilities](/tags/#rename-system-utilities), [MSBuild](/tags/#msbuild) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Process File Path](/endpoint/9be25988-ad82-11eb-a14f-acde48001122/) | [Create or Modify System Process](/tags/#create-or-modify-system-process) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Rundll32 StartW](/endpoint/9319dda5-73f2-4d43-a85a-67ce961bddb7/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Rundll32](/tags/#rundll32) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Rundll32 no Command Line Arguments](/endpoint/e451bd16-e4c5-4109-8eb1-c4c6ecf048b4/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Rundll32](/tags/#rundll32) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious SearchProtocolHost no Command Line Arguments](/endpoint/f52d2db8-31f9-4aa7-a176-25779effe55c/) | [Process Injection](/tags/#process-injection) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious microsoft workflow compiler rename](/endpoint/f0db4464-55d9-11eb-ae93-0242ac130002/) | [Masquerading](/tags/#masquerading), [Trusted Developer Utilities Proxy Execution](/tags/#trusted-developer-utilities-proxy-execution), [Rename System Utilities](/tags/#rename-system-utilities) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious msbuild path](/endpoint/f5198224-551c-11eb-ae93-0242ac130002/) | [Masquerading](/tags/#masquerading), [Trusted Developer Utilities Proxy Execution](/tags/#trusted-developer-utilities-proxy-execution), [Rename System Utilities](/tags/#rename-system-utilities), [MSBuild](/tags/#msbuild) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [W3WP Spawning Shell](/endpoint/0f03423c-7c6a-11eb-bc47-acde48001122/) | [Server Software Component](/tags/#server-software-component), [Web Shell](/tags/#web-shell) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Driver Load Non-Standard Path](/endpoint/9216ef3d-066a-4958-8f27-c84589465e62/) | [Rootkit](/tags/#rootkit), [Exploitation for Privilege Escalation](/tags/#exploitation-for-privilege-escalation) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Drivers Loaded by Signature](/endpoint/d2d4af6a-6c2b-4d79-80c5-fc2cf12a2f68/) | [Rootkit](/tags/#rootkit), [Exploitation for Privilege Escalation](/tags/#exploitation-for-privilege-escalation) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Exchange Autodiscover SSRF Abuse](/web/d436f9e7-0ee7-4a47-864b-6dea2c4e2752/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application), [External Remote Services](/tags/#external-remote-services) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows MSExchange Management Mailbox Cmdlet Usage](/endpoint/396de86f-25e7-4b0e-be09-a330be35249d/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Modify Registry EnableLinkedConnections](/endpoint/93048164-3358-4af0-8680-aa5f38440516/) | [Modify Registry](/tags/#modify-registry) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Modify Registry LongPathsEnabled](/endpoint/36f9626c-4272-4808-aadd-267acce681c0/) | [Modify Registry](/tags/#modify-registry) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows RDP Connection Successful](/endpoint/ceaed840-56b3-4a70-b8e1-d762b1c5c08c/) | [RDP Hijacking](/tags/#rdp-hijacking) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Raw Access To Disk Volume Partition](/endpoint/a85aa37e-9647-11ec-90c5-acde48001122/) | [Disk Structure Wipe](/tags/#disk-structure-wipe), [Disk Wipe](/tags/#disk-wipe) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Raw Access To Master Boot Record Drive](/endpoint/7b83f666-900c-11ec-a2d9-acde48001122/) | [Disk Structure Wipe](/tags/#disk-structure-wipe), [Disk Wipe](/tags/#disk-wipe) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Vulnerable Driver Loaded](/endpoint/a2b1f1ef-221f-4187-b2a4-d4b08ec745f4/) | [Windows Service](/tags/#windows-service) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://www.microsoft.com/en-us/security/blog/2023/07/06/the-five-day-job-a-blackbyte-ransomware-intrusion-case-study/](https://www.microsoft.com/en-us/security/blog/2023/07/06/the-five-day-job-a-blackbyte-ransomware-intrusion-case-study/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/blackbyte_ransomware.yml) \| *version*: **1**