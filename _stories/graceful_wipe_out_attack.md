---
title: "Graceful Wipe Out Attack"
last_modified_at: 2023-06-15
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

This analytic story contains detections that allow security analysts to detect and investigate unusual activities that might relate to the destructive attack or campaign found by "THE DFIR Report" that uses Truebot, FlawedGrace and MBR killer malware. This analytic story looks for suspicious dropped files, cobalt strike execution, im-packet execution, registry modification, scripts, persistence, lateral movement, impact, exfiltration and recon.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic)
- **Last Updated**: 2023-06-15
- **Author**: Teoderick Contreras, Splunk
- **ID**: 83b15b3c-6bda-45aa-a3b6-b05c52443f44

#### Narrative

Graceful Wipe Out Attack is a destructive malware campaign found by "The DFIR Report" targeting multiple organizations to collect, exfiltrate and wipe the data of targeted networks. This malicious payload corrupts or wipes Master Boot Records by using an NSIS script after the exfiltration of sensitive information from the targeted host or system.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Anomalous usage of 7zip](/endpoint/9364ee8e-a39a-11eb-8f1d-acde48001122/) | [Archive via Utility](/tags/#archive-via-utility), [Archive Collected Data](/tags/#archive-collected-data) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Attempt To Stop Security Service](/endpoint/c8e349c6-b97c-486e-8949-bd7bcd1f3910/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [CMD Echo Pipe - Escalation](/endpoint/eb277ba0-b96b-11eb-b00e-acde48001122/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [Windows Command Shell](/tags/#windows-command-shell), [Windows Service](/tags/#windows-service), [Create or Modify System Process](/tags/#create-or-modify-system-process) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Cobalt Strike Named Pipes](/endpoint/5876d429-0240-4709-8b93-ea8330b411b5/) | [Process Injection](/tags/#process-injection) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [DLLHost with no Command Line Arguments with Network](/endpoint/f1c07594-a141-11eb-8407-acde48001122/) | [Process Injection](/tags/#process-injection) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Deleting Of Net Users](/endpoint/1c8c6f66-acce-11eb-aafb-acde48001122/) | [Account Access Removal](/tags/#account-access-removal) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Regsvr32 Application Control Bypass](/endpoint/070e9b80-6252-11eb-ae93-0242ac130002/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Regsvr32](/tags/#regsvr32) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Domain Account Discovery With Net App](/endpoint/98f6a534-04c2-11ec-96b2-acde48001122/) | [Domain Account](/tags/#domain-account), [Account Discovery](/tags/#account-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Domain Group Discovery With Net](/endpoint/f2f14ac7-fa81-471a-80d5-7eb65c3c7349/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Domain Groups](/tags/#domain-groups) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Excessive Usage Of Net App](/endpoint/45e52536-ae42-11eb-b5c6-acde48001122/) | [Account Access Removal](/tags/#account-access-removal) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Executable File Written in Administrative SMB Share](/endpoint/f63c34fe-a435-11eb-935a-acde48001122/) | [Remote Services](/tags/#remote-services), [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Executables Or Script Creation In Suspicious Path](/endpoint/a7e3f0f0-ae42-11eb-b245-acde48001122/) | [Masquerading](/tags/#masquerading) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GPUpdate with no Command Line Arguments with Network](/endpoint/2c853856-a140-11eb-a5b5-acde48001122/) | [Process Injection](/tags/#process-injection) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Impacket Lateral Movement Commandline Parameters](/endpoint/8ce07472-496f-11ec-ab3b-3e22fbd008af/) | [Remote Services](/tags/#remote-services), [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares), [Distributed Component Object Model](/tags/#distributed-component-object-model), [Windows Management Instrumentation](/tags/#windows-management-instrumentation), [Windows Service](/tags/#windows-service) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Impacket Lateral Movement WMIExec Commandline Parameters](/endpoint/d6e464e4-5c6a-474e-82d2-aed616a3a492/) | [Remote Services](/tags/#remote-services), [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares), [Distributed Component Object Model](/tags/#distributed-component-object-model), [Windows Management Instrumentation](/tags/#windows-management-instrumentation), [Windows Service](/tags/#windows-service) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Impacket Lateral Movement smbexec CommandLine Parameters](/endpoint/bb3c1bac-6bdf-4aa0-8dc9-068b8b712a76/) | [Remote Services](/tags/#remote-services), [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares), [Distributed Component Object Model](/tags/#distributed-component-object-model), [Windows Management Instrumentation](/tags/#windows-management-instrumentation), [Windows Service](/tags/#windows-service) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Net Localgroup Discovery](/endpoint/54f5201e-155b-11ec-a6e2-acde48001122/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Local Groups](/tags/#local-groups) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Remote WMI Command Attempt](/endpoint/272df6de-61f1-4784-877c-1fbc3e2d0838/) | [Windows Management Instrumentation](/tags/#windows-management-instrumentation) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Rundll32 with no Command Line Arguments with Network](/endpoint/35307032-a12d-11eb-835f-acde48001122/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Rundll32](/tags/#rundll32) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [SAM Database File Access Attempt](/endpoint/57551656-ebdb-11eb-afdf-acde48001122/) | [Security Account Manager](/tags/#security-account-manager), [OS Credential Dumping](/tags/#os-credential-dumping) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [SearchProtocolHost with no Command Line with Network](/endpoint/b690df8c-a145-11eb-a38b-acde48001122/) | [Process Injection](/tags/#process-injection) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [SecretDumps Offline NTDS Dumping Tool](/endpoint/5672819c-be09-11eb-bbfb-acde48001122/) | [NTDS](/tags/#ntds), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Services Escalate Exe](/endpoint/c448488c-b7ec-11eb-8253-acde48001122/) | [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious DLLHost no Command Line Arguments](/endpoint/ff61e98c-0337-4593-a78f-72a676c56f26/) | [Process Injection](/tags/#process-injection) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious GPUpdate no Command Line Arguments](/endpoint/f308490a-473a-40ef-ae64-dd7a6eba284a/) | [Process Injection](/tags/#process-injection) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious MSBuild Rename](/endpoint/4006adac-5937-11eb-ae93-0242ac130002/) | [Masquerading](/tags/#masquerading), [Trusted Developer Utilities Proxy Execution](/tags/#trusted-developer-utilities-proxy-execution), [Rename System Utilities](/tags/#rename-system-utilities), [MSBuild](/tags/#msbuild) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Process File Path](/endpoint/9be25988-ad82-11eb-a14f-acde48001122/) | [Create or Modify System Process](/tags/#create-or-modify-system-process) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Rundll32 StartW](/endpoint/9319dda5-73f2-4d43-a85a-67ce961bddb7/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Rundll32](/tags/#rundll32) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Rundll32 no Command Line Arguments](/endpoint/e451bd16-e4c5-4109-8eb1-c4c6ecf048b4/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Rundll32](/tags/#rundll32) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious SearchProtocolHost no Command Line Arguments](/endpoint/f52d2db8-31f9-4aa7-a176-25779effe55c/) | [Process Injection](/tags/#process-injection) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious microsoft workflow compiler rename](/endpoint/f0db4464-55d9-11eb-ae93-0242ac130002/) | [Masquerading](/tags/#masquerading), [Trusted Developer Utilities Proxy Execution](/tags/#trusted-developer-utilities-proxy-execution), [Rename System Utilities](/tags/#rename-system-utilities) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious msbuild path](/endpoint/f5198224-551c-11eb-ae93-0242ac130002/) | [Masquerading](/tags/#masquerading), [Trusted Developer Utilities Proxy Execution](/tags/#trusted-developer-utilities-proxy-execution), [Rename System Utilities](/tags/#rename-system-utilities), [MSBuild](/tags/#msbuild) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows AdFind Exe](/endpoint/bd3b0187-189b-46c0-be45-f52da2bae67f/) | [Remote System Discovery](/tags/#remote-system-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Process Injection Remote Thread](/endpoint/8a618ade-ca8f-4d04-b972-2d526ba59924/) | [Process Injection](/tags/#process-injection), [Portable Executable Injection](/tags/#portable-executable-injection) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Raw Access To Disk Volume Partition](/endpoint/a85aa37e-9647-11ec-90c5-acde48001122/) | [Disk Structure Wipe](/tags/#disk-structure-wipe), [Disk Wipe](/tags/#disk-wipe) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Raw Access To Master Boot Record Drive](/endpoint/7b83f666-900c-11ec-a2d9-acde48001122/) | [Disk Structure Wipe](/tags/#disk-structure-wipe), [Disk Wipe](/tags/#disk-wipe) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Service Stop By Deletion](/endpoint/196ff536-58d9-4d1b-9686-b176b04e430b/) | [Service Stop](/tags/#service-stop) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Service Stop Via Net  and SC Application](/endpoint/827af04b-0d08-479b-9b84-b7d4644e4b80/) | [Service Stop](/tags/#service-stop) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://thedfirreport.com/2023/06/12/a-truly-graceful-wipe-out/](https://thedfirreport.com/2023/06/12/a-truly-graceful-wipe-out/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/graceful_wipe_out_attack.yml) \| *version*: **1**