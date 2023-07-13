---
title: "Windows Defense Evasion Tactics"
last_modified_at: 2018-05-31
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Change
  - Endpoint
  - Web
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Detect tactics used by malware to evade defenses on Windows endpoints. A few of these include suspicious `reg.exe` processes, files hidden with `attrib.exe` and disabling user-account control, among many others 

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Change](https://docs.splunk.com/Documentation/CIM/latest/User/Change), [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Web](https://docs.splunk.com/Documentation/CIM/latest/User/Web)
- **Last Updated**: 2018-05-31
- **Author**: David Dorsey, Splunk
- **ID**: 56e24a28-5003-4047-b2db-e8f3c4618064

#### Narrative

Defense evasion is a tactic--identified in the MITRE ATT&CK framework--that adversaries employ in a variety of ways to bypass or defeat defensive security measures. There are many techniques enumerated by the MITRE ATT&CK framework that are applicable in this context. This Analytic Story includes searches designed to identify the use of such techniques on Windows platforms.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Add or Set Windows Defender Exclusion](/endpoint/773b66fe-4dd9-11ec-8289-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [CSC Net On The Fly Compilation](/endpoint/ea73128a-43ab-11ec-9753-acde48001122/) | [Compile After Delivery](/tags/#compile-after-delivery), [Obfuscated Files or Information](/tags/#obfuscated-files-or-information) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disable Registry Tool](/endpoint/cd2cf33c-9201-11eb-a10a-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses), [Modify Registry](/tags/#modify-registry) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disable Security Logs Using MiniNt Registry](/endpoint/39ebdc68-25b9-11ec-aec7-acde48001122/) | [Modify Registry](/tags/#modify-registry) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disable Show Hidden Files](/endpoint/6f3ccfa2-91fe-11eb-8f9b-acde48001122/) | [Hidden Files and Directories](/tags/#hidden-files-and-directories), [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Hide Artifacts](/tags/#hide-artifacts), [Impair Defenses](/tags/#impair-defenses), [Modify Registry](/tags/#modify-registry) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disable UAC Remote Restriction](/endpoint/9928b732-210e-11ec-b65e-acde48001122/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disable Windows Behavior Monitoring](/endpoint/79439cae-9200-11eb-a4d3-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disable Windows SmartScreen Protection](/endpoint/664f0fd0-91ff-11eb-a56f-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disabling CMD Application](/endpoint/ff86077c-9212-11eb-a1e6-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses), [Modify Registry](/tags/#modify-registry) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disabling ControlPanel](/endpoint/6ae0148e-9215-11eb-a94a-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses), [Modify Registry](/tags/#modify-registry) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disabling Firewall with Netsh](/endpoint/6860a62c-9203-11eb-9e05-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disabling FolderOptions Windows Feature](/endpoint/83776de4-921a-11eb-868a-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disabling NoRun Windows App](/endpoint/de81bc46-9213-11eb-adc9-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses), [Modify Registry](/tags/#modify-registry) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disabling Remote User Account Control](/endpoint/bbc644bc-37df-4e1a-9c88-ec9a53e2038c/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disabling SystemRestore In Registry](/endpoint/f4f837e2-91fb-11eb-8bf6-acde48001122/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disabling Task Manager](/endpoint/dac279bc-9202-11eb-b7fb-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Eventvwr UAC Bypass](/endpoint/9cf8fe08-7ad8-11eb-9819-acde48001122/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Excessive number of service control start as disabled](/endpoint/77592bec-d5cc-11eb-9e60-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Firewall Allowed Program Enable](/endpoint/9a8f63a8-43ac-11ec-904c-acde48001122/) | [Disable or Modify System Firewall](/tags/#disable-or-modify-system-firewall), [Impair Defenses](/tags/#impair-defenses) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [FodHelper UAC Bypass](/endpoint/909f8fd8-7ac8-11eb-a1f3-acde48001122/) | [Modify Registry](/tags/#modify-registry), [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Hiding Files And Directories With Attrib exe](/endpoint/6e5a3ae4-90a3-462d-9aa6-0119f638c0f1/) | [File and Directory Permissions Modification](/tags/#file-and-directory-permissions-modification), [Windows File and Directory Permissions Modification](/tags/#windows-file-and-directory-permissions-modification) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Hiding Files And Directories With Attrib exe](/endpoint/028e4406-6176-11ec-aec2-acde48001122/) | [Windows File and Directory Permissions Modification](/tags/#windows-file-and-directory-permissions-modification), [File and Directory Permissions Modification](/tags/#file-and-directory-permissions-modification) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [NET Profiler UAC bypass](/endpoint/0252ca80-e30d-11eb-8aa3-acde48001122/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Powershell Windows Defender Exclusion Commands](/endpoint/907ac95c-4dd9-11ec-ba2c-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Reg exe used to hide files directories via registry keys](/deprecated/61a7d1e6-f5d4-41d9-a9be-39a1ffe69459/) | [Hidden Files and Directories](/tags/#hidden-files-and-directories) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Remote Registry Key modifications](/deprecated/c9f4b923-f8af-4155-b697-1354f5dcbc5e/) |  | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [SLUI RunAs Elevated](/endpoint/8d124810-b3e4-11eb-96c7-acde48001122/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [SLUI Spawning a Process](/endpoint/879c4330-b3e0-11eb-b1b1-acde48001122/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Sdclt UAC Bypass](/endpoint/d71efbf6-da63-11eb-8c6e-acde48001122/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [SilentCleanup UAC Bypass](/endpoint/56d7cfcc-da63-11eb-92d4-acde48001122/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Reg exe Process](/endpoint/a6b3ab4e-dd77-4213-95fa-fc94701995e0/) | [Modify Registry](/tags/#modify-registry) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [System Process Running from Unexpected Location](/endpoint/28179107-099a-464a-94d3-08301e6c055f/) | [Masquerading](/tags/#masquerading) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [UAC Bypass MMC Load Unsigned Dll](/endpoint/7f04349c-e30d-11eb-bc7f-acde48001122/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism), [MMC](/tags/#mmc) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [WSReset UAC Bypass](/endpoint/8b5901bc-da63-11eb-be43-acde48001122/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Command and Scripting Interpreter Hunting Path Traversal](/endpoint/d0026380-b3c4-4da0-ac8e-02790063ff6b/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Command and Scripting Interpreter Path Traversal Exec](/endpoint/58fcdeb1-728d-415d-b0d7-3ab18a275ec2/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows DISM Remove Defender](/endpoint/8567da9e-47f0-11ec-99a9-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows DLL Search Order Hijacking Hunt](/endpoint/79c7d0fc-60c7-41be-a616-ccda752efe89/) | [DLL Search Order Hijacking](/tags/#dll-search-order-hijacking), [Hijack Execution Flow](/tags/#hijack-execution-flow) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows DLL Search Order Hijacking Hunt with Sysmon](/endpoint/79c7d1fc-64c7-91be-a616-ccda752efe81/) | [DLL Search Order Hijacking](/tags/#dll-search-order-hijacking), [Hijack Execution Flow](/tags/#hijack-execution-flow) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows DLL Search Order Hijacking with iscsicpl](/endpoint/f39ee679-3b1e-4f47-841c-5c3c580acda2/) | [DLL Search Order Hijacking](/tags/#dll-search-order-hijacking) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Defender Exclusion Registry Entry](/endpoint/13395a44-4dd9-11ec-9df7-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Disable Change Password Through Registry](/endpoint/0df33e1a-9ef6-11ec-a1ad-acde48001122/) | [Modify Registry](/tags/#modify-registry) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Disable Lock Workstation Feature Through Registry](/endpoint/c82adbc6-9f00-11ec-a81f-acde48001122/) | [Modify Registry](/tags/#modify-registry) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Disable Notification Center](/endpoint/1cd983c8-8fd6-11ec-a09d-acde48001122/) | [Modify Registry](/tags/#modify-registry) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Disable Windows Event Logging Disable HTTP Logging](/endpoint/23fb6787-255f-4d5b-9a66-9fd7504032b5/) | [Disable Windows Event Logging](/tags/#disable-windows-event-logging), [Impair Defenses](/tags/#impair-defenses), [Server Software Component](/tags/#server-software-component), [IIS Components](/tags/#iis-components) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Disable Windows Group Policy Features Through Registry](/endpoint/63a449ae-9f04-11ec-945e-acde48001122/) | [Modify Registry](/tags/#modify-registry) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows DisableAntiSpyware Registry](/endpoint/23150a40-9301-4195-b802-5bb4f43067fb/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Event For Service Disabled](/endpoint/9c2620a8-94a1-11ec-b40c-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Excessive Disabled Services Event](/endpoint/c3f85976-94a5-11ec-9a58-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Hide Notification Features Through Registry](/endpoint/cafa4bce-9f06-11ec-a7b2-acde48001122/) | [Modify Registry](/tags/#modify-registry) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Impair Defense Delete Win Defender Context Menu](/endpoint/395ed5fe-ad13-4366-9405-a228427bdd91/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Impair Defense Delete Win Defender Profile Registry](/endpoint/65d4b105-ec52-48ec-ac46-289d0fbf7d96/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Impair Defenses Disable HVCI](/endpoint/b061dfcc-f0aa-42cc-a6d4-a87f172acb79/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Impair Defenses Disable Win Defender Auto Logging](/endpoint/76406a0f-f5e0-4167-8e1f-337fdc0f1b0c/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Modify Show Compress Color And Info Tip Registry](/endpoint/b7548c2e-9a10-11ec-99e3-acde48001122/) | [Modify Registry](/tags/#modify-registry) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows PowerShell Disable HTTP Logging](/endpoint/27958de0-2857-43ca-9d4c-b255cf59dcab/) | [Impair Defenses](/tags/#impair-defenses), [Disable Windows Event Logging](/tags/#disable-windows-event-logging), [Server Software Component](/tags/#server-software-component), [IIS Components](/tags/#iis-components) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Process With NamedPipe CommandLine](/endpoint/e64399d4-94a8-11ec-a9da-acde48001122/) | [Process Injection](/tags/#process-injection) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Rasautou DLL Execution](/endpoint/6f42b8be-8e96-11ec-ad5a-acde48001122/) | [Dynamic-link Library Injection](/tags/#dynamic-link-library-injection), [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Process Injection](/tags/#process-injection) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Rasautou DLL Execution](/endpoint/6f42b8ce-1e15-11ec-ad5a-acde48001122/) | [Dynamic-link Library Injection](/tags/#dynamic-link-library-injection), [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Process Injection](/tags/#process-injection) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://attack.mitre.org/wiki/Defense_Evasion](https://attack.mitre.org/wiki/Defense_Evasion)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/windows_defense_evasion_tactics.yml) \| *version*: **1**