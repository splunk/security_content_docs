---
title: "Windows Registry Abuse"
last_modified_at: 2022-03-17
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

Windows services are often used by attackers for persistence, privilege escalation, lateral movement, defense evasion, collection of data, a tool for recon, credential dumping and payload impact. This Analytic Story helps you monitor your environment for indications that Windows registry are being modified or created in a suspicious manner.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-03-17
- **Author**: Teoderick Contreras, Splunk
- **ID**: 78df1df1-25f1-4387-90f9-c4ea31ce6b75

#### Narrative

Windows Registry is one of the powerful and yet still mysterious Windows features that can tweak or manipulate Windows policies and low-level configuration settings. Because of this capability,  most malware, adversaries or threat actors abuse this hierarchical database to do their malicious intent on a targeted host or network environment. In these cases, attackers often use tools to create or modify registry in ways that are not typical for most environments, providing opportunities for detection.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Allow Inbound Traffic By Firewall Rule Registry](/endpoint/0a46537c-be02-11eb-92ca-acde48001122/) | [Remote Desktop Protocol](/tags/#remote-desktop-protocol), [Remote Services](/tags/#remote-services) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Allow Operation with Consent Admin](/endpoint/7de17d7a-c9d8-11eb-a812-acde48001122/) | [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Attempted Credential Dump From Registry via Reg exe](/endpoint/e9fb4a59-c5fb-440a-9f24-191fbc6b2911/) | [Security Account Manager](/tags/#security-account-manager), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Auto Admin Logon Registry Entry](/endpoint/1379d2b8-0f18-11ec-8ca3-acde48001122/) | [Credentials in Registry](/tags/#credentials-in-registry), [Unsecured Credentials](/tags/#unsecured-credentials) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Change Default File Association](/endpoint/462d17d8-1f71-11ec-ad07-acde48001122/) | [Change Default File Association](/tags/#change-default-file-association), [Event Triggered Execution](/tags/#event-triggered-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disable AMSI Through Registry](/endpoint/9c27ec42-d338-11eb-9044-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disable Defender AntiVirus Registry](/endpoint/aa4f695a-3024-11ec-9987-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disable Defender BlockAtFirstSeen Feature](/endpoint/2dd719ac-3021-11ec-97b4-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disable Defender Enhanced Notification](/endpoint/dc65678c-301f-11ec-8e30-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disable Defender MpEngine Registry](/endpoint/cc391750-3024-11ec-955a-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disable Defender Spynet Reporting](/endpoint/898debf4-3021-11ec-ba7c-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disable Defender Submit Samples Consent Feature](/endpoint/73922ff8-3022-11ec-bf5e-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disable ETW Through Registry](/endpoint/f0eacfa4-d33f-11eb-8f9d-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disable Registry Tool](/endpoint/cd2cf33c-9201-11eb-a10a-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disable Security Logs Using MiniNt Registry](/endpoint/39ebdc68-25b9-11ec-aec7-acde48001122/) | [Modify Registry](/tags/#modify-registry) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disable Show Hidden Files](/endpoint/6f3ccfa2-91fe-11eb-8f9b-acde48001122/) | [Hidden Files and Directories](/tags/#hidden-files-and-directories), [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Hide Artifacts](/tags/#hide-artifacts), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disable UAC Remote Restriction](/endpoint/9928b732-210e-11ec-b65e-acde48001122/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disable Windows App Hotkeys](/endpoint/1490f224-ad8b-11eb-8c4f-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disable Windows Behavior Monitoring](/endpoint/79439cae-9200-11eb-a4d3-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disable Windows SmartScreen Protection](/endpoint/664f0fd0-91ff-11eb-a56f-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disabling CMD Application](/endpoint/ff86077c-9212-11eb-a1e6-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disabling ControlPanel](/endpoint/6ae0148e-9215-11eb-a94a-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disabling Defender Services](/endpoint/911eacdc-317f-11ec-ad30-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disabling FolderOptions Windows Feature](/endpoint/83776de4-921a-11eb-868a-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disabling NoRun Windows App](/endpoint/de81bc46-9213-11eb-adc9-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disabling Remote User Account Control](/endpoint/bbc644bc-37df-4e1a-9c88-ec9a53e2038c/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disabling SystemRestore In Registry](/endpoint/f4f837e2-91fb-11eb-8bf6-acde48001122/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disabling Task Manager](/endpoint/dac279bc-9202-11eb-b7fb-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disabling Windows Local Security Authority Defences via Registry](/endpoint/45cd08f8-a2c9-4f4e-baab-e1a0c624b0ab/) | [Modify Authentication Process](/tags/#modify-authentication-process) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [ETW Registry Disabled](/endpoint/8ed523ac-276b-11ec-ac39-acde48001122/) | [Indicator Blocking](/tags/#indicator-blocking), [Trusted Developer Utilities Proxy Execution](/tags/#trusted-developer-utilities-proxy-execution), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Enable RDP In Other Port Number](/endpoint/99495452-b899-11eb-96dc-acde48001122/) | [Remote Services](/tags/#remote-services) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Enable WDigest UseLogonCredential Registry](/endpoint/0c7d8ffe-25b1-11ec-9f39-acde48001122/) | [Modify Registry](/tags/#modify-registry), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Eventvwr UAC Bypass](/endpoint/9cf8fe08-7ad8-11eb-9819-acde48001122/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Hide User Account From Sign-In Screen](/endpoint/834ba832-ad89-11eb-937d-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Modification Of Wallpaper](/endpoint/accb0712-c381-11eb-8e5b-acde48001122/) | [Defacement](/tags/#defacement) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Monitor Registry Keys for Print Monitors](/endpoint/f5f6af30-7ba7-4295-bfe9-07de87c01bbc/) | [Port Monitors](/tags/#port-monitors), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Registry Keys Used For Persistence](/endpoint/f5f6af30-7aa7-4295-bfe9-07fe87c01a4b/) | [Registry Run Keys / Startup Folder](/tags/#registry-run-keys-/-startup-folder), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Registry Keys Used For Privilege Escalation](/endpoint/c9f4b923-f8af-4155-b697-1354f5bcbc5e/) | [Image File Execution Options Injection](/tags/#image-file-execution-options-injection), [Event Triggered Execution](/tags/#event-triggered-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Registry Keys for Creating SHIM Databases](/endpoint/f5f6af30-7aa7-4295-bfe9-07fe87c01bbb/) | [Application Shimming](/tags/#application-shimming), [Event Triggered Execution](/tags/#event-triggered-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Remcos client registry install entry](/endpoint/f2a1615a-1d63-11ec-97d2-acde48001122/) | [Modify Registry](/tags/#modify-registry) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Revil Registry Entry](/endpoint/e3d3f57a-c381-11eb-9e35-acde48001122/) | [Modify Registry](/tags/#modify-registry) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Screensaver Event Trigger Execution](/endpoint/58cea3ec-1f6d-11ec-8560-acde48001122/) | [Event Triggered Execution](/tags/#event-triggered-execution), [Screensaver](/tags/#screensaver) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Sdclt UAC Bypass](/endpoint/d71efbf6-da63-11eb-8c6e-acde48001122/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [SilentCleanup UAC Bypass](/endpoint/56d7cfcc-da63-11eb-92d4-acde48001122/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Time Provider Persistence Registry](/endpoint/5ba382c4-2105-11ec-8d8f-acde48001122/) | [Time Providers](/tags/#time-providers), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [WSReset UAC Bypass](/endpoint/8b5901bc-da63-11eb-be43-acde48001122/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows AD DSRM Account Changes](/endpoint/08cb291e-ea77-48e8-a95a-0799319bf056/) | [Account Manipulation](/tags/#account-manipulation) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Autostart Execution LSASS Driver Registry Modification](/endpoint/57fb8656-141e-4d8a-9f51-62cff4ecb82a/) | [LSASS Driver](/tags/#lsass-driver) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Disable Lock Workstation Feature Through Registry](/endpoint/c82adbc6-9f00-11ec-a81f-acde48001122/) | [Modify Registry](/tags/#modify-registry) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Disable LogOff Button Through Registry](/endpoint/b2fb6830-9ed1-11ec-9fcb-acde48001122/) | [Modify Registry](/tags/#modify-registry) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Disable Memory Crash Dump](/endpoint/59e54602-9680-11ec-a8a6-acde48001122/) | [Data Destruction](/tags/#data-destruction) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Disable Notification Center](/endpoint/1cd983c8-8fd6-11ec-a09d-acde48001122/) | [Modify Registry](/tags/#modify-registry) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Disable Shutdown Button Through Registry](/endpoint/55fb2958-9ecd-11ec-a06a-acde48001122/) | [Modify Registry](/tags/#modify-registry) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Disable Windows Group Policy Features Through Registry](/endpoint/63a449ae-9f04-11ec-945e-acde48001122/) | [Modify Registry](/tags/#modify-registry) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows DisableAntiSpyware Registry](/endpoint/23150a40-9301-4195-b802-5bb4f43067fb/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Hide Notification Features Through Registry](/endpoint/cafa4bce-9f06-11ec-a7b2-acde48001122/) | [Modify Registry](/tags/#modify-registry) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Impair Defense Delete Win Defender Context Menu](/endpoint/395ed5fe-ad13-4366-9405-a228427bdd91/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Impair Defense Delete Win Defender Profile Registry](/endpoint/65d4b105-ec52-48ec-ac46-289d0fbf7d96/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Impair Defenses Disable HVCI](/endpoint/b061dfcc-f0aa-42cc-a6d4-a87f172acb79/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Impair Defenses Disable Win Defender Auto Logging](/endpoint/76406a0f-f5e0-4167-8e1f-337fdc0f1b0c/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Modify Show Compress Color And Info Tip Registry](/endpoint/b7548c2e-9a10-11ec-99e3-acde48001122/) | [Modify Registry](/tags/#modify-registry) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Registry Certificate Added](/endpoint/5ee98b2f-8b9e-457a-8bdc-dd41aaba9e87/) | [Install Root Certificate](/tags/#install-root-certificate), [Subvert Trust Controls](/tags/#subvert-trust-controls) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Registry Delete Task SD](/endpoint/ffeb7893-ff06-446f-815b-33ca73224e92/) | [Scheduled Task](/tags/#scheduled-task), [Impair Defenses](/tags/#impair-defenses) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Registry Modification for Safe Mode Persistence](/endpoint/c6149154-c9d8-11eb-9da7-acde48001122/) | [Registry Run Keys / Startup Folder](/tags/#registry-run-keys-/-startup-folder), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Service Creation Using Registry Entry](/endpoint/25212358-948e-11ec-ad47-acde48001122/) | [Services Registry Permissions Weakness](/tags/#services-registry-permissions-weakness) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://attack.mitre.org/techniques/T1112/](https://attack.mitre.org/techniques/T1112/)
* [https://redcanary.com/blog/windows-registry-attacks-threat-detection/](https://redcanary.com/blog/windows-registry-attacks-threat-detection/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/windows_registry_abuse.yml) \| *version*: **1**