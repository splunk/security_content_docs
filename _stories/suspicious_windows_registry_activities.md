---
title: "Suspicious Windows Registry Activities"
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

Monitor and detect registry changes initiated from remote locations, which can be a sign that an attacker has infiltrated your system.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2018-05-31
- **Author**: Bhavin Patel, Splunk
- **ID**: 2b1800dd-92f9-47dd-a981-fdf1351e5d55

#### Narrative

Attackers are developing increasingly sophisticated techniques for hijacking target servers, while evading detection. One such technique that has become progressively more common is registry modification.\
 The registry is a key component of the Windows operating system. It has a hierarchical database called "registry" that contains settings, options, and values for executables. Once the threat actor gains access to a machine, they can use reg.exe to modify their account to obtain administrator-level privileges, maintain persistence, and move laterally within the environment.\
 The searches in this story are designed to help you detect behaviors associated with manipulation of the Windows registry.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Disable UAC Remote Restriction](/endpoint/9928b732-210e-11ec-b65e-acde48001122/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disabling Remote User Account Control](/endpoint/bbc644bc-37df-4e1a-9c88-ec9a53e2038c/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Monitor Registry Keys for Print Monitors](/endpoint/f5f6af30-7ba7-4295-bfe9-07de87c01bbc/) | [Port Monitors](/tags/#port-monitors), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Reg exe used to hide files directories via registry keys](/deprecated/61a7d1e6-f5d4-41d9-a9be-39a1ffe69459/) | [Hidden Files and Directories](/tags/#hidden-files-and-directories) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Registry Keys Used For Persistence](/endpoint/f5f6af30-7aa7-4295-bfe9-07fe87c01a4b/) | [Registry Run Keys / Startup Folder](/tags/#registry-run-keys-/-startup-folder), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Registry Keys Used For Privilege Escalation](/endpoint/c9f4b923-f8af-4155-b697-1354f5bcbc5e/) | [Image File Execution Options Injection](/tags/#image-file-execution-options-injection), [Event Triggered Execution](/tags/#event-triggered-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Registry Keys for Creating SHIM Databases](/endpoint/f5f6af30-7aa7-4295-bfe9-07fe87c01bbb/) | [Application Shimming](/tags/#application-shimming), [Event Triggered Execution](/tags/#event-triggered-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Remote Registry Key modifications](/deprecated/c9f4b923-f8af-4155-b697-1354f5dcbc5e/) |  | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Changes to File Associations](/deprecated/1b989a0e-0129-4446-a695-f193a5b746fc/) | [Change Default File Association](/tags/#change-default-file-association) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Mshta Execution In Registry](/endpoint/e13ceade-b673-4d34-adc4-4d9c01729753/) | [Mshta](/tags/#mshta) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Service Creation Using Registry Entry](/endpoint/25212358-948e-11ec-ad47-acde48001122/) | [Services Registry Permissions Weakness](/tags/#services-registry-permissions-weakness) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://redcanary.com/blog/windows-registry-attacks-threat-detection/](https://redcanary.com/blog/windows-registry-attacks-threat-detection/)
* [https://attack.mitre.org/wiki/Technique/T1112](https://attack.mitre.org/wiki/Technique/T1112)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/suspicious_windows_registry_activities.yml) \| *version*: **1**