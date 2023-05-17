---
title: "Windows BootKits"
last_modified_at: 2023-05-03
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

Adversaries may use bootkits to persist on systems. Bootkits reside at a layer below the operating system and may make it difficult to perform full remediation unless an organization suspects one was used and can act accordingly.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2023-05-03
- **Author**: Michael Haag, Splunk
- **ID**: 1bef004d-23b2-4c49-8ceb-b59af0745317

#### Narrative

A bootkit is a sophisticated type of malware that targets the boot sectors of a hard drive, specifically the Master Boot Record (MBR) and Volume Boot Record (VBR). The MBR is the initial section of the disk that is loaded following the hardware initialization process executed by the Basic Input/Output System (BIOS). It houses the boot loader, which is responsible for loading the operating system. In contrast, the VBR is located at the beginning of each partition and contains the boot code for that specific partition. When an adversary gains raw access to the boot drive, they can overwrite the MBR or VBR, effectively diverting the execution during startup from the standard boot loader to the malicious code injected by the attacker. This tampering allows the malware to load before the operating system, enabling it to execute malicious activities stealthily and maintain persistence on the compromised system. Bootkits are particularly dangerous because they can bypass security measures implemented by the operating system and antivirus software. Since they load before the operating system, they can easily evade detection and manipulate the system's behavior from the earliest stages of the boot process. This capability makes bootkits a potent tool in an attacker's arsenal for gaining unauthorized access, stealing sensitive information, or launching further attacks on other systems. To defend against bootkit attacks, organizations should implement multiple layers of security, including strong endpoint protection, regular software updates, user awareness training, and monitoring for unusual system behavior. Additionally, hardware-based security features, such as Unified Extensible Firmware Interface (UEFI) Secure Boot and Trusted Platform Module (TPM), can help protect the integrity of the boot process and reduce the risk of bootkit infections.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Windows BootLoader Inventory](/endpoint/4f7e3913-4db3-4ccd-afe4-31198982305d/) | [System Firmware](/tags/#system-firmware), [Pre-OS Boot](/tags/#pre-os-boot) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Registry BootExecute Modification](/endpoint/eabbac3a-45aa-4659-920f-6b8cff383fb8/) | [Pre-OS Boot](/tags/#pre-os-boot), [Registry Run Keys / Startup Folder](/tags/#registry-run-keys-/-startup-folder) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://www.microsoft.com/en-us/security/blog/2023/04/11/guidance-for-investigating-attacks-using-cve-2022-21894-the-blacklotus-campaign/](https://www.microsoft.com/en-us/security/blog/2023/04/11/guidance-for-investigating-attacks-using-cve-2022-21894-the-blacklotus-campaign/)
* [https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/](https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/windows_bootkits.yml) \| *version*: **1**