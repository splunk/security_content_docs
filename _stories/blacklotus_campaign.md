---
title: "BlackLotus Campaign"
last_modified_at: 2023-04-14
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

The first in-the-wild UEFI bootkit bypassing UEFI Secure Boot on fully updated UEFI systems is now a reality

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2023-04-14
- **Author**: Michael Haag, Splunk
- **ID**: 8eb0e418-a2b6-4327-a387-85c976662c8f

#### Narrative

The number of UEFI vulnerabilities discovered in recent years and the failures in patching them or revoking vulnerable binaries within a reasonable time window hasn't gone unnoticed by threat actors. As a result, the first publicly known UEFI bootkit bypassing the essential platform security feature  UEFI Secure Boot  is now a reality. present the first public analysis of this UEFI bootkit, which is capable of running on even fully-up-to-date Windows 11 systems with UEFI Secure Boot enabled. Functionality of the bootkit and its individual features leads us to believe that we are dealing with a bootkit known as BlackLotus, the UEFI bootkit being sold on hacking forums for $5,000 since at least October 2022. (ESET, 2023) The following content aims to aid defenders in detecting suspicious bootloaders and understanding the diverse techniques employed in this campaign.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Windows BootLoader Inventory](/endpoint/4f7e3913-4db3-4ccd-afe4-31198982305d/) | [System Firmware](/tags/#system-firmware), [Pre-OS Boot](/tags/#pre-os-boot) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Impair Defenses Disable HVCI](/endpoint/b061dfcc-f0aa-42cc-a6d4-a87f172acb79/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://www.microsoft.com/en-us/security/blog/2023/04/11/guidance-for-investigating-attacks-using-cve-2022-21894-the-blacklotus-campaign/](https://www.microsoft.com/en-us/security/blog/2023/04/11/guidance-for-investigating-attacks-using-cve-2022-21894-the-blacklotus-campaign/)
* [https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/](https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/blacklotus_campaign.yml) \| *version*: **1**