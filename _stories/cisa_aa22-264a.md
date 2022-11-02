---
title: "CISA AA22-264A"
last_modified_at: 2022-09-22
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Endpoint_Processes
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Iranian State Actors Conduct Cyber Operations Against the Government of Albania.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Endpoint_Processes](https://docs.splunk.com/Documentation/CIM/latest/User/EndpointProcesses)
- **Last Updated**: 2022-09-22
- **Author**: Michael Haag, Splunk
- **ID**: bc7056a5-c3b0-4b83-93ce-5f31739305c8

#### Narrative

The Federal Bureau of Investigation (FBI) and the Cybersecurity and Infrastructure Security Agency (CISA) are releasing this joint Cybersecurity Advisory to provide information on recent cyber operations against the Government of Albania in July and September. This advisory provides a timeline of activity observed, from initial access to execution of encryption and wiper attacks. Additional information concerning files used by the actors during their exploitation of and cyber attack against the victim organization is provided in Appendices A and B. In September 2022, Iranian cyber actors launched another wave of cyber attacks against the Government of Albania, using similar TTPs and malware as the cyber attacks in July. These were likely done in retaliation for public attribution of the cyber attacks in July and severed diplomatic ties between Albania and Iran.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Attacker Tools On Endpoint](/endpoint/a51bfe1a-94f0-48cc-b4e4-16a110145893/) | [Match Legitimate Name or Location](/tags/#match-legitimate-name-or-location), [Masquerading](/tags/#masquerading), [OS Credential Dumping](/tags/#os-credential-dumping), [Active Scanning](/tags/#active-scanning) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Deleting Shadow Copies](/endpoint/b89919ed-ee5f-492c-b139-95dbb162039e/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Mimikatz Using Loaded Images](/endpoint/29e307ba-40af-4ab2-91b2-3c6b392bbba0/) | [LSASS Memory](/tags/#lsass-memory), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Mimikatz With PowerShell Script Block Logging](/endpoint/8148c29c-c952-11eb-9255-acde48001122/) | [OS Credential Dumping](/tags/#os-credential-dumping), [PowerShell](/tags/#powershell) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Dump LSASS via comsvcs DLL](/endpoint/8943b567-f14d-4ee8-a0bb-2121d4ce3184/) | [LSASS Memory](/tags/#lsass-memory), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Excessive Usage Of Taskkill](/endpoint/fe5bca48-accb-11eb-a67c-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Exchange PowerShell Module Usage](/endpoint/2d10095e-05ae-11ec-8fdf-acde48001122/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [W3WP Spawning Shell](/endpoint/0f03423c-7c6a-11eb-bc47-acde48001122/) | [Server Software Component](/tags/#server-software-component), [Web Shell](/tags/#web-shell) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [WevtUtil Usage To Clear Logs](/endpoint/5438113c-cdd9-11eb-93b8-acde48001122/) | [Indicator Removal](/tags/#indicator-removal), [Clear Windows Event Logs](/tags/#clear-windows-event-logs) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows DisableAntiSpyware Registry](/endpoint/23150a40-9301-4195-b802-5bb4f43067fb/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Event Log Cleared](/endpoint/ad517544-aff9-4c96-bd99-d6eb43bfbb6a/) | [Indicator Removal](/tags/#indicator-removal), [Clear Windows Event Logs](/tags/#clear-windows-event-logs) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Exchange PowerShell Module Usage](/endpoint/1118bc65-b0c7-4589-bc2f-ad6802fd0909/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Possible Credential Dumping](/endpoint/e4723b92-7266-11ec-af45-acde48001122/) | [LSASS Memory](/tags/#lsass-memory), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Raw Access To Disk Volume Partition](/endpoint/a85aa37e-9647-11ec-90c5-acde48001122/) | [Disk Structure Wipe](/tags/#disk-structure-wipe), [Disk Wipe](/tags/#disk-wipe) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Raw Access To Master Boot Record Drive](/endpoint/7b83f666-900c-11ec-a2d9-acde48001122/) | [Disk Structure Wipe](/tags/#disk-structure-wipe), [Disk Wipe](/tags/#disk-wipe) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows System File on Disk](/endpoint/993ce99d-9cdd-42c7-a2cf-733d5954e5a6/) | [Exploitation for Privilege Escalation](/tags/#exploitation-for-privilege-escalation) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://www.cisa.gov/uscert/ncas/alerts/aa22-264a](https://www.cisa.gov/uscert/ncas/alerts/aa22-264a)
* [https://www.cisa.gov/uscert/sites/default/files/publications/aa22-264a-iranian-cyber-actors-conduct-cyber-operations-against-the-government-of-albania.pdf](https://www.cisa.gov/uscert/sites/default/files/publications/aa22-264a-iranian-cyber-actors-conduct-cyber-operations-against-the-government-of-albania.pdf)
* [https://www.mandiant.com/resources/blog/likely-iranian-threat-actor-conducts-politically-motivated-disruptive-activity-against](https://www.mandiant.com/resources/blog/likely-iranian-threat-actor-conducts-politically-motivated-disruptive-activity-against)
* [https://www.microsoft.com/security/blog/2022/09/08/microsoft-investigates-iranian-attacks-against-the-albanian-government/](https://www.microsoft.com/security/blog/2022/09/08/microsoft-investigates-iranian-attacks-against-the-albanian-government/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/cisa_aa22_264a.yml) \| *version*: **1**