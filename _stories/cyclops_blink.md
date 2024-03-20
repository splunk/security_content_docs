---
title: "Cyclops Blink"
last_modified_at: 2024-03-14
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

Leverage searches that allow you to detect and investigate unusual activities that might relate to the cyclopsblink malware including firewall modification, spawning more process, botnet c2 communication, defense evasion and etc. Cyclops Blink is a Linux ELF executable compiled for 32-bit x86 and PowerPC architecture that has targeted several network devices. The complete list of targeted devices is unknown at this time, but WatchGuard FireBox has specifically been listed as a target. The modular malware consists of core components and modules that are deployed as child processes using the Linux API fork. At this point, four modules have been identified that download and upload files, gather system information and contain updating mechanisms for the malware itself. Additional modules can be downloaded and executed from the Command And Control (C2) server.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2024-03-14
- **Author**: Teoderick Contreras, Splunk
- **ID**: 7c75b1c8-dfff-46f1-8250-e58df91b6fd9

#### Narrative

Adversaries may use this technique to maximize the impact on the target organization in operations where network wide availability interruption is the goal.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Linux Iptables Firewall Modification](/endpoint/309d59dc-1e1b-49b2-9800-7cf18d12f7b7/) | [Disable or Modify System Firewall](/tags/#disable-or-modify-system-firewall), [Impair Defenses](/tags/#impair-defenses) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Kworker Process In Writable Process Path](/endpoint/1cefb270-74a5-4e27-aa0c-2b6fa7c5b4ed/) | [Masquerade Task or Service](/tags/#masquerade-task-or-service), [Masquerading](/tags/#masquerading) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Stdout Redirection To Dev Null File](/endpoint/de62b809-a04d-46b5-9a15-8298d330f0c8/) | [Disable or Modify System Firewall](/tags/#disable-or-modify-system-firewall), [Impair Defenses](/tags/#impair-defenses) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://www.ncsc.gov.uk/files/Cyclops-Blink-Malware-Analysis-Report.pdf](https://www.ncsc.gov.uk/files/Cyclops-Blink-Malware-Analysis-Report.pdf)
* [https://www.trendmicro.com/en_us/research/22/c/cyclops-blink-sets-sights-on-asus-routers--.html](https://www.trendmicro.com/en_us/research/22/c/cyclops-blink-sets-sights-on-asus-routers--.html)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/cyclops_blink.yml) \| *version*: **2**