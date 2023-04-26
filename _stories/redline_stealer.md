---
title: "RedLine Stealer"
last_modified_at: 2023-04-24
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

Leverage searches that allow you to detect and investigate unusual activities that might relate to the Redline Stealer trojan, including looking for file writes associated with its payload, screencapture, registry modification, persistence and data collection..

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2023-04-24
- **Author**: Teoderick Contreras, Splunk
- **ID**: 12e31e8b-671b-4d6e-b362-a682812a71eb

#### Narrative

RedLine Stealer is a malware available on underground forum and subscription basis that are compiled or written in C#. This malware is capable of harvesting sensitive information from browsers such as saved credentials, auto file data, browser cookies and credit card information. It also gathers system information of the targeted or compromised host like username, location IP, RAM size available, hardware configuration and software installed. The current version of this malware contains features to steal wallet and crypto currency information.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Disable Windows Behavior Monitoring](/endpoint/79439cae-9200-11eb-a4d3-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Executables Or Script Creation In Suspicious Path](/endpoint/a7e3f0f0-ae42-11eb-b245-acde48001122/) | [Masquerading](/tags/#masquerading) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Non Chrome Process Accessing Chrome Default Dir](/endpoint/81263de4-160a-11ec-944f-acde48001122/) | [Credentials from Password Stores](/tags/#credentials-from-password-stores), [Credentials from Web Browsers](/tags/#credentials-from-web-browsers) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Non Firefox Process Access Firefox Profile Dir](/endpoint/e6fc13b0-1609-11ec-b533-acde48001122/) | [Credentials from Password Stores](/tags/#credentials-from-password-stores), [Credentials from Web Browsers](/tags/#credentials-from-web-browsers) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Process File Path](/endpoint/9be25988-ad82-11eb-a14f-acde48001122/) | [Create or Modify System Process](/tags/#create-or-modify-system-process) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows DisableAntiSpyware Registry](/endpoint/23150a40-9301-4195-b802-5bb4f43067fb/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Event For Service Disabled](/endpoint/9c2620a8-94a1-11ec-b40c-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://malpedia.caad.fkie.fraunhofer.de/details/win.redline_stealer](https://malpedia.caad.fkie.fraunhofer.de/details/win.redline_stealer)
* [https://blogs.blackberry.com/en/2021/10/threat-thursday-redline-infostealer-update](https://blogs.blackberry.com/en/2021/10/threat-thursday-redline-infostealer-update)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/redline_stealer.yml) \| *version*: **1**