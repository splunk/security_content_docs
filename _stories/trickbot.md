---
title: "Trickbot"
last_modified_at: 2021-04-20
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

Leverage searches that allow you to detect and investigate unusual activities that might relate to the trickbot banking trojan, including looking for file writes associated with its payload, process injection, shellcode execution and data collection even in LDAP environment.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-04-20
- **Author**: Rod Soto, Teoderick Contreras, Splunk
- **ID**: 16f93769-8342-44c0-9b1d-f131937cce8e

#### Narrative

trickbot banking trojan campaigns targeting banks and other vertical sectors.This malware is known in Microsoft Windows OS where target security Microsoft Defender to prevent its detection and removal. steal Verizon credentials and targeting banks using its multi component modules that collect and exfiltrate data.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Account Discovery With Net App](/endpoint/339805ce-ac30-11eb-b87d-acde48001122/) | [Domain Account](/tags/#domain-account), [Account Discovery](/tags/#account-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Attempt To Stop Security Service](/endpoint/c8e349c6-b97c-486e-8949-bd7bcd1f3910/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Cobalt Strike Named Pipes](/endpoint/5876d429-0240-4709-8b93-ea8330b411b5/) | [Process Injection](/tags/#process-injection) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Executable File Written in Administrative SMB Share](/endpoint/f63c34fe-a435-11eb-935a-acde48001122/) | [Remote Services](/tags/#remote-services), [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Executables Or Script Creation In Suspicious Path](/endpoint/a7e3f0f0-ae42-11eb-b245-acde48001122/) | [Masquerading](/tags/#masquerading) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Mshta spawning Rundll32 OR Regsvr32 Process](/endpoint/4aa5d062-e893-11eb-9eb2-acde48001122/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Mshta](/tags/#mshta) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Office Application Spawn rundll32 process](/endpoint/958751e4-9c5f-11eb-b103-acde48001122/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Office Document Executing Macro Code](/endpoint/b12c89bc-9d06-11eb-a592-acde48001122/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Office Product Spawn CMD Process](/endpoint/b8b19420-e892-11eb-9244-acde48001122/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Office Product Spawning CertUtil](/endpoint/6925fe72-a6d5-11eb-9e17-acde48001122/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Powershell Remote Thread To Known Windows Process](/endpoint/ec102cb2-a0f5-11eb-9b38-acde48001122/) | [Process Injection](/tags/#process-injection) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Schedule Task with Rundll32 Command Trigger](/endpoint/75b00fd8-a0ff-11eb-8b31-acde48001122/) | [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Scheduled Task Deleted Or Created via CMD](/endpoint/d5af132c-7c17-439c-9d31-13d55340f36c/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Process File Path](/endpoint/9be25988-ad82-11eb-a14f-acde48001122/) | [Create or Modify System Process](/tags/#create-or-modify-system-process) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Rundll32 StartW](/endpoint/9319dda5-73f2-4d43-a85a-67ce961bddb7/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Rundll32](/tags/#rundll32) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Trickbot Named Pipe](/endpoint/1804b0a4-a682-11eb-8f68-acde48001122/) | [Process Injection](/tags/#process-injection) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Wermgr Process Connecting To IP Check Web Services](/endpoint/ed313326-a0f9-11eb-a89c-acde48001122/) | [Gather Victim Network Information](/tags/#gather-victim-network-information), [IP Addresses](/tags/#ip-addresses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Wermgr Process Create Executable File](/endpoint/ab3bcce0-a105-11eb-973c-acde48001122/) | [Obfuscated Files or Information](/tags/#obfuscated-files-or-information) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Wermgr Process Spawned CMD Or Powershell Process](/endpoint/e8fc95bc-a107-11eb-a978-acde48001122/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://en.wikipedia.org/wiki/Trickbot](https://en.wikipedia.org/wiki/Trickbot)
* [https://blog.checkpoint.com/2021/03/11/february-2021s-most-wanted-malware-trickbot-takes-over-following-emotet-shutdown/](https://blog.checkpoint.com/2021/03/11/february-2021s-most-wanted-malware-trickbot-takes-over-following-emotet-shutdown/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/trickbot.yml) \| *version*: **1**