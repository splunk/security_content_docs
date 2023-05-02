---
title: "DarkSide Ransomware"
last_modified_at: 2021-05-12
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

Leverage searches that allow you to detect and investigate unusual activities that might relate to the DarkSide Ransomware

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-05-12
- **Author**: Bhavin Patel, Splunk
- **ID**: 507edc74-13d5-4339-878e-b9114ded1f35

#### Narrative

This story addresses Darkside ransomware. This ransomware payload has many similarities to common ransomware however there are certain items particular to it. The creation of a .TXT log that shows every item being encrypted as well as the creation of ransomware notes and files adding a machine ID created based on CRC32 checksum algorithm. This ransomware payload leaves machines in minimal operation level,enough to browse the attackers websites. A customized URI with leaked information is presented to each victim.This is the ransomware payload that shut down the Colonial pipeline. The story is composed of several detection searches covering similar items to other ransomware payloads and those particular to Darkside payload.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Attempted Credential Dump From Registry via Reg exe](/endpoint/e9fb4a59-c5fb-440a-9f24-191fbc6b2911/) | [Security Account Manager](/tags/#security-account-manager), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [BITSAdmin Download File](/endpoint/80630ff4-8e4c-11eb-aab5-acde48001122/) | [BITS Jobs](/tags/#bits-jobs), [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [CMLUA Or CMSTPLUA UAC Bypass](/endpoint/f87b5062-b405-11eb-a889-acde48001122/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [CMSTP](/tags/#cmstp) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [CertUtil Download With URLCache and Split Arguments](/endpoint/415b4306-8bfb-11eb-85c4-acde48001122/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [CertUtil Download With VerifyCtl and Split Arguments](/endpoint/801ad9e4-8bfb-11eb-8b31-acde48001122/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Cobalt Strike Named Pipes](/endpoint/5876d429-0240-4709-8b93-ea8330b411b5/) | [Process Injection](/tags/#process-injection) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Delete ShadowCopy With PowerShell](/endpoint/5ee2bcd0-b2ff-11eb-bb34-acde48001122/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Mimikatz Using Loaded Images](/deprecated/29e307ba-40af-4ab2-91b2-3c6b392bbba0/) | [LSASS Memory](/tags/#lsass-memory), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect PsExec With accepteula Flag](/endpoint/27c3a83d-cada-47c6-9042-67baf19d2574/) | [Remote Services](/tags/#remote-services), [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect RClone Command-Line Usage](/endpoint/32e0baea-b3f1-11eb-a2ce-acde48001122/) | [Automated Exfiltration](/tags/#automated-exfiltration) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect RClone Command-Line Usage](/endpoint/e8b74268-5454-11ec-a799-acde48001122/) | [Automated Exfiltration](/tags/#automated-exfiltration) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Renamed PSExec](/endpoint/683e6196-b8e8-11eb-9a79-acde48001122/) | [System Services](/tags/#system-services), [Service Execution](/tags/#service-execution) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Renamed RClone](/endpoint/6dca1124-b3ec-11eb-9328-acde48001122/) | [Automated Exfiltration](/tags/#automated-exfiltration) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Extraction of Registry Hives](/endpoint/8bbb7d58-b360-11eb-ba21-acde48001122/) | [Security Account Manager](/tags/#security-account-manager), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Ransomware Notes bulk creation](/endpoint/eff7919a-8330-11eb-83f8-acde48001122/) | [Data Encrypted for Impact](/tags/#data-encrypted-for-impact) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [SLUI RunAs Elevated](/endpoint/8d124810-b3e4-11eb-96c7-acde48001122/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [SLUI Spawning a Process](/endpoint/879c4330-b3e0-11eb-b1b1-acde48001122/) | [Bypass User Account Control](/tags/#bypass-user-account-control), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Bitsadmin Download File](/endpoint/d76e8188-8f5a-11ec-ace4-acde48001122/) | [BITS Jobs](/tags/#bits-jobs), [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows CertUtil URLCache Download](/endpoint/8cb1ad38-8f6d-11ec-87a3-acde48001122/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows CertUtil VerifyCtl Download](/endpoint/9ac29c40-8f6b-11ec-b19a-acde48001122/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Possible Credential Dumping](/endpoint/e4723b92-7266-11ec-af45-acde48001122/) | [LSASS Memory](/tags/#lsass-memory), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://www.splunk.com/en_us/blog/security/the-darkside-of-the-ransomware-pipeline.htmlbig-game-hunting-with-ryuk-another-lucrative-targeted-ransomware/](https://www.splunk.com/en_us/blog/security/the-darkside-of-the-ransomware-pipeline.htmlbig-game-hunting-with-ryuk-another-lucrative-targeted-ransomware/)
* [https://www.mandiant.com/resources/shining-a-light-on-darkside-ransomware-operations](https://www.mandiant.com/resources/shining-a-light-on-darkside-ransomware-operations)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/darkside_ransomware.yml) \| *version*: **1**