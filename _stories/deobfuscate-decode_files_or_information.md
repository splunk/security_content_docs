---
title: "Deobfuscate-Decode Files or Information"
last_modified_at: 2021-03-24
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

Adversaries may use Obfuscated Files or Information to hide artifacts of an intrusion from analysis.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-03-24
- **Author**: Michael Haag, Splunk
- **ID**: 0bd01a54-8cbe-11eb-abcd-acde48001122

#### Narrative

An example of obfuscated files is `Certutil.exe` usage to encode a portable executable to a certificate file, which is base64 encoded, to hide the originating file. There are many utilities cross-platform to encode using XOR, using compressed .cab files to hide contents and scripting languages that may perform similar native Windows tasks. Triaging an event related will require the capability to review related process events and file modifications. Using a tool such as CyberChef will assist with identifying the encoding that was used, and potentially assist with decoding the contents.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [CertUtil With Decode Argument](/endpoint/bfe94226-8c10-11eb-a4b3-acde48001122/) | [Deobfuscate/Decode Files or Information](/tags/#deobfuscate/decode-files-or-information) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows CertUtil Decode File](/endpoint/b06983f4-8f72-11ec-ab50-acde48001122/) | [Deobfuscate/Decode Files or Information](/tags/#deobfuscate/decode-files-or-information) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://attack.mitre.org/techniques/T1140/](https://attack.mitre.org/techniques/T1140/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/deobfuscate_decode_files_or_information.yml) \| *version*: **1**