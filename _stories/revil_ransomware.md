---
title: "Revil Ransomware"
last_modified_at: 2021-06-04
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

Leverage searches that allow you to detect and investigate unusual activities that might relate to the Revil ransomware, including looking for file writes associated with Revil, encrypting network shares, deleting shadow volume storage, registry key modification, deleting of security logs, and more.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-06-04
- **Author**: Teoderick Contreras, Splunk
- **ID**: 817cae42-f54b-457a-8a36-fbf45521e29e

#### Narrative

Revil ransomware is a RaaS,that a single group may operates and manges the development of this ransomware. It involve the use of ransomware payloads along with exfiltration of data. Malicious actors demand payment for ransome of data and threaten deletion and exposure of exfiltrated data.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Allow Network Discovery In Firewall](/endpoint/ccd6a38c-d40b-11eb-85a5-acde48001122/) | [Disable or Modify Cloud Firewall](/tags/#disable-or-modify-cloud-firewall), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Delete ShadowCopy With PowerShell](/endpoint/5ee2bcd0-b2ff-11eb-bb34-acde48001122/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disable Windows Behavior Monitoring](/endpoint/79439cae-9200-11eb-a4d3-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Modification Of Wallpaper](/endpoint/accb0712-c381-11eb-8e5b-acde48001122/) | [Defacement](/tags/#defacement) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Msmpeng Application DLL Side Loading](/endpoint/8bb3f280-dd9b-11eb-84d5-acde48001122/) | [DLL Side-Loading](/tags/#dll-side-loading), [Hijack Execution Flow](/tags/#hijack-execution-flow) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Powershell Disable Security Monitoring](/endpoint/c148a894-dd93-11eb-bf2a-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Revil Common Exec Parameter](/endpoint/85facebe-c382-11eb-9c3e-acde48001122/) | [User Execution](/tags/#user-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Revil Registry Entry](/endpoint/e3d3f57a-c381-11eb-9e35-acde48001122/) | [Modify Registry](/tags/#modify-registry) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Wbemprox COM Object Execution](/endpoint/9d911ce0-c3be-11eb-b177-acde48001122/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [CMSTP](/tags/#cmstp) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://krebsonsecurity.com/2021/05/a-closer-look-at-the-darkside-ransomware-gang/](https://krebsonsecurity.com/2021/05/a-closer-look-at-the-darkside-ransomware-gang/)
* [https://www.mcafee.com/blogs/other-blogs/mcafee-labs/mcafee-atr-analyzes-sodinokibi-aka-revil-ransomware-as-a-service-what-the-code-tells-us/](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/mcafee-atr-analyzes-sodinokibi-aka-revil-ransomware-as-a-service-what-the-code-tells-us/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/revil_ransomware.yml) \| *version*: **1**