---
title: "Spearphishing Attachments"
last_modified_at: 2019-04-29
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

Detect signs of malicious payloads that may indicate that your environment has been breached via a phishing attack.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Endpoint_Processes](https://docs.splunk.com/Documentation/CIM/latest/User/EndpointProcesses)
- **Last Updated**: 2019-04-29
- **Author**: Splunk Research Team, Splunk
- **ID**: 57226b40-94f3-4ce5-b101-a75f67759c27

#### Narrative

Despite its simplicity, phishing remains the most pervasive and dangerous cyberthreat. In fact, research shows that as many as [91% of all successful attacks](https://digitalguardian.com/blog/91-percent-cyber-attacks-start-phishing-email-heres-how-protect-against-phishing) are initiated via a phishing email. \
As most people know, these emails use fraudulent domains, [email scraping](https://www.cyberscoop.com/emotet-trojan-phishing-scraping-templates-cofense-geodo/), familiar contact names inserted as senders, and other tactics to lure targets into clicking a malicious link, opening an attachment with a [nefarious payload](https://www.cyberscoop.com/emotet-trojan-phishing-scraping-templates-cofense-geodo/), or entering sensitive personal information that perpetrators may intercept. This attack technique requires a relatively low level of skill and allows adversaries to easily cast a wide net. Worse, because its success relies on the gullibility of humans, it's impossible to completely "automate" it out of your environment. However, you can use ES and ESCU to detect and investigate potentially malicious payloads injected into your environment subsequent to a phishing attack. \
While any kind of file may contain a malicious payload, some are more likely to be perceived as benign (and thus more often escape notice) by the average victim&#151;especially when the attacker sends an email that seems to be from one of their contacts. An example is Microsoft Office files. Most corporate users are familiar with documents with the following suffixes: .doc/.docx (MS Word), .xls/.xlsx (MS Excel), and .ppt/.pptx (MS PowerPoint), so they may click without a second thought, slashing a hole in their organizations' security. \
Following is a typical series of events, according to an [article by Trend Micro](https://blog.trendmicro.com/trendlabs-security-intelligence/rising-trend-attackers-using-lnk-files-download-malware/):\
1. Attacker sends a phishing email. Recipient downloads the attached file, which is typically a .docx or .zip file with an embedded .lnk file\
1. The .lnk file executes a PowerShell script\
1. Powershell executes a reverse shell, rendering the exploit successful </ol>As a side note, adversaries are likely to use a tool like Empire to craft and obfuscate payloads and their post-injection activities, such as [exfiltration, lateral movement, and persistence](https://github.com/EmpireProject/Empire).\
This Analytic Story focuses on detecting signs that a malicious payload has been injected into your environment. For example, one search detects outlook.exe writing a .zip file. Another looks for suspicious .lnk files launching processes.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Detect Outlook exe writing a zip file](/endpoint/a51bfe1a-94f0-4822-b1e4-16ae10145893/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Excel Spawning PowerShell](/endpoint/42d40a22-9be3-11eb-8f08-acde48001122/) | [Security Account Manager](/tags/#security-account-manager), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Excel Spawning Windows Script Host](/endpoint/57fe880a-9be3-11eb-9bf3-acde48001122/) | [Security Account Manager](/tags/#security-account-manager), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Gdrive suspicious file sharing](/cloud/a7131dae-34e3-11ec-a2de-acde48001122/) | [Phishing](/tags/#phishing) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Gsuite suspicious calendar invite](/cloud/03cdd68a-34fb-11ec-9bd3-acde48001122/) | [Phishing](/tags/#phishing) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [MSHTML Module Load in Office Product](/endpoint/5f1c168e-118b-11ec-84ff-acde48001122/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Office Application Spawn rundll32 process](/endpoint/958751e4-9c5f-11eb-b103-acde48001122/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Office Document Creating Schedule Task](/endpoint/cc8b7b74-9d0f-11eb-8342-acde48001122/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Office Document Executing Macro Code](/endpoint/b12c89bc-9d06-11eb-a592-acde48001122/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Office Document Spawned Child Process To Download](/endpoint/6fed27d2-9ec7-11eb-8fe4-aa665a019aa3/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Office Product Spawning BITSAdmin](/endpoint/e8c591f4-a6d7-11eb-8cf7-acde48001122/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Office Product Spawning CertUtil](/endpoint/6925fe72-a6d5-11eb-9e17-acde48001122/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Office Product Spawning MSHTA](/endpoint/6078fa20-a6d2-11eb-b662-acde48001122/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Office Product Spawning Rundll32 with no DLL](/endpoint/c661f6be-a38c-11eb-be57-acde48001122/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Office Product Spawning Windows Script Host](/endpoint/3ea3851a-8736-41a0-bc09-7e4485b48fa6/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Office Product Spawning Windows Script Host](/endpoint/b3628a5b-8d02-42fa-a891-eebf2351cbe1/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Office Product Spawning Wmic](/endpoint/ffc236d6-a6c9-11eb-95f1-acde48001122/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Office Product Writing cab or inf](/endpoint/f48cd1d4-125a-11ec-a447-acde48001122/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Office Spawning Control](/endpoint/053e027c-10c7-11ec-8437-acde48001122/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Process Creating LNK file in Suspicious Location](/endpoint/5d814af1-1041-47b5-a9ac-d754e82e9a26/) | [Phishing](/tags/#phishing), [Spearphishing Link](/tags/#spearphishing-link) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows ISO LNK File Creation](/endpoint/d7c2c09b-9569-4a9e-a8b6-6a39a99c1d32/) | [Spearphishing Attachment](/tags/#spearphishing-attachment), [Phishing](/tags/#phishing), [Malicious Link](/tags/#malicious-link), [User Execution](/tags/#user-execution) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Office Product Spawning MSDT](/endpoint/127eba64-c981-40bf-8589-1830638864a7/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Phishing PDF File Executes URL Link](/endpoint/2fa9dec8-9d8e-46d3-96c1-202c06f0e6e1/) | [Spearphishing Attachment](/tags/#spearphishing-attachment), [Phishing](/tags/#phishing) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Spearphishing Attachment Connect To None MS Office Domain](/endpoint/1cb40e15-cffa-45cc-abbd-e35884a49766/) | [Spearphishing Attachment](/tags/#spearphishing-attachment), [Phishing](/tags/#phishing) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Spearphishing Attachment Onenote Spawn Mshta](/endpoint/35aeb0e7-7de5-444a-ac45-24d6788796ec/) | [Spearphishing Attachment](/tags/#spearphishing-attachment), [Phishing](/tags/#phishing) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Winword Spawning Cmd](/endpoint/6fcbaedc-a37b-11eb-956b-acde48001122/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Winword Spawning PowerShell](/endpoint/b2c950b8-9be2-11eb-8658-acde48001122/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Winword Spawning Windows Script Host](/endpoint/637e1b5c-9be1-11eb-9c32-acde48001122/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://www.fireeye.com/blog/threat-research/2019/04/spear-phishing-campaign-targets-ukraine-government.html](https://www.fireeye.com/blog/threat-research/2019/04/spear-phishing-campaign-targets-ukraine-government.html)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/spearphishing_attachments.yml) \| *version*: **1**