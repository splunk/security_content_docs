---
title: "BITS Jobs"
last_modified_at: 2021-03-26
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

Adversaries may abuse BITS jobs to persistently execute or clean up after malicious payloads.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-03-26
- **Author**: Michael Haag, Splunk
- **ID**: dbc7edce-8e4c-11eb-9f31-acde48001122

#### Narrative

Windows Background Intelligent Transfer Service (BITS) is a low-bandwidth, asynchronous file transfer mechanism exposed through Component Object Model (COM). BITS is commonly used by updaters, messengers, and other applications preferred to operate in the background (using available idle bandwidth) without interrupting other networked applications. File transfer tasks are implemented as BITS jobs, which contain a queue of one or more file operations. The interface to create and manage BITS jobs is accessible through PowerShell and the BITSAdmin tool. Adversaries may abuse BITS to download, execute, and even clean up after running malicious code. BITS tasks are self-contained in the BITS job database, without new files or registry modifications, and often permitted by host firewalls. BITS enabled execution may also enable persistence by creating long-standing jobs (the default maximum lifetime is 90 days and extendable) or invoking an arbitrary program when a job completes or errors (including after system reboots).

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [BITS Job Persistence](/endpoint/e97a5ffe-90bf-11eb-928a-acde48001122/) | [BITS Jobs](/tags/#bits-jobs) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [BITSAdmin Download File](/endpoint/80630ff4-8e4c-11eb-aab5-acde48001122/) | [BITS Jobs](/tags/#bits-jobs), [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [PowerShell Start-BitsTransfer](/endpoint/39e2605a-90d8-11eb-899e-acde48001122/) | [BITS Jobs](/tags/#bits-jobs) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Bits Job Persistence](/endpoint/1e25e97a-8ea4-11ec-9767-acde48001122/) | [BITS Jobs](/tags/#bits-jobs) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Bitsadmin Download File](/endpoint/d76e8188-8f5a-11ec-ace4-acde48001122/) | [BITS Jobs](/tags/#bits-jobs), [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows PowerShell Start-BitsTransfer](/endpoint/0bafd086-8f61-11ec-996e-acde48001122/) | [BITS Jobs](/tags/#bits-jobs), [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://attack.mitre.org/techniques/T1197/](https://attack.mitre.org/techniques/T1197/)
* [https://docs.microsoft.com/en-us/windows/win32/bits/bitsadmin-tool](https://docs.microsoft.com/en-us/windows/win32/bits/bitsadmin-tool)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/bits_jobs.yml) \| *version*: **1**