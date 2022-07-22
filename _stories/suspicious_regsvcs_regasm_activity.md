---
title: "Suspicious Regsvcs Regasm Activity"
last_modified_at: 2021-02-11
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

Monitor and detect techniques used by attackers who leverage the mshta.exe process to execute malicious code.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-02-11
- **Author**: Michael Haag, Splunk
- **ID**: 2cdf33a0-4805-4b61-b025-59c20f418fbe

#### Narrative

 Adversaries may abuse Regsvcs and Regasm to proxy execution of code through a trusted Windows utility. Regsvcs and Regasm are Windows command-line utilities that are used to register .NET Component Object Model (COM) assemblies. Both are digitally signed by Microsoft. The following queries assist with detecting suspicious and malicious usage of Regasm.exe and Regsvcs.exe. Upon reviewing usage of Regasm.exe Regsvcs.exe, review file modification events for possible script code written. Review parallel process events for csc.exe being utilized to compile script code.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Detect Regasm Spawning a Process](/endpoint/72170ec5-f7d2-42f5-aefb-2b8be6aad15f/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Regsvcs/Regasm](/tags/#regsvcs/regasm) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Regasm with Network Connection](/endpoint/07921114-6db4-4e2e-ae58-3ea8a52ae93f/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Regsvcs/Regasm](/tags/#regsvcs/regasm) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Regasm with no Command Line Arguments](/endpoint/c3bc1430-04e7-4178-835f-047d8e6e97df/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Regsvcs/Regasm](/tags/#regsvcs/regasm) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Regsvcs Spawning a Process](/endpoint/bc477b57-5c21-4ab6-9c33-668772e7f114/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Regsvcs/Regasm](/tags/#regsvcs/regasm) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Regsvcs with Network Connection](/endpoint/e3e7a1c0-f2b9-445c-8493-f30a63522d1a/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Regsvcs/Regasm](/tags/#regsvcs/regasm) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Regsvcs with No Command Line Arguments](/endpoint/6b74d578-a02e-4e94-a0d1-39440d0bf254/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Regsvcs/Regasm](/tags/#regsvcs/regasm) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://attack.mitre.org/techniques/T1218/009/](https://attack.mitre.org/techniques/T1218/009/)
* [https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/evasion/windows/applocker_evasion_regasm_regsvcs.md](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/evasion/windows/applocker_evasion_regasm_regsvcs.md)
* [https://oddvar.moe/2017/12/13/applocker-case-study-how-insecure-is-it-really-part-1/](https://oddvar.moe/2017/12/13/applocker-case-study-how-insecure-is-it-really-part-1/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/suspicious_regsvcs_regasm_activity.yml) \| *version*: **1**