---
title: "Suspicious Rundll32 Activity"
last_modified_at: 2021-02-03
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

Monitor and detect techniques used by attackers who leverage rundll32.exe to execute arbitrary malicious code.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Endpoint_Processes](https://docs.splunk.com/Documentation/CIM/latest/User/EndpointProcesses)
- **Last Updated**: 2021-02-03
- **Author**: Michael Haag, Splunk
- **ID**: 80a65487-854b-42f1-80a1-935e4c170694

#### Narrative

One common adversary tactic is to bypass application control solutions via the rundll32.exe process. Natively, rundll32.exe will load DLLs and is a great example of a Living off the Land Binary. Rundll32.exe may load malicious DLLs by ordinals, function names or directly. The queries in this story focus on loading default DLLs, syssetup.dll, ieadvpack.dll, advpack.dll and setupapi.dll from disk that may be abused by adversaries. Additionally, two analytics developed to assist with identifying DLLRegisterServer, Start and StartW functions being called. The searches in this story help you detect and investigate suspicious activity that may indicate that an adversary is leveraging rundll32.exe to execute malicious code.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Detect Rundll32 Application Control Bypass - advpack](/endpoint/4aefadfe-9abd-4bf8-b3fd-867e9ef95bf8/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Rundll32](/tags/#rundll32) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Rundll32 Application Control Bypass - setupapi](/endpoint/61e7b44a-6088-4f26-b788-9a96ba13b37a/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Rundll32](/tags/#rundll32) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Rundll32 Application Control Bypass - syssetup](/endpoint/71b9bf37-cde1-45fb-b899-1b0aa6fa1183/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Rundll32](/tags/#rundll32) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Dump LSASS via comsvcs DLL](/endpoint/8943b567-f14d-4ee8-a0bb-2121d4ce3184/) | [LSASS Memory](/tags/#lsass-memory), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [RunDLL Loading DLL By Ordinal](/endpoint/6c135f8d-5e60-454e-80b7-c56eed739833/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Rundll32](/tags/#rundll32) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Rundll32 Control RunDLL Hunt](/endpoint/c8e7ced0-10c5-11ec-8b03-acde48001122/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Rundll32](/tags/#rundll32) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Rundll32 Control RunDLL World Writable Directory](/endpoint/1adffe86-10c3-11ec-8ce6-acde48001122/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Rundll32](/tags/#rundll32) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Rundll32 with no Command Line Arguments with Network](/endpoint/35307032-a12d-11eb-835f-acde48001122/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Rundll32](/tags/#rundll32) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Rundll32 Rename](/deprecated/7360137f-abad-473e-8189-acbdaa34d114/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Masquerading](/tags/#masquerading), [Rundll32](/tags/#rundll32), [Rename System Utilities](/tags/#rename-system-utilities) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Rundll32 StartW](/endpoint/9319dda5-73f2-4d43-a85a-67ce961bddb7/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Rundll32](/tags/#rundll32) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Rundll32 dllregisterserver](/endpoint/8c00a385-9b86-4ac0-8932-c9ec3713b159/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Rundll32](/tags/#rundll32) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Rundll32 no Command Line Arguments](/endpoint/e451bd16-e4c5-4109-8eb1-c4c6ecf048b4/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Rundll32](/tags/#rundll32) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Rundll32 Comsvcs Memory Dump](/endpoint/76bb9e35-f314-4c3d-a385-83c72a13ce4e/) | [NTDS](/tags/#ntds), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://attack.mitre.org/techniques/T1218/011/](https://attack.mitre.org/techniques/T1218/011/)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.011/T1218.011.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.011/T1218.011.md)
* [https://lolbas-project.github.io/lolbas/Binaries/Rundll32](https://lolbas-project.github.io/lolbas/Binaries/Rundll32)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/suspicious_rundll32_activity.yml) \| *version*: **1**