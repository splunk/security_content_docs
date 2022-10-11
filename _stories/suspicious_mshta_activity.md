---
title: "Suspicious MSHTA Activity"
last_modified_at: 2021-01-20
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

Monitor and detect techniques used by attackers who leverage the mshta.exe process to execute malicious code.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Endpoint_Processes](https://docs.splunk.com/Documentation/CIM/latest/User/EndpointProcesses)
- **Last Updated**: 2021-01-20
- **Author**: Bhavin Patel, Michael Haag, Splunk
- **ID**: 1e5a5a53-540b-462a-8fb7-f44a4292f5dc

#### Narrative

One common adversary tactic is to bypass application control solutions via the mshta.exe process, which loads Microsoft HTML applications (mshtml.dll) with the .hta suffix. In these cases, attackers use the trusted Windows utility to proxy execution of malicious files, whether an .hta application, javascript, or VBScript.\
The searches in this story help you detect and investigate suspicious activity that may indicate that an attacker is leveraging mshta.exe to execute malicious code.\
Triage\
Validate execution \
1. Determine if MSHTA.exe executed. Validate the OriginalFileName of MSHTA.exe and further PE metadata. If executed outside of c:\windows\system32 or c:\windows\syswow64, it should be highly suspect.\
1. Determine if script code was executed with MSHTA.\
Situational Awareness\
The objective of this step is meant to identify suspicious behavioral indicators related to executed of Script code by MSHTA.exe.\
1. Parent process. Is the parent process a known LOLBin? Is the parent process an Office Application?\
1. Module loads. Are the known MSHTA.exe modules being loaded by a non-standard application? Is MSHTA loading any suspicious .DLLs?\
1. Network connections. Any network connections? Review the reputation of the remote IP or domain.\
Retrieval of script code\
The objective of this step is to confirm the executed script code is benign or malicious.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Detect MSHTA Url in Command Line](/endpoint/9b3af1e6-5b68-11eb-ae93-0242ac130002/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Mshta](/tags/#mshta) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Prohibited Applications Spawning cmd exe](/endpoint/dcfd6b40-42f9-469d-a433-2e53f7486664/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [Windows Command Shell](/tags/#windows-command-shell) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Rundll32 Inline HTA Execution](/endpoint/91c79f14-5b41-11eb-ae93-0242ac130002/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Mshta](/tags/#mshta) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect mshta inline hta execution](/endpoint/a0873b32-5b68-11eb-ae93-0242ac130002/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Mshta](/tags/#mshta) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect mshta renamed](/endpoint/8f45fcf0-5b68-11eb-ae93-0242ac130002/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Mshta](/tags/#mshta) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Registry Keys Used For Persistence](/endpoint/f5f6af30-7aa7-4295-bfe9-07fe87c01a4b/) | [Registry Run Keys / Startup Folder](/tags/#registry-run-keys-/-startup-folder), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious mshta child process](/endpoint/60023bb6-5500-11eb-ae93-0242ac130002/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Mshta](/tags/#mshta) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious mshta spawn](/endpoint/4d33a488-5b5f-11eb-ae93-0242ac130002/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Mshta](/tags/#mshta) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows MSHTA Child Process](/endpoint/f63f7e9c-9526-11ec-9fc7-acde48001122/) | [Mshta](/tags/#mshta), [System Binary Proxy Execution](/tags/#system-binary-proxy-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows MSHTA Command-Line URL](/endpoint/9b35c538-94ef-11ec-9439-acde48001122/) | [Mshta](/tags/#mshta), [System Binary Proxy Execution](/tags/#system-binary-proxy-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows MSHTA Inline HTA Execution](/endpoint/24962154-9524-11ec-9333-acde48001122/) | [Mshta](/tags/#mshta), [System Binary Proxy Execution](/tags/#system-binary-proxy-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Rundll32 Inline HTA Execution](/endpoint/0caa1dd6-94f5-11ec-9786-acde48001122/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Mshta](/tags/#mshta) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://redcanary.com/blog/introducing-atomictestharnesses/](https://redcanary.com/blog/introducing-atomictestharnesses/)
* [https://redcanary.com/blog/windows-registry-attacks-threat-detection/](https://redcanary.com/blog/windows-registry-attacks-threat-detection/)
* [https://attack.mitre.org/techniques/T1218/005/](https://attack.mitre.org/techniques/T1218/005/)
* [https://medium.com/@mbromileyDFIR/malware-monday-aebb456356c5](https://medium.com/@mbromileyDFIR/malware-monday-aebb456356c5)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/suspicious_mshta_activity.yml) \| *version*: **2**