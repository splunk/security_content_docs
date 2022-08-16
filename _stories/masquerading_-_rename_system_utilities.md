---
title: "Masquerading - Rename System Utilities"
last_modified_at: 2021-04-26
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

Adversaries may rename legitimate system utilities to try to evade security mechanisms concerning the usage of those utilities.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Endpoint_Processes](https://docs.splunk.com/Documentation/CIM/latest/User/EndpointProcesses)
- **Last Updated**: 2021-04-26
- **Author**: Michael Haag, Splunk
- **ID**: f0258af4-a6ae-11eb-b3c2-acde48001122

#### Narrative

Security monitoring and control mechanisms may be in place for system utilities adversaries are capable of abusing. It may be possible to bypass those security mechanisms by renaming the utility prior to utilization (ex: rename rundll32.exe). An alternative case occurs when a legitimate utility is copied or moved to a different directory and renamed to avoid detections based on system utilities executing from non-standard paths.\
The following content is here to assist with binaries within `system32` or `syswow64` being moved to a new location or an adversary bringing a the binary in to execute.\
There will be false positives as some native Windows processes are moved or ran by third party applications from different paths. If file names are mismatched between the file name on disk and that of the binarys PE metadata, this is a likely indicator that a binary was renamed after it was compiled. Collecting and comparing disk and resource filenames for binaries by looking to see if the InternalName, OriginalFilename, and or ProductName match what is expected could provide useful leads, but may not always be indicative of malicious activity. Do not focus on the possible names a file could have, but instead on the command-line arguments that are known to be used and are distinct because it will have a better rate of detection.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Execution of File With Spaces Before Extension](/deprecated/ab0353e6-a956-420b-b724-a8b4846d5d5a/) | [Rename System Utilities](/tags/#rename-system-utilities) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Execution of File with Multiple Extensions](/endpoint/b06a555e-dce0-417d-a2eb-28a5d8d66ef7/) | [Masquerading](/tags/#masquerading), [Rename System Utilities](/tags/#rename-system-utilities) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Sdelete Application Execution](/endpoint/31702fc0-2682-11ec-85c3-acde48001122/) | [Data Destruction](/tags/#data-destruction), [File Deletion](/tags/#file-deletion), [Indicator Removal on Host](/tags/#indicator-removal-on-host) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious MSBuild Rename](/endpoint/4006adac-5937-11eb-ae93-0242ac130002/) | [Masquerading](/tags/#masquerading), [Trusted Developer Utilities Proxy Execution](/tags/#trusted-developer-utilities-proxy-execution), [Rename System Utilities](/tags/#rename-system-utilities), [MSBuild](/tags/#msbuild) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Rundll32 Rename](/deprecated/7360137f-abad-473e-8189-acbdaa34d114/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Masquerading](/tags/#masquerading), [Rundll32](/tags/#rundll32), [Rename System Utilities](/tags/#rename-system-utilities) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious microsoft workflow compiler rename](/endpoint/f0db4464-55d9-11eb-ae93-0242ac130002/) | [Masquerading](/tags/#masquerading), [Trusted Developer Utilities Proxy Execution](/tags/#trusted-developer-utilities-proxy-execution), [Rename System Utilities](/tags/#rename-system-utilities) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious msbuild path](/endpoint/f5198224-551c-11eb-ae93-0242ac130002/) | [Masquerading](/tags/#masquerading), [Trusted Developer Utilities Proxy Execution](/tags/#trusted-developer-utilities-proxy-execution), [Rename System Utilities](/tags/#rename-system-utilities), [MSBuild](/tags/#msbuild) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [System Process Running from Unexpected Location](/endpoint/28179107-099a-464a-94d3-08301e6c055f/) | [Masquerading](/tags/#masquerading) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [System Processes Run From Unexpected Locations](/endpoint/a34aae96-ccf8-4aef-952c-3ea21444444d/) | [Masquerading](/tags/#masquerading), [Rename System Utilities](/tags/#rename-system-utilities) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows DotNet Binary in Non Standard Path](/endpoint/fddf3b56-7933-11ec-98a6-acde48001122/) | [Masquerading](/tags/#masquerading), [Rename System Utilities](/tags/#rename-system-utilities), [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [InstallUtil](/tags/#installutil) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows DotNet Binary in Non Standard Path](/endpoint/21179107-099a-324a-94d3-08301e6c065f/) | [Masquerading](/tags/#masquerading), [Rename System Utilities](/tags/#rename-system-utilities), [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [InstallUtil](/tags/#installutil) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows InstallUtil in Non Standard Path](/endpoint/dcf74b22-7933-11ec-857c-acde48001122/) | [Masquerading](/tags/#masquerading), [Rename System Utilities](/tags/#rename-system-utilities), [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [InstallUtil](/tags/#installutil) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://attack.mitre.org/techniques/T1036/003/](https://attack.mitre.org/techniques/T1036/003/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/masquerading___rename_system_utilities.yml) \| *version*: **1**