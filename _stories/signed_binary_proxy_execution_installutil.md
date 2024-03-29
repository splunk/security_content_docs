---
title: "Signed Binary Proxy Execution InstallUtil"
last_modified_at: 2021-11-12
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Network_Traffic
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Adversaries may use InstallUtil to proxy execution of code through a trusted Windows utility.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic)
- **Last Updated**: 2021-11-12
- **Author**: Michael Haag, Splunk
- **ID**: 9482a314-43dc-11ec-a3c9-acde48001122

#### Narrative

InstallUtil is a command-line utility that allows for installation and uninstallation of resources by executing specific installer components specified in .NET binaries. InstallUtil is digitally signed by Microsoft and located in the .NET directories on a Windows system: C:\Windows\Microsoft.NET\Framework\v\InstallUtil.exe and C:\Windows\Microsoft.NET\Framework64\v\InstallUtil.exe. \
There are multiple ways to instantiate InstallUtil and they are all outlined within Atomic Red Team - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.004/T1218.004.md. Two specific ways may be used and that includes invoking via  installer assembly class constructor through .NET and via InstallUtil.exe. \
Typically, adversaries will utilize the most commonly found way to invoke via InstallUtil Uninstall method. \
Note that parallel processes, and parent process, play a role in how InstallUtil is being used. In particular, a developer using InstallUtil will spawn from VisualStudio. Adversaries, will spawn from non-standard processes like Explorer.exe, cmd.exe or PowerShell.exe. It's important to review the command-line to identify the DLL being loaded. \
Parallel processes may also include csc.exe being used to compile a local `.cs` file. This file will be the input to the output. Developers usually do not build direct on the command shell, therefore this should raise suspicion.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Windows DotNet Binary in Non Standard Path](/endpoint/fddf3b56-7933-11ec-98a6-acde48001122/) | [Masquerading](/tags/#masquerading), [Rename System Utilities](/tags/#rename-system-utilities), [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [InstallUtil](/tags/#installutil) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows DotNet Binary in Non Standard Path](/endpoint/21179107-099a-324a-94d3-08301e6c065f/) | [Masquerading](/tags/#masquerading), [Rename System Utilities](/tags/#rename-system-utilities), [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [InstallUtil](/tags/#installutil) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows InstallUtil Credential Theft](/endpoint/ccfeddec-43ec-11ec-b494-acde48001122/) | [InstallUtil](/tags/#installutil), [System Binary Proxy Execution](/tags/#system-binary-proxy-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows InstallUtil Remote Network Connection](/endpoint/4fbf9270-43da-11ec-9486-acde48001122/) | [InstallUtil](/tags/#installutil), [System Binary Proxy Execution](/tags/#system-binary-proxy-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows InstallUtil URL in Command Line](/endpoint/28e06670-43df-11ec-a569-acde48001122/) | [InstallUtil](/tags/#installutil), [System Binary Proxy Execution](/tags/#system-binary-proxy-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows InstallUtil Uninstall Option](/endpoint/cfa7b9ac-43f0-11ec-9b48-acde48001122/) | [InstallUtil](/tags/#installutil), [System Binary Proxy Execution](/tags/#system-binary-proxy-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows InstallUtil Uninstall Option with Network](/endpoint/1a52c836-43ef-11ec-a36c-acde48001122/) | [InstallUtil](/tags/#installutil), [System Binary Proxy Execution](/tags/#system-binary-proxy-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows InstallUtil in Non Standard Path](/endpoint/dcf74b22-7933-11ec-857c-acde48001122/) | [Masquerading](/tags/#masquerading), [Rename System Utilities](/tags/#rename-system-utilities), [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [InstallUtil](/tags/#installutil) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://attack.mitre.org/techniques/T1218/004/](https://attack.mitre.org/techniques/T1218/004/)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.004/T1218.004.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.004/T1218.004.md)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/signed_binary_proxy_execution_installutil.yml) \| *version*: **1**