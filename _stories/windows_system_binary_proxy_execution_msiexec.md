---
title: "Windows System Binary Proxy Execution MSIExec"
last_modified_at: 2022-06-16
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

Adversaries may abuse msiexec.exe to proxy execution of malicious payloads. Msiexec.exe is the command-line utility for the Windows Installer and is thus commonly associated with executing installation packages (.msi).

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic)
- **Last Updated**: 2022-06-16
- **Author**: Michael Haag, Splunk
- **ID**: bea2e16b-4599-46ad-a95b-116078726c68

#### Narrative

Adversaries may abuse msiexec.exe to launch local or network accessible MSI files. Msiexec.exe can also execute DLLs. Since it may be signed and native on Windows systems, msiexec.exe can be used to bypass application control solutions that do not account for its potential abuse. Msiexec.exe execution may also be elevated to SYSTEM privileges if the AlwaysInstallElevated policy is enabled.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Windows MSIExec DLLRegisterServer](/endpoint/fdb59aef-d88f-4909-8369-ec2afbd2c398/) | [Msiexec](/tags/#msiexec) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows MSIExec Remote Download](/endpoint/6aa49ff2-3c92-4586-83e0-d83eb693dfda/) | [Msiexec](/tags/#msiexec) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows MSIExec Spawn Discovery Command](/endpoint/e9d05aa2-32f0-411b-930c-5b8ca5c4fcee/) | [Msiexec](/tags/#msiexec) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows MSIExec Unregister DLLRegisterServer](/endpoint/a27db3c5-1a9a-46df-a577-765d3f1a3c24/) | [Msiexec](/tags/#msiexec) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows MSIExec With Network Connections](/endpoint/827409a1-5393-4d8d-8da4-bbb297c262a7/) | [Msiexec](/tags/#msiexec) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows System Binary Proxy Execution MSIExec DLLRegisterServer](/endpoint/8d1d5570-722c-49a3-996c-2e2cceef5163/) | [Msiexec](/tags/#msiexec) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows System Binary Proxy Execution MSIExec Remote Download](/endpoint/92cbbf0f-9a6b-4e9d-8c35-cc9244a4e3d5/) | [Msiexec](/tags/#msiexec) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows System Binary Proxy Execution MSIExec Unregister DLL](/endpoint/df76a8d1-92e1-4ec9-b8f7-695b5838703e/) | [Msiexec](/tags/#msiexec) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://attack.mitre.org/techniques/T1218/007/](https://attack.mitre.org/techniques/T1218/007/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/windows_system_binary_proxy_execution_msiexec.yml) \| *version*: **1**