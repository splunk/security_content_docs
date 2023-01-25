---
title: "IIS Components"
last_modified_at: 2022-12-19
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

Adversaries may install malicious components that run on Internet Information Services (IIS) web servers to establish persistence.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-12-19
- **Author**: Michael Haag, Splunk
- **ID**: 0fbde550-8252-43ab-a26a-03976f55b58b

#### Narrative

IIS provides several mechanisms to extend the functionality of the web servers. For example, Internet Server Application Programming Interface (ISAPI) extensions and filters can be installed to examine and/or modify incoming and outgoing IIS web requests. Extensions and filters are deployed as DLL files that export three functions - Get{Extension/Filter}Version, Http{Extension/Filter}Proc, and (optionally) Terminate{Extension/Filter}. IIS modules may also be installed to extend IIS web servers.\
Adversaries may install malicious ISAPI extensions and filters to observe and/or modify traffic, execute commands on compromised machines, or proxy command and control traffic. ISAPI extensions and filters may have access to all IIS web requests and responses. For example, an adversary may abuse these mechanisms to modify HTTP responses in order to distribute malicious commands/content to previously comprised hosts.\
Adversaries may also install malicious IIS modules to observe and/or modify traffic. IIS 7.0 introduced modules that provide the same unrestricted access to HTTP requests and responses as ISAPI extensions and filters. IIS modules can be written as a DLL that exports RegisterModule, or as a .NET application that interfaces with ASP.NET APIs to access IIS HTTP requests. (reference MITRE)

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Windows Disable Windows Event Logging Disable HTTP Logging](/endpoint/23fb6787-255f-4d5b-9a66-9fd7504032b5/) | [Disable Windows Event Logging](/tags/#disable-windows-event-logging), [Impair Defenses](/tags/#impair-defenses), [Server Software Component](/tags/#server-software-component), [IIS Components](/tags/#iis-components) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows IIS Components Add New Module](/endpoint/38fe731c-1f13-43d4-b878-a5bbe44807e3/) | [Server Software Component](/tags/#server-software-component), [IIS Components](/tags/#iis-components) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows IIS Components Get-WebGlobalModule Module Query](/endpoint/20db5f70-34b4-4e83-8926-fa26119de173/) | [IIS Components](/tags/#iis-components), [Server Software Component](/tags/#server-software-component) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows IIS Components Module Failed to Load](/endpoint/40c2ba5b-dd6a-496b-9e6e-c9524d0be167/) | [Server Software Component](/tags/#server-software-component), [IIS Components](/tags/#iis-components) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows IIS Components New Module Added](/endpoint/55f22929-cfd3-4388-ba5c-4d01fac7ee7e/) | [Server Software Component](/tags/#server-software-component), [IIS Components](/tags/#iis-components) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows PowerShell Add Module to Global Assembly Cache](/endpoint/3fc16961-97e5-4a5b-a079-e4ab0d9763eb/) | [Server Software Component](/tags/#server-software-component), [IIS Components](/tags/#iis-components) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows PowerShell Disable HTTP Logging](/endpoint/27958de0-2857-43ca-9d4c-b255cf59dcab/) | [Impair Defenses](/tags/#impair-defenses), [Disable Windows Event Logging](/tags/#disable-windows-event-logging), [Server Software Component](/tags/#server-software-component), [IIS Components](/tags/#iis-components) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows PowerShell IIS Components WebGlobalModule Usage](/endpoint/33fc9f6f-0ce7-4696-924e-a69ec61a3d57/) | [Server Software Component](/tags/#server-software-component), [IIS Components](/tags/#iis-components) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Server Software Component GACUtil Install to GAC](/endpoint/7c025ef0-9e65-4c57-be39-1c13dbb1613e/) | [Server Software Component](/tags/#server-software-component), [IIS Components](/tags/#iis-components) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://www.microsoft.com/en-us/security/blog/2022/12/12/iis-modules-the-evolution-of-web-shells-and-how-to-detect-them/](https://www.microsoft.com/en-us/security/blog/2022/12/12/iis-modules-the-evolution-of-web-shells-and-how-to-detect-them/)
* [https://attack.mitre.org/techniques/T1505/004/](https://attack.mitre.org/techniques/T1505/004/)
* [https://www.crowdstrike.com/wp-content/uploads/2022/05/crowdstrike-iceapple-a-novel-internet-information-services-post-exploitation-framework-1.pdf](https://www.crowdstrike.com/wp-content/uploads/2022/05/crowdstrike-iceapple-a-novel-internet-information-services-post-exploitation-framework-1.pdf)
* [https://unit42.paloaltonetworks.com/unit42-oilrig-uses-rgdoor-iis-backdoor-targets-middle-east/](https://unit42.paloaltonetworks.com/unit42-oilrig-uses-rgdoor-iis-backdoor-targets-middle-east/)
* [https://www.secureworks.com/research/bronze-union](https://www.secureworks.com/research/bronze-union)
* [https://strontic.github.io/xcyclopedia/library/appcmd.exe-055B2B09409F980BF9B5A3969D01E5B2.html](https://strontic.github.io/xcyclopedia/library/appcmd.exe-055B2B09409F980BF9B5A3969D01E5B2.html)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/iis_components.yml) \| *version*: **1**