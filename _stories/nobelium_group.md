---
title: "NOBELIUM Group"
last_modified_at: 2020-12-14
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Endpoint_Processes
  - Network_Traffic
  - Web
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Sunburst is a trojanized updates to SolarWinds Orion IT monitoring and management software. It was discovered by FireEye in December 2020. The actors behind this campaign gained access to numerous public and private organizations around the world.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Endpoint_Processes](https://docs.splunk.com/Documentation/CIM/latest/User/EndpointProcesses), [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic), [Web](https://docs.splunk.com/Documentation/CIM/latest/User/Web)
- **Last Updated**: 2020-12-14
- **Author**: Patrick Bareiss, Michael Haag, Splunk
- **ID**: 758196b5-2e21-424f-a50c-6e421ce926c2

#### Narrative

This Analytic Story supports you to detect Tactics, Techniques and Procedures (TTPs) of the NOBELIUM Group. The threat actor behind sunburst compromised the SolarWinds.Orion.Core.BusinessLayer.dll, is a SolarWinds digitally-signed component of the Orion software framework that contains a backdoor that communicates via HTTP to third party servers. The detections in this Analytic Story are focusing on the dll loading events, file create events and network events to detect This malware.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Anomalous usage of 7zip](/endpoint/9364ee8e-a39a-11eb-8f1d-acde48001122/) | [Archive via Utility](/tags/#archive-via-utility), [Archive Collected Data](/tags/#archive-collected-data) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Anomalous usage of Archive Tools](/endpoint/63614a58-10e2-4c6c-ae81-ea1113681439/) | [Archive via Utility](/tags/#archive-via-utility), [Archive Collected Data](/tags/#archive-collected-data) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Outbound SMB Traffic](/network/1bed7774-304a-4e8f-9d72-d80e45ff492b/) | [File Transfer Protocols](/tags/#file-transfer-protocols), [Application Layer Protocol](/tags/#application-layer-protocol) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Prohibited Applications Spawning cmd exe](/endpoint/dcfd6b40-42f9-469d-a433-2e53f7486664/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [Windows Command Shell](/tags/#windows-command-shell) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Rundll32 Inline HTA Execution](/endpoint/91c79f14-5b41-11eb-ae93-0242ac130002/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Mshta](/tags/#mshta) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [First Time Seen Running Windows Service](/endpoint/823136f2-d755-4b6d-ae04-372b486a5808/) | [System Services](/tags/#system-services), [Service Execution](/tags/#service-execution) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Malicious PowerShell Process - Encoded Command](/endpoint/c4db14d9-7909-48b4-a054-aa14d89dbb19/) | [Obfuscated Files or Information](/tags/#obfuscated-files-or-information) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Sc exe Manipulating Windows Services](/endpoint/f0c693d8-2a89-4ce7-80b4-98fea4c3ea6d/) | [Windows Service](/tags/#windows-service), [Create or Modify System Process](/tags/#create-or-modify-system-process) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Scheduled Task Deleted Or Created via CMD](/endpoint/d5af132c-7c17-439c-9d31-13d55340f36c/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Schtasks scheduling job on remote system](/endpoint/1297fb80-f42a-4b4a-9c8a-88c066237cf6/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Sunburst Correlation DLL and Network Event](/endpoint/701a8740-e8db-40df-9190-5516d3819787/) | [Exploitation for Client Execution](/tags/#exploitation-for-client-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Supernova Webshell](/web/2ec08a09-9ff1-4dac-b59f-1efd57972ec1/) | [Web Shell](/tags/#web-shell) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [TOR Traffic](/network/ea688274-9c06-4473-b951-e4cb7a5d7a45/) | [Application Layer Protocol](/tags/#application-layer-protocol), [Web Protocols](/tags/#web-protocols) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows AdFind Exe](/endpoint/bd3b0187-189b-46c0-be45-f52da2bae67f/) | [Remote System Discovery](/tags/#remote-system-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Rundll32 Inline HTA Execution](/endpoint/0caa1dd6-94f5-11ec-9786-acde48001122/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Mshta](/tags/#mshta) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://www.microsoft.com/security/blog/2021/03/04/goldmax-goldfinder-sibot-analyzing-nobelium-malware/](https://www.microsoft.com/security/blog/2021/03/04/goldmax-goldfinder-sibot-analyzing-nobelium-malware/)
* [https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html](https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html)
* [https://msrc-blog.microsoft.com/2020/12/13/customer-guidance-on-recent-nation-state-cyber-attacks/](https://msrc-blog.microsoft.com/2020/12/13/customer-guidance-on-recent-nation-state-cyber-attacks/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/nobelium_group.yml) \| *version*: **2**