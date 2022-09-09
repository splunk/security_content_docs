---
title: "Unusual Processes"
last_modified_at: 2020-02-04
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

Quickly identify systems running new or unusual processes in your environment that could be indicators of suspicious activity. Processes run from unusual locations, those with conspicuously long command lines, and rare executables are all examples of activities that may warrant deeper investigation.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Endpoint_Processes](https://docs.splunk.com/Documentation/CIM/latest/User/EndpointProcesses)
- **Last Updated**: 2020-02-04
- **Author**: Bhavin Patel, Splunk
- **ID**: f4368e3f-d59f-4192-84f6-748ac5a3ddb6

#### Narrative

Being able to profile a host's processes within your environment can help you more quickly identify processes that seem out of place when compared to the rest of the population of hosts or asset types.\
This Analytic Story lets you identify processes that are either a) not typically seen running or b) have some sort of suspicious command-line arguments associated with them. This Analytic Story will also help you identify the user running these processes and the associated process activity on the host.\
In the event an unusual process is identified, it is imperative to better understand how that process was able to execute on the host, when it first executed, and whether other hosts are affected. This extra information may provide clues that can help the analyst further investigate any suspicious activity.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Attacker Tools On Endpoint](/endpoint/a51bfe1a-94f0-48cc-b4e4-16a110145893/) | [Match Legitimate Name or Location](/tags/#match-legitimate-name-or-location), [Masquerading](/tags/#masquerading), [OS Credential Dumping](/tags/#os-credential-dumping), [Active Scanning](/tags/#active-scanning) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Credential ExtractionFGDump and CacheDump](/deprecated/3c40b0ef-a03f-460a-9484-e4b9117cbb38/) | [OS Credential Dumping](/tags/#os-credential-dumping), [Security Account Manager](/tags/#security-account-manager) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Rare Executables](/endpoint/44fddcb2-8d3b-454c-874e-7c6de5a4f7ac/) |  | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect processes used for System Network Configuration Discovery](/endpoint/a51bfe1a-94f0-48cc-b1e4-16ae10145893/) | [System Network Configuration Discovery](/tags/#system-network-configuration-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [First time seen command line argument](/endpoint/fc0edc95-ff2b-48b0-9f6f-63da3789fd23/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [Indirect Command Execution](/tags/#indirect-command-execution) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Rare Parent-Child Process Relationship](/endpoint/cf090c78-bcc6-11eb-8529-0242ac130003/) | [Exploitation for Client Execution](/tags/#exploitation-for-client-execution), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [Scheduled Task/Job](/tags/#scheduled-task/job), [Software Deployment Tools](/tags/#software-deployment-tools) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [RunDLL Loading DLL By Ordinal](/endpoint/6c135f8d-5e60-454e-80b7-c56eed739833/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Rundll32](/tags/#rundll32) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Rundll32 Shimcache Flush](/endpoint/a913718a-25b6-11ec-96d3-acde48001122/) | [Modify Registry](/tags/#modify-registry) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Copy on System32](/endpoint/ce633e56-25b2-11ec-9e76-acde48001122/) | [Rename System Utilities](/tags/#rename-system-utilities), [Masquerading](/tags/#masquerading) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [System Processes Run From Unexpected Locations](/endpoint/a34aae96-ccf8-4aef-952c-3ea21444444d/) | [Masquerading](/tags/#masquerading), [Rename System Utilities](/tags/#rename-system-utilities) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Uncommon Processes On Endpoint](/deprecated/29ccce64-a10c-4389-a45f-337cb29ba1f7/) | [Malicious File](/tags/#malicious-file) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Unusual LOLBAS in short period of time](/deprecated/59c0dd70-169c-4900-9a1f-bfcf13302f93/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [Scheduled Task/Job](/tags/#scheduled-task/job) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Unusually Long Command Line](/endpoint/c77162d3-f93c-45cc-80c8-22f6a4264e7f/) |  | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Unusually Long Command Line](/deprecated/58f43aba-1775-445e-b19c-be2b87d83ae3/) |  | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Unusually Long Command Line - MLTK](/endpoint/57edaefa-a73b-45e5-bbae-f39c1473f941/) |  | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Verclsid CLSID Execution](/endpoint/61e9a56a-20fa-11ec-8ba3-acde48001122/) | [Verclsid](/tags/#verclsid), [System Binary Proxy Execution](/tags/#system-binary-proxy-execution) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [WinRM Spawning a Process](/endpoint/a081836a-ba4d-11eb-8593-acde48001122/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows DotNet Binary in Non Standard Path](/endpoint/fddf3b56-7933-11ec-98a6-acde48001122/) | [Masquerading](/tags/#masquerading), [Rename System Utilities](/tags/#rename-system-utilities), [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [InstallUtil](/tags/#installutil) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows DotNet Binary in Non Standard Path](/endpoint/21179107-099a-324a-94d3-08301e6c065f/) | [Masquerading](/tags/#masquerading), [Rename System Utilities](/tags/#rename-system-utilities), [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [InstallUtil](/tags/#installutil) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows InstallUtil in Non Standard Path](/endpoint/dcf74b22-7933-11ec-857c-acde48001122/) | [Masquerading](/tags/#masquerading), [Rename System Utilities](/tags/#rename-system-utilities), [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [InstallUtil](/tags/#installutil) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows LOLBin Binary in Non Standard Path](/endpoint/25689101-012a-324a-94d3-08301e6c065a/) | [Masquerading](/tags/#masquerading), [Rename System Utilities](/tags/#rename-system-utilities), [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [InstallUtil](/tags/#installutil) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows NirSoft AdvancedRun](/endpoint/bb4f3090-7ae4-11ec-897f-acde48001122/) | [Tool](/tags/#tool) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Remote Assistance Spawning Process](/endpoint/ced50492-8849-11ec-9f68-acde48001122/) | [Process Injection](/tags/#process-injection) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Wscript Or Cscript Suspicious Child Process](/endpoint/1f35e1da-267b-11ec-90a9-acde48001122/) | [Process Injection](/tags/#process-injection), [Create or Modify System Process](/tags/#create-or-modify-system-process), [Parent PID Spoofing](/tags/#parent-pid-spoofing), [Access Token Manipulation](/tags/#access-token-manipulation) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://web.archive.org/web/20210921093439/https://www.fireeye.com/blog/threat-research/2017/08/monitoring-windows-console-activity-part-two.html](https://web.archive.org/web/20210921093439/https://www.fireeye.com/blog/threat-research/2017/08/monitoring-windows-console-activity-part-two.html)
* [https://www.splunk.com/pdfs/technical-briefs/advanced-threat-detection-and-response-tech-brief.pdf](https://www.splunk.com/pdfs/technical-briefs/advanced-threat-detection-and-response-tech-brief.pdf)
* [https://www.sans.org/reading-room/whitepapers/logging/detecting-security-incidents-windows-workstation-event-logs-34262](https://www.sans.org/reading-room/whitepapers/logging/detecting-security-incidents-windows-workstation-event-logs-34262)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/unusual_processes.yml) \| *version*: **2**