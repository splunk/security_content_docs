---
title: "Cobalt Strike"
last_modified_at: 2021-02-16
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

Cobalt Strike is threat emulation software. Red teams and penetration testers use Cobalt Strike to demonstrate the risk of a breach and evaluate mature security programs. Most recently, Cobalt Strike has become the choice tool by threat groups due to its ease of use and extensibility.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Endpoint_Processes](https://docs.splunk.com/Documentation/CIM/latest/User/EndpointProcesses)
- **Last Updated**: 2021-02-16
- **Author**: Michael Haag, Splunk
- **ID**: bcfd17e8-5461-400a-80a2-3b7d1459220c

#### Narrative

This Analytic Story supports you to detect Tactics, Techniques and Procedures (TTPs) from Cobalt Strike. Cobalt Strike has many ways to be enhanced by using aggressor scripts, malleable C2 profiles, default attack packages, and much more. For endpoint behavior, Cobalt Strike is most commonly identified via named pipes, spawn to processes, and DLL function names. Many additional variables are provided for in memory operation of the beacon implant. On the network, depending on the malleable C2 profile used, it is near infinite in the amount of ways to conceal the C2 traffic with Cobalt Strike. Not every query may be specific to Cobalt Strike the tool, but the methodologies and techniques used by it.\
Splunk Threat Research reviewed all publicly available instances of Malleabe C2 Profiles and generated a list of the most commonly used spawnto and pipenames.\
`Spawnto_x86` and `spawnto_x64` is the process that Cobalt Strike will spawn and injects shellcode into.\
Pipename sets the named pipe name used in Cobalt Strikes Beacon SMB C2 traffic.\
With that, new detections were generated focused on these spawnto processes spawning without command line arguments. Similar, the named pipes most commonly used by Cobalt Strike added as a detection. In generating content for Cobalt Strike, the following is considered:\
- Is it normal for spawnto_ value to have no command line arguments? No command line arguments and a network connection?\
- What is the default, or normal, process lineage for spawnto_ value?\
- Does the spawnto_ value make network connections?\
- Is it normal for spawnto_ value to load jscript, vbscript, Amsi.dll, and clr.dll?\
While investigating a detection related to this Analytic Story, keep in mind the parent process, process path, and any file modifications that may occur. Tuning may need to occur to remove any false positives.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Anomalous usage of 7zip](/endpoint/9364ee8e-a39a-11eb-8f1d-acde48001122/) | [Archive via Utility](/tags/#archive-via-utility), [Archive Collected Data](/tags/#archive-collected-data) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Anomalous usage of Archive Tools](/endpoint/63614a58-10e2-4c6c-ae81-ea1113681439/) | [Archive via Utility](/tags/#archive-via-utility), [Archive Collected Data](/tags/#archive-collected-data) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [CMD Echo Pipe - Escalation](/endpoint/eb277ba0-b96b-11eb-b00e-acde48001122/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [Windows Command Shell](/tags/#windows-command-shell), [Windows Service](/tags/#windows-service), [Create or Modify System Process](/tags/#create-or-modify-system-process) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Cobalt Strike Named Pipes](/endpoint/5876d429-0240-4709-8b93-ea8330b411b5/) | [Process Injection](/tags/#process-injection) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [DLLHost with no Command Line Arguments with Network](/endpoint/f1c07594-a141-11eb-8407-acde48001122/) | [Process Injection](/tags/#process-injection) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Regsvr32 Application Control Bypass](/endpoint/070e9b80-6252-11eb-ae93-0242ac130002/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Regsvr32](/tags/#regsvr32) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GPUpdate with no Command Line Arguments with Network](/endpoint/2c853856-a140-11eb-a5b5-acde48001122/) | [Process Injection](/tags/#process-injection) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Rundll32 with no Command Line Arguments with Network](/endpoint/35307032-a12d-11eb-835f-acde48001122/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Rundll32](/tags/#rundll32) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [SearchProtocolHost with no Command Line with Network](/endpoint/b690df8c-a145-11eb-a38b-acde48001122/) | [Process Injection](/tags/#process-injection) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Services Escalate Exe](/endpoint/c448488c-b7ec-11eb-8253-acde48001122/) | [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious DLLHost no Command Line Arguments](/endpoint/ff61e98c-0337-4593-a78f-72a676c56f26/) | [Process Injection](/tags/#process-injection) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious GPUpdate no Command Line Arguments](/endpoint/f308490a-473a-40ef-ae64-dd7a6eba284a/) | [Process Injection](/tags/#process-injection) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious MSBuild Rename](/endpoint/4006adac-5937-11eb-ae93-0242ac130002/) | [Masquerading](/tags/#masquerading), [Trusted Developer Utilities Proxy Execution](/tags/#trusted-developer-utilities-proxy-execution), [Rename System Utilities](/tags/#rename-system-utilities), [MSBuild](/tags/#msbuild) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Rundll32 StartW](/endpoint/9319dda5-73f2-4d43-a85a-67ce961bddb7/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Rundll32](/tags/#rundll32) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Rundll32 no Command Line Arguments](/endpoint/e451bd16-e4c5-4109-8eb1-c4c6ecf048b4/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Rundll32](/tags/#rundll32) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious SearchProtocolHost no Command Line Arguments](/endpoint/f52d2db8-31f9-4aa7-a176-25779effe55c/) | [Process Injection](/tags/#process-injection) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious microsoft workflow compiler rename](/endpoint/f0db4464-55d9-11eb-ae93-0242ac130002/) | [Masquerading](/tags/#masquerading), [Trusted Developer Utilities Proxy Execution](/tags/#trusted-developer-utilities-proxy-execution), [Rename System Utilities](/tags/#rename-system-utilities) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious msbuild path](/endpoint/f5198224-551c-11eb-ae93-0242ac130002/) | [Masquerading](/tags/#masquerading), [Trusted Developer Utilities Proxy Execution](/tags/#trusted-developer-utilities-proxy-execution), [Rename System Utilities](/tags/#rename-system-utilities), [MSBuild](/tags/#msbuild) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://www.cobaltstrike.com/](https://www.cobaltstrike.com/)
* [https://www.infocyte.com/blog/2020/09/02/cobalt-strike-the-new-favorite-among-thieves/](https://www.infocyte.com/blog/2020/09/02/cobalt-strike-the-new-favorite-among-thieves/)
* [https://bluescreenofjeff.com/2017-01-24-how-to-write-malleable-c2-profiles-for-cobalt-strike/](https://bluescreenofjeff.com/2017-01-24-how-to-write-malleable-c2-profiles-for-cobalt-strike/)
* [https://blog.talosintelligence.com/2020/09/coverage-strikes-back-cobalt-strike-paper.html](https://blog.talosintelligence.com/2020/09/coverage-strikes-back-cobalt-strike-paper.html)
* [https://www.fireeye.com/blog/threat-research/2020/12/unauthorized-access-of-fireeye-red-team-tools.html](https://www.fireeye.com/blog/threat-research/2020/12/unauthorized-access-of-fireeye-red-team-tools.html)
* [https://github.com/MichaelKoczwara/Awesome-CobaltStrike-Defence](https://github.com/MichaelKoczwara/Awesome-CobaltStrike-Defence)
* [https://github.com/zer0yu/Awesome-CobaltStrike](https://github.com/zer0yu/Awesome-CobaltStrike)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/cobalt_strike.yml) \| *version*: **1**