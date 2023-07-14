---
title: "Qakbot"
last_modified_at: 2022-11-14
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Risk
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

QakBot is a modular banking trojan that has been used primarily by financially-motivated actors since at least 2007. QakBot is continuously maintained and developed and has evolved from an information stealer into a delivery agent for ransomware (ref. MITRE ATT&CK).

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Risk](https://docs.splunk.com/Documentation/CIM/latest/User/Risk)
- **Last Updated**: 2022-11-14
- **Author**: Teoderick Contreras, Splunk
- **ID**: 0c6169b1-f126-4d86-8e4f-f7891007ebc6

#### Narrative

QakBot notably has made its way on the CISA top malware list for 2021. QakBot for years has been under continious improvement when it comes to initial access, injection and post-exploitation. Multiple adversaries use QakBot to gain initial access and persist, most notably TA551. The actor(s) behind QakBot possess a modular framework consisting of maldoc builders, signed loaders, and DLLs that produce initially low detection rates at the beginning of the attack, which creates opportunities to deliver additional malware such as Egregor and Cobalt Strike. (ref. Cybersecurity ATT) The more recent campaigns utilize HTML smuggling to deliver a ISO container that has a LNK and QakBot payload. QakBot will either load via regsvr32.exe directly, it will attempt to perform DLL sideloading.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [CMD Carry Out String Command Parameter](/endpoint/54a6ed00-3256-11ec-b031-acde48001122/) | [Windows Command Shell](/tags/#windows-command-shell), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Cmdline Tool Not Executed In CMD Shell](/endpoint/6c3f7dd8-153c-11ec-ac2d-acde48001122/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [JavaScript](/tags/#javascript) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Cmdline Tool Not Executed In CMD Shell](/endpoint/6c3f7dd8-153c-11ec-ac2d-acde48001122/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [JavaScript](/tags/#javascript) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Create Remote Thread In Shell Application](/endpoint/10399c1e-f51e-11eb-b920-acde48001122/) | [Process Injection](/tags/#process-injection) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disable Defender Spynet Reporting](/endpoint/898debf4-3021-11ec-ba7c-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Executables Or Script Creation In Suspicious Path](/endpoint/a7e3f0f0-ae42-11eb-b245-acde48001122/) | [Masquerading](/tags/#masquerading) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Malicious PowerShell Process - Encoded Command](/endpoint/c4db14d9-7909-48b4-a054-aa14d89dbb19/) | [Obfuscated Files or Information](/tags/#obfuscated-files-or-information) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [NLTest Domain Trust Discovery](/endpoint/c3e05466-5f22-11eb-ae93-0242ac130002/) | [Domain Trust Discovery](/tags/#domain-trust-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Network Connection Discovery With Arp](/endpoint/ae008c0f-83bd-4ed4-9350-98d4328e15d2/) | [System Network Connections Discovery](/tags/#system-network-connections-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Network Connection Discovery With Netstat](/endpoint/2cf5cc25-f39a-436d-a790-4857e5995ede/) | [System Network Connections Discovery](/tags/#system-network-connections-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Network Discovery Using Route Windows App](/endpoint/dd83407e-439f-11ec-ab8e-acde48001122/) | [System Network Configuration Discovery](/tags/#system-network-configuration-discovery), [Internet Connection Discovery](/tags/#internet-connection-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Office Application Spawn Regsvr32 process](/endpoint/2d9fc90c-f11f-11eb-9300-acde48001122/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Office Document Executing Macro Code](/endpoint/b12c89bc-9d06-11eb-a592-acde48001122/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Office Product Spawn CMD Process](/endpoint/b8b19420-e892-11eb-9244-acde48001122/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Process Creating LNK file in Suspicious Location](/endpoint/5d814af1-1041-47b5-a9ac-d754e82e9a26/) | [Phishing](/tags/#phishing), [Spearphishing Link](/tags/#spearphishing-link) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Recon AVProduct Through Pwh or WMI](/endpoint/28077620-c9f6-11eb-8785-acde48001122/) | [Gather Victim Host Information](/tags/#gather-victim-host-information) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Recon Using WMI Class](/endpoint/018c1972-ca07-11eb-9473-acde48001122/) | [Gather Victim Host Information](/tags/#gather-victim-host-information), [PowerShell](/tags/#powershell) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Registry Keys Used For Persistence](/endpoint/f5f6af30-7aa7-4295-bfe9-07fe87c01a4b/) | [Registry Run Keys / Startup Folder](/tags/#registry-run-keys-/-startup-folder), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Regsvr32 with Known Silent Switch Cmdline](/endpoint/c9ef7dc4-eeaf-11eb-b2b6-acde48001122/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Regsvr32](/tags/#regsvr32) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Scheduled Task Deleted Or Created via CMD](/endpoint/d5af132c-7c17-439c-9d31-13d55340f36c/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Schtasks Run Task On Demand](/endpoint/bb37061e-af1f-11eb-a159-acde48001122/) | [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Services LOLBAS Execution Process Spawn](/endpoint/ba9e1954-4c04-11ec-8b74-3e22fbd008af/) | [Create or Modify System Process](/tags/#create-or-modify-system-process), [Windows Service](/tags/#windows-service) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Copy on System32](/endpoint/ce633e56-25b2-11ec-9e76-acde48001122/) | [Rename System Utilities](/tags/#rename-system-utilities), [Masquerading](/tags/#masquerading) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Process File Path](/endpoint/9be25988-ad82-11eb-a14f-acde48001122/) | [Create or Modify System Process](/tags/#create-or-modify-system-process) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Regsvr32 Register Suspicious Path](/endpoint/62732736-6250-11eb-ae93-0242ac130002/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Regsvr32](/tags/#regsvr32) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [System Processes Run From Unexpected Locations](/endpoint/a34aae96-ccf8-4aef-952c-3ea21444444d/) | [Masquerading](/tags/#masquerading), [Rename System Utilities](/tags/#rename-system-utilities) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [System User Discovery With Whoami](/endpoint/894fc43e-6f50-47d5-a68b-ee9ee23e18f4/) | [System Owner/User Discovery](/tags/#system-owner/user-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Wermgr Process Spawned CMD Or Powershell Process](/endpoint/e8fc95bc-a107-11eb-a978-acde48001122/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [WinEvent Windows Task Scheduler Event Action Started](/endpoint/b3632472-310b-11ec-9aab-acde48001122/) | [Scheduled Task](/tags/#scheduled-task) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows App Layer Protocol Qakbot NamedPipe](/endpoint/63a2c15e-9448-43c5-a4a8-9852266aaada/) | [Application Layer Protocol](/tags/#application-layer-protocol) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows App Layer Protocol Wermgr Connect To NamedPipe](/endpoint/2f3a4092-548b-421c-9caa-84918e1787ef/) | [Application Layer Protocol](/tags/#application-layer-protocol) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Command Shell Fetch Env Variables](/endpoint/048839e4-1eaa-43ff-8a22-86d17f6fcc13/) | [Process Injection](/tags/#process-injection) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Common Abused Cmd Shell Risk Behavior](/endpoint/e99fcc4f-c6b0-4443-aa2a-e3c85126ec9a/) | [File and Directory Permissions Modification](/tags/#file-and-directory-permissions-modification), [System Network Connections Discovery](/tags/#system-network-connections-discovery), [System Owner/User Discovery](/tags/#system-owner/user-discovery), [System Shutdown/Reboot](/tags/#system-shutdown/reboot), [System Network Configuration Discovery](/tags/#system-network-configuration-discovery), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | [Correlation](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows DLL Search Order Hijacking Hunt with Sysmon](/endpoint/79c7d1fc-64c7-91be-a616-ccda752efe81/) | [DLL Search Order Hijacking](/tags/#dll-search-order-hijacking), [Hijack Execution Flow](/tags/#hijack-execution-flow) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows DLL Side-Loading In Calc](/endpoint/af01f6db-26ac-440e-8d89-2793e303f137/) | [DLL Side-Loading](/tags/#dll-side-loading), [Hijack Execution Flow](/tags/#hijack-execution-flow) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows DLL Side-Loading Process Child Of Calc](/endpoint/295ca9ed-e97b-4520-90f7-dfb6469902e1/) | [DLL Side-Loading](/tags/#dll-side-loading), [Hijack Execution Flow](/tags/#hijack-execution-flow) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Defender Exclusion Registry Entry](/endpoint/13395a44-4dd9-11ec-9df7-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows ISO LNK File Creation](/endpoint/d7c2c09b-9569-4a9e-a8b6-6a39a99c1d32/) | [Spearphishing Attachment](/tags/#spearphishing-attachment), [Phishing](/tags/#phishing), [Malicious Link](/tags/#malicious-link), [User Execution](/tags/#user-execution) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Masquerading Explorer As Child Process](/endpoint/61490da9-52a1-4855-a0c5-28233c88c481/) | [DLL Side-Loading](/tags/#dll-side-loading), [Hijack Execution Flow](/tags/#hijack-execution-flow) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Modify Registry Qakbot Binary Data Registry](/endpoint/2e768497-04e0-4188-b800-70dd2be0e30d/) | [Modify Registry](/tags/#modify-registry) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Phishing Recent ISO Exec Registry](/endpoint/cb38ee66-8ae5-47de-bd66-231c7bbc0b2c/) | [Spearphishing Attachment](/tags/#spearphishing-attachment), [Phishing](/tags/#phishing) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Process Injection Of Wermgr to Known Browser](/endpoint/aec755a5-3a2c-4be0-ab34-6540e68644e9/) | [Dynamic-link Library Injection](/tags/#dynamic-link-library-injection), [Process Injection](/tags/#process-injection) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Process Injection Remote Thread](/endpoint/8a618ade-ca8f-4d04-b972-2d526ba59924/) | [Process Injection](/tags/#process-injection), [Portable Executable Injection](/tags/#portable-executable-injection) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Process Injection Wermgr Child Process](/endpoint/360ae6b0-38b5-4328-9e2b-bc9436cddb17/) | [Process Injection](/tags/#process-injection) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Regsvr32 Renamed Binary](/endpoint/7349a9e9-3cf6-4171-bb0c-75607a8dcd1a/) | [Regsvr32](/tags/#regsvr32), [System Binary Proxy Execution](/tags/#system-binary-proxy-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Schtasks Create Run As System](/endpoint/41a0e58e-884c-11ec-9976-acde48001122/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Service Created with Suspicious Service Path](/endpoint/429141be-8311-11eb-adb6-acde48001122/) | [System Services](/tags/#system-services), [Service Execution](/tags/#service-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows System Discovery Using Qwinsta](/endpoint/2e765c1b-144a-49f0-93d0-1df4287cca04/) | [System Owner/User Discovery](/tags/#system-owner/user-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows System Discovery Using ldap Nslookup](/endpoint/2418780f-7c3e-4c45-b8b4-996ea850cd49/) | [System Owner/User Discovery](/tags/#system-owner/user-discovery) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows WMI Impersonate Token](/endpoint/cf192860-2d94-40db-9a51-c04a2e8a8f8b/) | [Windows Management Instrumentation](/tags/#windows-management-instrumentation) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows WMI Process Call Create](/endpoint/0661c2de-93de-11ec-9833-acde48001122/) | [Windows Management Instrumentation](/tags/#windows-management-instrumentation) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://www.cisa.gov/sites/default/files/publications/202010221030_QakBot%20TLPWHITE.pdf](https://www.cisa.gov/sites/default/files/publications/202010221030_QakBot%20TLPWHITE.pdf)
* [https://malpedia.caad.fkie.fraunhofer.de/details/win.QakBot](https://malpedia.caad.fkie.fraunhofer.de/details/win.QakBot)
* [https://securelist.com/QakBot-technical-analysis/103931/](https://securelist.com/QakBot-technical-analysis/103931/)
* [https://www.fortinet.com/blog/threat-research/new-variant-of-QakBot-spread-by-phishing-emails](https://www.fortinet.com/blog/threat-research/new-variant-of-QakBot-spread-by-phishing-emails)
* [https://attack.mitre.org/software/S0650/](https://attack.mitre.org/software/S0650/)
* [https://cybersecurity.att.com/blogs/labs-research/the-rise-of-qakbot](https://cybersecurity.att.com/blogs/labs-research/the-rise-of-qakbot)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/qakbot.yml) \| *version*: **2**