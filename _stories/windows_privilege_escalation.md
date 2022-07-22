---
title: "Windows Privilege Escalation"
last_modified_at: 2020-02-04
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

Monitor for and investigate activities that may be associated with a Windows privilege-escalation attack, including unusual processes running on endpoints, modified registry keys, and more.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2020-02-04
- **Author**: David Dorsey, Splunk
- **ID**: 644e22d3-598a-429c-a007-16fdb802cae5

#### Narrative

Privilege escalation is a "land-and-expand" technique, wherein an adversary gains an initial foothold on a host and then exploits its weaknesses to increase his privileges. The motivation is simple: certain actions on a Windows machine--such as installing software--may require higher-level privileges than those the attacker initially acquired. By increasing his privilege level, the attacker can gain the control required to carry out his malicious ends. This Analytic Story provides searches to detect and investigate behaviors that attackers may use to elevate their privileges in your environment.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Active Setup Registry Autostart](/endpoint/f64579c0-203f-11ec-abcc-acde48001122/) | [Active Setup](/tags/#active-setup), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Change Default File Association](/endpoint/462d17d8-1f71-11ec-ad07-acde48001122/) | [Change Default File Association](/tags/#change-default-file-association), [Event Triggered Execution](/tags/#event-triggered-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Child Processes of Spoolsv exe](/endpoint/aa0c4aeb-5b18-41c4-8c07-f1442d7599df/) | [Exploitation for Privilege Escalation](/tags/#exploitation-for-privilege-escalation) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [ETW Registry Disabled](/endpoint/8ed523ac-276b-11ec-ac39-acde48001122/) | [Indicator Blocking](/tags/#indicator-blocking), [Trusted Developer Utilities Proxy Execution](/tags/#trusted-developer-utilities-proxy-execution), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Kerberoasting spn request with RC4 encryption](/endpoint/5cc67381-44fa-4111-8a37-7a230943f027/) | [Steal or Forge Kerberos Tickets](/tags/#steal-or-forge-kerberos-tickets), [Kerberoasting](/tags/#kerberoasting) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Logon Script Event Trigger Execution](/endpoint/4c38c264-1f74-11ec-b5fa-acde48001122/) | [Boot or Logon Initialization Scripts](/tags/#boot-or-logon-initialization-scripts), [Logon Script (Windows)](/tags/#logon-script-(windows)) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [MSI Module Loaded by Non-System Binary](/endpoint/ccb98a66-5851-11ec-b91c-acde48001122/) | [DLL Side-Loading](/tags/#dll-side-loading), [Hijack Execution Flow](/tags/#hijack-execution-flow) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Overwriting Accessibility Binaries](/endpoint/13c2f6c3-10c5-4deb-9ba1-7c4460ebe4ae/) | [Event Triggered Execution](/tags/#event-triggered-execution), [Accessibility Features](/tags/#accessibility-features) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Print Processor Registry Autostart](/endpoint/1f5b68aa-2037-11ec-898e-acde48001122/) | [Print Processors](/tags/#print-processors), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Registry Keys Used For Privilege Escalation](/endpoint/c9f4b923-f8af-4155-b697-1354f5bcbc5e/) | [Image File Execution Options Injection](/tags/#image-file-execution-options-injection), [Event Triggered Execution](/tags/#event-triggered-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Runas Execution in CommandLine](/endpoint/4807e716-43a4-11ec-a0e7-acde48001122/) | [Access Token Manipulation](/tags/#access-token-manipulation), [Token Impersonation/Theft](/tags/#token-impersonation/theft) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Screensaver Event Trigger Execution](/endpoint/58cea3ec-1f6d-11ec-8560-acde48001122/) | [Event Triggered Execution](/tags/#event-triggered-execution), [Screensaver](/tags/#screensaver) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Time Provider Persistence Registry](/endpoint/5ba382c4-2105-11ec-8d8f-acde48001122/) | [Time Providers](/tags/#time-providers), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Uncommon Processes On Endpoint](/deprecated/29ccce64-a10c-4389-a45f-337cb29ba1f7/) | [Malicious File](/tags/#malicious-file) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/windows_privilege_escalation.yml) \| *version*: **2**