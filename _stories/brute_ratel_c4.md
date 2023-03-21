---
title: "Brute Ratel C4"
last_modified_at: 2022-08-23
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

Leverage searches that allow you to detect and investigate unusual activities that may be related to Brute Ratel Red Teaming tool. This includes creation, modification and deletion of services, collection or data, ping IP, DNS cache, process injection, debug privileges adjustment, winlogon process duplicate token, lock workstation, get clipboard or screenshot and much more.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-08-23
- **Author**: Teoderick Contreras, Splunk
- **ID**: 0ec9dbfe-f64e-46bb-8eb8-04e92326f513

#### Narrative

Brute RATEL BRC4 is the latest red-teaming tool that simulate several TTP's. It uses several techniques like syscall, patching ETW/AMSI and written in native C to minimize noise in process command-line. This tool was seen in the wild being abused by some ransomware (blackcat) and adversaries in their campaigns to install the BRC4 agent that can serve as remote admin tool to compromise the target host or network.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Executables Or Script Creation In Suspicious Path](/endpoint/a7e3f0f0-ae42-11eb-b245-acde48001122/) | [Masquerading](/tags/#masquerading) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Modification Of Wallpaper](/endpoint/accb0712-c381-11eb-8e5b-acde48001122/) | [Defacement](/tags/#defacement) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Process File Path](/endpoint/9be25988-ad82-11eb-a14f-acde48001122/) | [Create or Modify System Process](/tags/#create-or-modify-system-process) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Access Token Manipulation SeDebugPrivilege](/endpoint/6ece9ed0-5f92-4315-889d-48560472b188/) | [Create Process with Token](/tags/#create-process-with-token), [Access Token Manipulation](/tags/#access-token-manipulation) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Access Token Manipulation Winlogon Duplicate Token Handle](/endpoint/dda126d7-1d99-4f0b-b72a-4c14031f9398/) | [Token Impersonation/Theft](/tags/#token-impersonation/theft), [Access Token Manipulation](/tags/#access-token-manipulation) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Access Token Winlogon Duplicate Handle In Uncommon Path](/endpoint/b8f7ed6b-0556-4c84-bffd-839c262b0278/) | [Token Impersonation/Theft](/tags/#token-impersonation/theft), [Access Token Manipulation](/tags/#access-token-manipulation) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Defacement Modify Transcodedwallpaper File](/endpoint/e11c3d90-5bc7-42ad-94cd-ba75db10d897/) | [Defacement](/tags/#defacement) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Gather Victim Identity SAM Info](/endpoint/a18e85d7-8b98-4399-820c-d46a1ca3516f/) | [Credentials](/tags/#credentials), [Gather Victim Identity Information](/tags/#gather-victim-identity-information) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Hijack Execution Flow Version Dll Side Load](/endpoint/8351340b-ac0e-41ec-8b07-dd01bf32d6ea/) | [DLL Search Order Hijacking](/tags/#dll-search-order-hijacking), [Hijack Execution Flow](/tags/#hijack-execution-flow) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows ISO LNK File Creation](/endpoint/d7c2c09b-9569-4a9e-a8b6-6a39a99c1d32/) | [Spearphishing Attachment](/tags/#spearphishing-attachment), [Phishing](/tags/#phishing), [Malicious Link](/tags/#malicious-link), [User Execution](/tags/#user-execution) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Input Capture Using Credential UI Dll](/endpoint/406c21d6-6c75-4e9f-9ca9-48049a1dd90e/) | [GUI Input Capture](/tags/#gui-input-capture), [Input Capture](/tags/#input-capture) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Phishing Recent ISO Exec Registry](/endpoint/cb38ee66-8ae5-47de-bd66-231c7bbc0b2c/) | [Spearphishing Attachment](/tags/#spearphishing-attachment), [Phishing](/tags/#phishing) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Process Injection With Public Source Path](/endpoint/492f09cf-5d60-4d87-99dd-0bc325532dda/) | [Process Injection](/tags/#process-injection), [Portable Executable Injection](/tags/#portable-executable-injection) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Remote Access Software BRC4 Loaded Dll](/endpoint/73cf5dcb-cf36-4167-8bbe-384fe5384d05/) | [Remote Access Software](/tags/#remote-access-software), [OS Credential Dumping](/tags/#os-credential-dumping) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Service Created with Suspicious Service Path](/endpoint/429141be-8311-11eb-adb6-acde48001122/) | [System Services](/tags/#system-services), [Service Execution](/tags/#service-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Service Creation Using Registry Entry](/endpoint/25212358-948e-11ec-ad47-acde48001122/) | [Services Registry Permissions Weakness](/tags/#services-registry-permissions-weakness) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Service Deletion In Registry](/endpoint/daed6823-b51c-4843-a6ad-169708f1323e/) | [Service Stop](/tags/#service-stop) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://unit42.paloaltonetworks.com/brute-ratel-c4-tool/](https://unit42.paloaltonetworks.com/brute-ratel-c4-tool/)
* [https://www.mdsec.co.uk/2022/08/part-3-how-i-met-your-beacon-brute-ratel/](https://www.mdsec.co.uk/2022/08/part-3-how-i-met-your-beacon-brute-ratel/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/brute_ratel_c4.yml) \| *version*: **1**