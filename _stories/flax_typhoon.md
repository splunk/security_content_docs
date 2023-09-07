---
title: "Flax Typhoon"
last_modified_at: 2023-08-25
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

Microsoft has identified a nation-state activity group, Flax Typhoon, based in China, targeting Taiwanese organizations for espionage. The group maintains long-term access to networks with minimal use of malware, relying on built-in OS tools and benign software. The group's activities are primarily focused on Taiwan, but the techniques used could be easily reused in other operations outside the region. Microsoft has not observed Flax Typhoon using this access to conduct additional actions.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2023-08-25
- **Author**: Michael Haag, Splunk
- **ID**: 78fadce9-a07f-4508-8d14-9b20052a62cc

#### Narrative

Flax Typhoon has been active since mid-2021, targeting government agencies, education, critical manufacturing, and IT organizations in Taiwan. The group uses the China Chopper web shell, Metasploit, Juicy Potato privilege escalation tool, Mimikatz, and SoftEther VPN client. However, they primarily rely on living-off-the-land techniques and hands-on-keyboard activity. Initial access is achieved by exploiting known vulnerabilities in public-facing servers and deploying web shells. Following initial access, Flax Typhoon uses command-line tools to establish persistent access over the remote desktop protocol, deploy a VPN connection to actor-controlled network infrastructure, and collect credentials from compromised systems. The group also uses this VPN access to scan for vulnerabilities on targeted systems and organizations from the compromised systems.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [BITSAdmin Download File](/endpoint/80630ff4-8e4c-11eb-aab5-acde48001122/) | [BITS Jobs](/tags/#bits-jobs), [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [CertUtil Download With URLCache and Split Arguments](/endpoint/415b4306-8bfb-11eb-85c4-acde48001122/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Webshell Exploit Behavior](/endpoint/22597426-6dbd-49bd-bcdc-4ec19857192f/) | [Server Software Component](/tags/#server-software-component), [Web Shell](/tags/#web-shell) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Dump LSASS via comsvcs DLL](/endpoint/8943b567-f14d-4ee8-a0bb-2121d4ce3184/) | [LSASS Memory](/tags/#lsass-memory), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Overwriting Accessibility Binaries](/endpoint/13c2f6c3-10c5-4deb-9ba1-7c4460ebe4ae/) | [Event Triggered Execution](/tags/#event-triggered-execution), [Accessibility Features](/tags/#accessibility-features) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [PowerShell 4104 Hunting](/endpoint/d6f2b006-0041-11ec-8885-acde48001122/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [W3WP Spawning Shell](/endpoint/0f03423c-7c6a-11eb-bc47-acde48001122/) | [Server Software Component](/tags/#server-software-component), [Web Shell](/tags/#web-shell) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Mimikatz Binary Execution](/endpoint/a9e0d6d3-9676-4e26-994d-4e0406bb4467/) | [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows SQL Spawning CertUtil](/endpoint/dfc18a5a-946e-44ee-a373-c0f60d06e676/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Service Created with Suspicious Service Path](/endpoint/429141be-8311-11eb-adb6-acde48001122/) | [System Services](/tags/#system-services), [Service Execution](/tags/#service-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://www.microsoft.com/en-us/security/blog/2023/08/24/flax-typhoon-using-legitimate-software-to-quietly-access-taiwanese-organizations/](https://www.microsoft.com/en-us/security/blog/2023/08/24/flax-typhoon-using-legitimate-software-to-quietly-access-taiwanese-organizations/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/flax_typhoon.yml) \| *version*: **1**