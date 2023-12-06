---
title: "PlugX"
last_modified_at: 2023-10-12
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

PlugX, also referred to as "PlugX RAT" or "Kaba," is a highly sophisticated remote access Trojan (RAT) discovered in 2012. This malware is notorious for its involvement in targeted cyberattacks, primarily driven by cyber espionage objectives. PlugX provides attackers with comprehensive remote control capabilities over compromised systems, granting them the ability to execute commands, collect sensitive data, and manipulate the infected host.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2023-10-12
- **Author**: Teoderick Contreras, Splunk
- **ID**: a2c94c99-b93b-4bc7-a749-e2198743d0d6

#### Narrative

PlugX, known as the "silent infiltrator of the digital realm, is a shadowy figure in the world of cyber threats. This remote access Trojan (RAT), first unveiled in 2012, is not your run-of-the-mill malware. It's the go-to tool for sophisticated hackers with one goal in mind, espionage. PlugX's repertoire of capabilities reads like a spy thriller. It doesn't just breach your defenses; it goes a step further, slipping quietly into your systems, much like a ghost. Once inside, it opens the door to a world of possibilities for cybercriminals. With a few keystrokes, they can access your data, capture your screen, and silently watch your every move. In the hands of skilled hackers, it's a versatile instrument for cyber espionage. This malware thrives on persistence. It's not a one-time hit; it's in it for the long haul. Even if you reboot your system, PlugX remains, ensuring that its grip on your infrastructure doesn't waver.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Allow Inbound Traffic By Firewall Rule Registry](/endpoint/0a46537c-be02-11eb-92ca-acde48001122/) | [Remote Desktop Protocol](/tags/#remote-desktop-protocol), [Remote Services](/tags/#remote-services) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [CMD Carry Out String Command Parameter](/endpoint/54a6ed00-3256-11ec-b031-acde48001122/) | [Windows Command Shell](/tags/#windows-command-shell), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Executables Or Script Creation In Suspicious Path](/endpoint/a7e3f0f0-ae42-11eb-b245-acde48001122/) | [Masquerading](/tags/#masquerading) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Firewall Allowed Program Enable](/endpoint/9a8f63a8-43ac-11ec-904c-acde48001122/) | [Disable or Modify System Firewall](/tags/#disable-or-modify-system-firewall), [Impair Defenses](/tags/#impair-defenses) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Network Connection Discovery With Netstat](/endpoint/2cf5cc25-f39a-436d-a790-4857e5995ede/) | [System Network Connections Discovery](/tags/#system-network-connections-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Office Application Drop Executable](/endpoint/73ce70c4-146d-11ec-9184-acde48001122/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Office Document Executing Macro Code](/endpoint/b12c89bc-9d06-11eb-a592-acde48001122/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Office Document Spawned Child Process To Download](/endpoint/6fed27d2-9ec7-11eb-8fe4-aa665a019aa3/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Office Product Spawn CMD Process](/endpoint/b8b19420-e892-11eb-9244-acde48001122/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Process File Path](/endpoint/9be25988-ad82-11eb-a14f-acde48001122/) | [Create or Modify System Process](/tags/#create-or-modify-system-process) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious writes to windows Recycle Bin](/endpoint/b5541828-8ffd-4070-9d95-b3da4de924cb/) | [Masquerading](/tags/#masquerading) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Access Token Manipulation SeDebugPrivilege](/endpoint/6ece9ed0-5f92-4315-889d-48560472b188/) | [Create Process with Token](/tags/#create-process-with-token), [Access Token Manipulation](/tags/#access-token-manipulation) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Masquerading Msdtc Process](/endpoint/238f3a07-8440-480b-b26f-462f41d9a47c/) | [Masquerading](/tags/#masquerading) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Replication Through Removable Media](/endpoint/60df805d-4605-41c8-bbba-57baa6a4eb97/) | [Replication Through Removable Media](/tags/#replication-through-removable-media) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Service Created with Suspicious Service Path](/endpoint/429141be-8311-11eb-adb6-acde48001122/) | [System Services](/tags/#system-services), [Service Execution](/tags/#service-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Service Creation Using Registry Entry](/endpoint/25212358-948e-11ec-ad47-acde48001122/) | [Services Registry Permissions Weakness](/tags/#services-registry-permissions-weakness) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Service Deletion In Registry](/endpoint/daed6823-b51c-4843-a6ad-169708f1323e/) | [Service Stop](/tags/#service-stop) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://malpedia.caad.fkie.fraunhofer.de/details/win.plugx](https://malpedia.caad.fkie.fraunhofer.de/details/win.plugx)
* [https://blog.sekoia.io/my-teas-not-cold-an-overview-of-china-cyber-threat/](https://blog.sekoia.io/my-teas-not-cold-an-overview-of-china-cyber-threat/)
* [https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/carderbee-software-supply-chain-certificate-abuse](https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/carderbee-software-supply-chain-certificate-abuse)
* [https://go.recordedfuture.com/hubfs/reports/cta-2023-0808.pdf](https://go.recordedfuture.com/hubfs/reports/cta-2023-0808.pdf)
* [https://www.mandiant.com/resources/blog/infected-usb-steal-secrets](https://www.mandiant.com/resources/blog/infected-usb-steal-secrets)
* [https://attack.mitre.org/software/S0013/](https://attack.mitre.org/software/S0013/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/plugx.yml) \| *version*: **2**