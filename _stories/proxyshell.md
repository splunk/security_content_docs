---
title: "ProxyShell"
last_modified_at: 2021-08-24
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Risk
  - Web
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

ProxyShell is a chain of exploits targeting on-premise Microsoft Exchange Server - CVE-2021-34473, CVE-2021-34523, and CVE-2021-31207.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Risk](https://docs.splunk.com/Documentation/CIM/latest/User/Risk), [Web](https://docs.splunk.com/Documentation/CIM/latest/User/Web)
- **Last Updated**: 2021-08-24
- **Author**: Michael Haag, Teoderick Contreras, Mauricio Velazco, Splunk
- **ID**: 413bb68e-04e2-11ec-a835-acde48001122

#### Narrative

During Pwn2Own April 2021, a security researcher demonstrated an attack  chain targeting on-premise Microsoft Exchange Server. August 5th, the same researcher  publicly released further details and demonstrated the attack chain. CVE-2021-34473  Pre-auth path confusion leads to ACL Bypass (Patched in April by KB5001779)  CVE-2021-34523 - Elevation of privilege on Exchange PowerShell backend (Patched in April by KB5001779) . CVE-2021-31207 - Post-auth Arbitrary-File-Write  leads to RCE (Patched in May by KB5003435) Upon successful exploitation,  the remote attacker will have SYSTEM privileges on the Exchange Server. In addition    to remote access/execution, the adversary may be able to run Exchange PowerShell  Cmdlets to perform further actions.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Detect Exchange Web Shell](/endpoint/8c14eeee-2af1-4a4b-bda8-228da0f4862a/) | [Server Software Component](/tags/#server-software-component), [Web Shell](/tags/#web-shell), [Exploit Public-Facing Application](/tags/#exploit-public-facing-application) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Exchange PowerShell Abuse via SSRF](/endpoint/29228ab4-0762-11ec-94aa-acde48001122/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Exchange PowerShell Module Usage](/endpoint/2d10095e-05ae-11ec-8fdf-acde48001122/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [MS Exchange Mailbox Replication service writing Active Server Pages](/endpoint/985f322c-57a5-11ec-b9ac-acde48001122/) | [Server Software Component](/tags/#server-software-component), [Web Shell](/tags/#web-shell), [Exploit Public-Facing Application](/tags/#exploit-public-facing-application) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [ProxyShell ProxyNotShell Behavior Detected](/web/c32fab32-6aaf-492d-bfaf-acbed8e50cdf/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application) | [Correlation](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [W3WP Spawning Shell](/endpoint/0f03423c-7c6a-11eb-bc47-acde48001122/) | [Server Software Component](/tags/#server-software-component), [Web Shell](/tags/#web-shell) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Exchange Autodiscover SSRF Abuse](/web/d436f9e7-0ee7-4a47-864b-6dea2c4e2752/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Exchange PowerShell Module Usage](/endpoint/1118bc65-b0c7-4589-bc2f-ad6802fd0909/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows MSExchange Management Mailbox Cmdlet Usage](/endpoint/396de86f-25e7-4b0e-be09-a330be35249d/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://y4y.space/2021/08/12/my-steps-of-reproducing-proxyshell/](https://y4y.space/2021/08/12/my-steps-of-reproducing-proxyshell/)
* [https://www.zerodayinitiative.com/blog/2021/8/17/from-pwn2own-2021-a-new-attack-surface-on-microsoft-exchange-proxyshell](https://www.zerodayinitiative.com/blog/2021/8/17/from-pwn2own-2021-a-new-attack-surface-on-microsoft-exchange-proxyshell)
* [https://www.youtube.com/watch?v=FC6iHw258RI](https://www.youtube.com/watch?v=FC6iHw258RI)
* [https://www.huntress.com/blog/rapid-response-microsoft-exchange-servers-still-vulnerable-to-proxyshell-exploit#what-should-you-do](https://www.huntress.com/blog/rapid-response-microsoft-exchange-servers-still-vulnerable-to-proxyshell-exploit#what-should-you-do)
* [https://i.blackhat.com/USA21/Wednesday-Handouts/us-21-ProxyLogon-Is-Just-The-Tip-Of-The-Iceberg-A-New-Attack-Surface-On-Microsoft-Exchange-Server.pdf](https://i.blackhat.com/USA21/Wednesday-Handouts/us-21-ProxyLogon-Is-Just-The-Tip-Of-The-Iceberg-A-New-Attack-Surface-On-Microsoft-Exchange-Server.pdf)
* [https://www.inversecos.com/2022/07/hunting-for-apt-abuse-of-exchange.html](https://www.inversecos.com/2022/07/hunting-for-apt-abuse-of-exchange.html)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/proxyshell.yml) \| *version*: **1**