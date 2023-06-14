---
title: "ProxyNotShell"
last_modified_at: 2022-09-30
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

Two new zero day Microsoft Exchange vulnerabilities have been identified actively exploited in the wild - CVE-2022-41040 and CVE-2022-41082.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Risk](https://docs.splunk.com/Documentation/CIM/latest/User/Risk), [Web](https://docs.splunk.com/Documentation/CIM/latest/User/Web)
- **Last Updated**: 2022-09-30
- **Author**: Michael Haag, Splunk
- **ID**: 4e3f17e7-9ed7-425d-a05e-b65464945836

#### Narrative

Microsoft is investigating two reported zero-day vulnerabilities affecting Microsoft Exchange Server 2013, 2016, and 2019. The first vulnerability, identified as CVE-2022-41040, is a Server-Side Request Forgery (SSRF) vulnerability, while the second, identified as CVE-2022-41082, allows remote code execution (RCE) when PowerShell is accessible to the attacker. Originally identified by GTSC monitoring Exchange, some adversary post-exploitation activity was identified and is tagged to this story.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [CMD Carry Out String Command Parameter](/endpoint/54a6ed00-3256-11ec-b031-acde48001122/) | [Windows Command Shell](/tags/#windows-command-shell), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [CertUtil Download With URLCache and Split Arguments](/endpoint/415b4306-8bfb-11eb-85c4-acde48001122/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Exchange Web Shell](/endpoint/8c14eeee-2af1-4a4b-bda8-228da0f4862a/) | [Server Software Component](/tags/#server-software-component), [Web Shell](/tags/#web-shell), [Exploit Public-Facing Application](/tags/#exploit-public-facing-application) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Webshell Exploit Behavior](/endpoint/22597426-6dbd-49bd-bcdc-4ec19857192f/) | [Server Software Component](/tags/#server-software-component), [Web Shell](/tags/#web-shell) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Exchange PowerShell Abuse via SSRF](/endpoint/29228ab4-0762-11ec-94aa-acde48001122/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Exchange PowerShell Module Usage](/endpoint/2d10095e-05ae-11ec-8fdf-acde48001122/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [ProxyShell ProxyNotShell Behavior Detected](/web/c32fab32-6aaf-492d-bfaf-acbed8e50cdf/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application) | [Correlation](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [W3WP Spawning Shell](/endpoint/0f03423c-7c6a-11eb-bc47-acde48001122/) | [Server Software Component](/tags/#server-software-component), [Web Shell](/tags/#web-shell) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Exchange Autodiscover SSRF Abuse](/web/d436f9e7-0ee7-4a47-864b-6dea2c4e2752/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows MSExchange Management Mailbox Cmdlet Usage](/endpoint/396de86f-25e7-4b0e-be09-a330be35249d/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://msrc-blog.microsoft.com/2022/09/29/customer-guidance-for-reported-zero-day-vulnerabilities-in-microsoft-exchange-server/](https://msrc-blog.microsoft.com/2022/09/29/customer-guidance-for-reported-zero-day-vulnerabilities-in-microsoft-exchange-server/)
* [https://twitter.com/GossiTheDog/status/1575762721353916417?s=20&t=67gq9xCWuyPm1VEm8ydfyA](https://twitter.com/GossiTheDog/status/1575762721353916417?s=20&t=67gq9xCWuyPm1VEm8ydfyA)
* [https://twitter.com/cglyer/status/1575793769814728705?s=20&t=67gq9xCWuyPm1VEm8ydfyA](https://twitter.com/cglyer/status/1575793769814728705?s=20&t=67gq9xCWuyPm1VEm8ydfyA)
* [https://www.gteltsc.vn/blog/warning-new-attack-campaign-utilized-a-new-0day-rce-vulnerability-on-microsoft-exchange-server-12715.html](https://www.gteltsc.vn/blog/warning-new-attack-campaign-utilized-a-new-0day-rce-vulnerability-on-microsoft-exchange-server-12715.html)
* [https://research.splunk.com/stories/proxyshell/](https://research.splunk.com/stories/proxyshell/)
* [https://www.inversecos.com/2022/07/hunting-for-apt-abuse-of-exchange.html](https://www.inversecos.com/2022/07/hunting-for-apt-abuse-of-exchange.html)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/proxynotshell.yml) \| *version*: **1**