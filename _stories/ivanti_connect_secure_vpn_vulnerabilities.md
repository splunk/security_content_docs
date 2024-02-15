---
title: "Ivanti Connect Secure VPN Vulnerabilities"
last_modified_at: 2024-01-16
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Web
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic story addresses critical vulnerabilities CVE-2023-46805 and CVE-2024-21887 in Ivanti Connect Secure and Ivanti Policy Secure Gateways. CVE-2023-46805 is an authentication bypass vulnerability, while CVE-2024-21887 is a command injection flaw, both presenting significant risks in versions 9.x and 22.x. Combined, these vulnerabilities enable unauthenticated threat actors to execute arbitrary commands, compromising system integrity. Immediate mitigation is imperative, with patches scheduled for staggered release. Ivanti has provided interim mitigation steps, and it's crucial for customers to apply these measures to protect their systems against potential exploits.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Web](https://docs.splunk.com/Documentation/CIM/latest/User/Web)
- **Last Updated**: 2024-01-16
- **Author**: Michael Haag, Splunk
- **ID**: e3b5c3b8-082b-4b4e-b2c9-47ed79e2a5ab

#### Narrative

Ivanti Connect Secure and Ivanti Policy Secure gateways face a severe security challenge with the discovery of CVE-2023-46805 and CVE-2024-21887. CVE-2023-46805 allows attackers to bypass authentication in critical web components of versions 9.x and 22.x. More alarmingly, when paired with CVE-2024-21887, a command injection vulnerability, it enables remote attackers to execute arbitrary commands without authentication. This combination poses a heightened threat, undermining the security of enterprise networks. Ivanti has mobilized resources to address these vulnerabilities, offering immediate mitigation advice and scheduling patch releases. Customers are urged to apply these mitigations without delay to safeguard their networks.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Access to Vulnerable Ivanti Connect Secure Bookmark Endpoint](/web/15838756-f425-43fa-9d88-a7f88063e81a/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Ivanti Connect Secure Command Injection Attempts](/web/1f32a7e0-a060-4545-b7de-73fcf9ad536e/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Ivanti Connect Secure SSRF in SAML Component](/web/8e6ca490-7af3-4299-9a24-39fb69759925/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Ivanti Connect Secure System Information Access via Auth Bypass](/web/d51c13dd-a232-4c83-a2bb-72ab36233c5d/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://github.com/RootUp/PersonalStuff/blob/master/http-vuln-cve2023-46805_2024_21887.nse](https://github.com/RootUp/PersonalStuff/blob/master/http-vuln-cve2023-46805_2024_21887.nse)
* [https://github.com/projectdiscovery/nuclei-templates/blob/c6b351e71b0fb0e40e222e97038f1fe09ac58194/http/misconfiguration/ivanti/CVE-2023-46085-CVE-2024-21887-mitigation-not-applied.yaml](https://github.com/projectdiscovery/nuclei-templates/blob/c6b351e71b0fb0e40e222e97038f1fe09ac58194/http/misconfiguration/ivanti/CVE-2023-46085-CVE-2024-21887-mitigation-not-applied.yaml)
* [https://github.com/rapid7/metasploit-framework/pull/18708/files](https://github.com/rapid7/metasploit-framework/pull/18708/files)
* [https://attackerkb.com/topics/AdUh6by52K/cve-2023-46805/rapid7-analysis](https://attackerkb.com/topics/AdUh6by52K/cve-2023-46805/rapid7-analysis)
* [https://labs.watchtowr.com/welcome-to-2024-the-sslvpn-chaos-continues-ivanti-cve-2023-46805-cve-2024-21887/](https://labs.watchtowr.com/welcome-to-2024-the-sslvpn-chaos-continues-ivanti-cve-2023-46805-cve-2024-21887/)
* [https://www.volexity.com/blog/2024/01/10/active-exploitation-of-two-zero-day-vulnerabilities-in-ivanti-connect-secure-vpn/](https://www.volexity.com/blog/2024/01/10/active-exploitation-of-two-zero-day-vulnerabilities-in-ivanti-connect-secure-vpn/)
* [https://www.mandiant.com/resources/blog/suspected-apt-targets-ivanti-zero-day](https://www.mandiant.com/resources/blog/suspected-apt-targets-ivanti-zero-day)
* [https://forums.ivanti.com/s/article/CVE-2023-46805-Authentication-Bypass-CVE-2024-21887-Command-Injection-for-Ivanti-Connect-Secure-and-Ivanti-Policy-Secure-Gateways?language=en_US](https://forums.ivanti.com/s/article/CVE-2023-46805-Authentication-Bypass-CVE-2024-21887-Command-Injection-for-Ivanti-Connect-Secure-and-Ivanti-Policy-Secure-Gateways?language=en_US)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/ivanti_connect_secure_vpn_vulnerabilities.yml) \| *version*: **1**