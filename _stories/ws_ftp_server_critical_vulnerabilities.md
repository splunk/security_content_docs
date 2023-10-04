---
title: "WS FTP Server Critical Vulnerabilities"
last_modified_at: 2023-10-01
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Web
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

A critical security advisory was released by Progress Software on September 27, 2023, concerning multiple vulnerabilities in WS_FTP Server, a widely-used secure file transfer solution. The two critical vulnerabilities are CVE-2023-40044, a .NET deserialization flaw, and CVE-2023-42657, a directory traversal vulnerability. Rapid7 has observed active exploitation of these vulnerabilities. Affected versions are prior to 8.7.4 and 8.8.2. Immediate action is advised - upgrade to WS_FTP Server version 8.8.2. For those unable to update, disabling the Ad Hoc Transfer module is suggested as a temporary measure. This comes in the wake of increased scrutiny following the Cl0p ransomware attack on MOVEit Transfer in May 2023.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Web](https://docs.splunk.com/Documentation/CIM/latest/User/Web)
- **Last Updated**: 2023-10-01
- **Author**: Michael Haag, Splunk
- **ID**: 60466291-3ab4-452b-9c11-456aa2dc7293

#### Narrative

Two critical vulnerabilities have been identified in WS_FTP Server, a widely-used secure file transfer solution. The first, CVE-2023-40044, is a .NET deserialization flaw that targets the Ad Hoc Transfer module of WS_FTP Server versions earlier than 8.7.4 and 8.8.2. This flaw allows an attacker to execute arbitrary commands on the server's operating system without needing authentication. The second vulnerability, CVE-2023-42657, is a directory traversal flaw that allows attackers to perform unauthorized file operations outside of their authorized WS_FTP folder. In severe cases, the attacker could escape the WS_FTP Server file structure and perform operations on the underlying operating system. Both vulnerabilities have been observed being exploited in the wild and immediate action for mitigation is strongly advised. Updating to WS_FTP Server version 8.8.2 is recommended. For those unable to update, disabling the Ad Hoc Transfer module is suggested as a temporary measure.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Detect Webshell Exploit Behavior](/endpoint/22597426-6dbd-49bd-bcdc-4ec19857192f/) | [Server Software Component](/tags/#server-software-component), [Web Shell](/tags/#web-shell) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [W3WP Spawning Shell](/endpoint/0f03423c-7c6a-11eb-bc47-acde48001122/) | [Server Software Component](/tags/#server-software-component), [Web Shell](/tags/#web-shell) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [WS FTP Remote Code Execution](/web/b84e8f39-4e7b-4d4f-9e7c-fcd29a227845/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows IIS Components Get-WebGlobalModule Module Query](/endpoint/20db5f70-34b4-4e83-8926-fa26119de173/) | [IIS Components](/tags/#iis-components), [Server Software Component](/tags/#server-software-component) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://www.assetnote.io/resources/research/rce-in-progress-ws-ftp-ad-hoc-via-iis-http-modules-cve-2023-40044](https://www.assetnote.io/resources/research/rce-in-progress-ws-ftp-ad-hoc-via-iis-http-modules-cve-2023-40044)
* [https://community.progress.com/s/article/WS-FTP-Server-Critical-Vulnerability-September-2023](https://community.progress.com/s/article/WS-FTP-Server-Critical-Vulnerability-September-2023)
* [https://www.cve.org/CVERecord?id=CVE-2023-40044](https://www.cve.org/CVERecord?id=CVE-2023-40044)
* [https://www.rapid7.com/blog/post/2023/09/29/etr-critical-vulnerabilities-in-ws_ftp-server/](https://www.rapid7.com/blog/post/2023/09/29/etr-critical-vulnerabilities-in-ws_ftp-server/)
* [https://www.splunk.com/en_us/blog/security/fantastic-iis-modules-and-how-to-find-them.html](https://www.splunk.com/en_us/blog/security/fantastic-iis-modules-and-how-to-find-them.html)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/ws_ftp_server_critical_vulnerabilities.yml) \| *version*: **1**