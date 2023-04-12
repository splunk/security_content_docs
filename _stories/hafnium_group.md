---
title: "HAFNIUM Group"
last_modified_at: 2021-03-03
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Network_Traffic
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

HAFNIUM group was identified by Microsoft as exploiting 4 Microsoft Exchange CVEs in the wild - CVE-2021-26855, CVE-2021-26857, CVE-2021-26858 and CVE-2021-27065.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic)
- **Last Updated**: 2021-03-03
- **Author**: Michael Haag, Splunk
- **ID**: beae2ab0-7c3f-11eb-8b63-acde48001122

#### Narrative

On Tuesday, March 2, 2021, Microsoft released a set of security patches for its mail server, Microsoft Exchange. These patches respond to a group of vulnerabilities known to impact Exchange 2013, 2016, and 2019. It is important to note that an Exchange 2010 security update has also been issued, though the CVEs do not reference that version as being vulnerable.\
While the CVEs do not shed much light on the specifics of the vulnerabilities or exploits, the first vulnerability (CVE-2021-26855) has a remote network attack vector that allows the attacker, a group Microsoft named HAFNIUM, to authenticate as the Exchange server. Three additional vulnerabilities (CVE-2021-26857, CVE-2021-26858, and CVE-2021-27065) were also identified as part of this activity. When chained together along with CVE-2021-26855 for initial access, the attacker would have complete control over the Exchange server. This includes the ability to run code as SYSTEM and write to any path on the server.\
The following Splunk detections assist with identifying the HAFNIUM groups tradecraft and methodology.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Any Powershell DownloadString](/endpoint/4d015ef2-7adf-11eb-95da-acde48001122/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell), [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Exchange Web Shell](/endpoint/8c14eeee-2af1-4a4b-bda8-228da0f4862a/) | [Server Software Component](/tags/#server-software-component), [Web Shell](/tags/#web-shell), [Exploit Public-Facing Application](/tags/#exploit-public-facing-application) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect New Local Admin account](/endpoint/b25f6f62-0712-43c1-b203-083231ffd97d/) | [Local Account](/tags/#local-account), [Create Account](/tags/#create-account) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect PsExec With accepteula Flag](/endpoint/27c3a83d-cada-47c6-9042-67baf19d2574/) | [Remote Services](/tags/#remote-services), [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Renamed PSExec](/endpoint/683e6196-b8e8-11eb-9a79-acde48001122/) | [System Services](/tags/#system-services), [Service Execution](/tags/#service-execution) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Dump LSASS via comsvcs DLL](/endpoint/8943b567-f14d-4ee8-a0bb-2121d4ce3184/) | [LSASS Memory](/tags/#lsass-memory), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Dump LSASS via procdump](/endpoint/3742ebfe-64c2-11eb-ae93-0242ac130002/) | [LSASS Memory](/tags/#lsass-memory), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Dump LSASS via procdump Rename](/deprecated/21276daa-663d-11eb-ae93-0242ac130002/) | [LSASS Memory](/tags/#lsass-memory) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Email servers sending high volume traffic to hosts](/application/7f5fb3e1-4209-4914-90db-0ec21b556378/) | [Email Collection](/tags/#email-collection), [Remote Email Collection](/tags/#remote-email-collection) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Malicious PowerShell Process - Execution Policy Bypass](/endpoint/9be56c82-b1cc-4318-87eb-d138afaaca39/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Nishang PowershellTCPOneLine](/endpoint/1a382c6c-7c2e-11eb-ac69-acde48001122/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Ntdsutil Export NTDS](/endpoint/da63bc76-61ae-11eb-ae93-0242ac130002/) | [NTDS](/tags/#ntds), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [PowerShell - Connect To Internet With Hidden Window](/endpoint/ee18ed37-0802-4268-9435-b3b91aaa18db/) | [PowerShell](/tags/#powershell), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Set Default PowerShell Execution Policy To Unrestricted or Bypass](/endpoint/c2590137-0b08-4985-9ec5-6ae23d92f63d/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [W3WP Spawning Shell](/endpoint/0f03423c-7c6a-11eb-bc47-acde48001122/) | [Server Software Component](/tags/#server-software-component), [Web Shell](/tags/#web-shell) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows OS Credential Dumping with Ntdsutil Export NTDS](/endpoint/dad9ddec-a72a-47be-87b6-a0f7ba98ed6e/) | [NTDS](/tags/#ntds), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows OS Credential Dumping with Procdump](/endpoint/e102e297-dbe6-4a19-b319-5c08f4c19a06/) | [LSASS Memory](/tags/#lsass-memory), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Powershell Connect to Internet With Hidden Window](/endpoint/477e068e-8b6d-11ec-b6c1-81af21670352/) | [Automated Exfiltration](/tags/#automated-exfiltration) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://www.splunk.com/en_us/blog/security/detecting-hafnium-exchange-server-zero-day-activity-in-splunk.html](https://www.splunk.com/en_us/blog/security/detecting-hafnium-exchange-server-zero-day-activity-in-splunk.html)
* [https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/](https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/)
* [https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/](https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/)
* [https://blog.rapid7.com/2021/03/03/rapid7s-insightidr-enables-detection-and-response-to-microsoft-exchange-0-day/](https://blog.rapid7.com/2021/03/03/rapid7s-insightidr-enables-detection-and-response-to-microsoft-exchange-0-day/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/hafnium_group.yml) \| *version*: **1**