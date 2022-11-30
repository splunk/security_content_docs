---
title: "CISA AA22-320A"
last_modified_at: 2022-11-16
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Network_Resolution
  - Network_Traffic
  - Risk
  - Web
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

CISA and the FBI have identified an APT activity where the adversary gained initial access via Log4Shell via a unpatched VMware Horizon server. From there the adversary moved laterally and continued to its objective.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Network_Resolution](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkResolution), [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic), [Risk](https://docs.splunk.com/Documentation/CIM/latest/User/Risk), [Web](https://docs.splunk.com/Documentation/CIM/latest/User/Web)
- **Last Updated**: 2022-11-16
- **Author**: Michael Haag, Splunk
- **ID**: c1fca73d-3a8d-49a6-b9c0-1d5d155f7dd4

#### Narrative

From mid-June through mid-July 2022, CISA conducted an incident response engagement at a Federal Civilian Executive Branch (FCEB) organization where CISA observed suspected advanced persistent threat (APT) activity. In the course of incident response activities, CISA determined that cyber threat actors exploited the Log4Shell vulnerability in an unpatched VMware Horizon server, installed XMRig crypto mining software, moved laterally to the domain controller (DC), compromised credentials, and then implanted Ngrok reverse proxies on several hosts to maintain persistence. CISA and the Federal Bureau of Investigation (FBI) assess that the FCEB network was compromised by Iranian government-sponsored APT actors.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Add or Set Windows Defender Exclusion](/endpoint/773b66fe-4dd9-11ec-8289-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Mimikatz Using Loaded Images](/endpoint/29e307ba-40af-4ab2-91b2-3c6b392bbba0/) | [LSASS Memory](/tags/#lsass-memory), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Mimikatz With PowerShell Script Block Logging](/endpoint/8148c29c-c952-11eb-9255-acde48001122/) | [OS Credential Dumping](/tags/#os-credential-dumping), [PowerShell](/tags/#powershell) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect PsExec With accepteula Flag](/endpoint/27c3a83d-cada-47c6-9042-67baf19d2574/) | [Remote Services](/tags/#remote-services), [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Renamed PSExec](/endpoint/683e6196-b8e8-11eb-9a79-acde48001122/) | [System Services](/tags/#system-services), [Service Execution](/tags/#service-execution) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Enable WDigest UseLogonCredential Registry](/endpoint/0c7d8ffe-25b1-11ec-9f39-acde48001122/) | [Modify Registry](/tags/#modify-registry), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GetAdComputer with PowerShell Script Block](/endpoint/a9a1da02-8e27-4bf7-a348-f4389c9da487/) | [Remote System Discovery](/tags/#remote-system-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Hunting for Log4Shell](/endpoint/158b68fa-5d1a-11ec-aac8-acde48001122/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Log4Shell CVE-2021-44228 Exploitation](/endpoint/9be30d80-3a39-4df9-9102-64a467b24eac/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer), [Exploit Public-Facing Application](/tags/#exploit-public-facing-application), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | [Correlation](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Log4Shell JNDI Payload Injection Attempt](/web/c184f12e-5c90-11ec-bf1f-497c9a704a72/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Log4Shell JNDI Payload Injection with Outbound Connection](/web/69afee44-5c91-11ec-bf1f-497c9a704a72/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Malicious PowerShell Process - Encoded Command](/endpoint/c4db14d9-7909-48b4-a054-aa14d89dbb19/) | [Obfuscated Files or Information](/tags/#obfuscated-files-or-information) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Mimikatz PassTheTicket CommandLine Parameters](/endpoint/13bbd574-83ac-11ec-99d4-acde48001122/) | [Use Alternate Authentication Material](/tags/#use-alternate-authentication-material), [Pass the Ticket](/tags/#pass-the-ticket) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Ngrok Reverse Proxy on Network](/network/5790a766-53b8-40d3-a696-3547b978fcf0/) | [Protocol Tunneling](/tags/#protocol-tunneling), [Proxy](/tags/#proxy), [Web Service](/tags/#web-service) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Powershell Windows Defender Exclusion Commands](/endpoint/907ac95c-4dd9-11ec-ba2c-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Driver Loaded Path](/endpoint/f880acd4-a8f1-11eb-a53b-acde48001122/) | [Windows Service](/tags/#windows-service), [Create or Modify System Process](/tags/#create-or-modify-system-process) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Powershell Command-Line Arguments](/deprecated/2cdb91d2-542c-497f-b252-be495e71f38c/) | [PowerShell](/tags/#powershell) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Driver Load Non-Standard Path](/endpoint/9216ef3d-066a-4958-8f27-c84589465e62/) | [Rootkit](/tags/#rootkit) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Drivers Loaded by Signature](/endpoint/d2d4af6a-6c2b-4d79-80c5-fc2cf12a2f68/) | [Rootkit](/tags/#rootkit), [Exploitation for Privilege Escalation](/tags/#exploitation-for-privilege-escalation) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Mimikatz Binary Execution](/endpoint/a9e0d6d3-9676-4e26-994d-4e0406bb4467/) | [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Ngrok Reverse Proxy Usage](/endpoint/e2549f2c-0aef-408a-b0c1-e0f270623436/) | [Protocol Tunneling](/tags/#protocol-tunneling), [Proxy](/tags/#proxy), [Web Service](/tags/#web-service) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Service Create Kernel Mode Driver](/endpoint/0b4e3b06-1b2b-4885-b752-cf06d12a90cb/) | [Windows Service](/tags/#windows-service), [Create or Modify System Process](/tags/#create-or-modify-system-process), [Exploitation for Privilege Escalation](/tags/#exploitation-for-privilege-escalation) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [XMRIG Driver Loaded](/endpoint/90080fa6-a8df-11eb-91e4-acde48001122/) | [Windows Service](/tags/#windows-service), [Create or Modify System Process](/tags/#create-or-modify-system-process) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://www.cisa.gov/uscert/ncas/alerts/aa22-320a](https://www.cisa.gov/uscert/ncas/alerts/aa22-320a)
* [https://www.cisa.gov/uscert/sites/default/files/publications/aa22-320a_joint_csa_iranian_government-sponsored_apt_actors_compromise_federal%20network_deploy_crypto%20miner_credential_harvester.pdf](https://www.cisa.gov/uscert/sites/default/files/publications/aa22-320a_joint_csa_iranian_government-sponsored_apt_actors_compromise_federal%20network_deploy_crypto%20miner_credential_harvester.pdf)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/cisa_aa22_320a.yml) \| *version*: **1**