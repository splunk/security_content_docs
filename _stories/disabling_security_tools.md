---
title: "Disabling Security Tools"
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

Looks for activities and techniques associated with the disabling of security tools on a Windows system, such as suspicious `reg.exe` processes, processes launching netsh, and many others.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2020-02-04
- **Author**: Rico Valdez, Splunk
- **ID**: fcc27099-46a0-46b0-a271-5c7dab56b6f1

#### Narrative

Attackers employ a variety of tactics in order to avoid detection and operate without barriers. This often involves modifying the configuration of security tools to get around them or explicitly disabling them to prevent them from running. This Analytic Story includes searches that look for activity consistent with attackers attempting to disable various security mechanisms. Such activity may involve monitoring for suspicious registry activity, as this is where much of the configuration for Windows and various other programs reside, or explicitly attempting to shut down security-related services. Other times, attackers attempt various tricks to prevent specific programs from running, such as adding the certificates with which the security tools are signed to a block list (which would prevent them from running).

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Attempt To Add Certificate To Untrusted Store](/endpoint/6bc5243e-ef36-45dc-9b12-f4a6be131159/) | [Install Root Certificate](/tags/#install-root-certificate), [Subvert Trust Controls](/tags/#subvert-trust-controls) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Attempt To Stop Security Service](/endpoint/c8e349c6-b97c-486e-8949-bd7bcd1f3910/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Processes launching netsh](/endpoint/b89919ed-fe5f-492c-b139-95dbb162040e/) | [Disable or Modify System Firewall](/tags/#disable-or-modify-system-firewall), [Impair Defenses](/tags/#impair-defenses) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Sc exe Manipulating Windows Services](/endpoint/f0c693d8-2a89-4ce7-80b4-98fea4c3ea6d/) | [Windows Service](/tags/#windows-service), [Create or Modify System Process](/tags/#create-or-modify-system-process) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Reg exe Process](/endpoint/a6b3ab4e-dd77-4213-95fa-fc94701995e0/) | [Modify Registry](/tags/#modify-registry) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Unload Sysmon Filter Driver](/endpoint/e5928ff3-23eb-4d8b-b8a4-dcbc844fdfbe/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://attack.mitre.org/wiki/Technique/T1089](https://attack.mitre.org/wiki/Technique/T1089)
* [https://blog.malwarebytes.com/cybercrime/2015/11/vonteera-adware-uses-certificates-to-disable-anti-malware/](https://blog.malwarebytes.com/cybercrime/2015/11/vonteera-adware-uses-certificates-to-disable-anti-malware/)
* [https://web.archive.org/web/20220425194457/https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-Tools-Report.pdf](https://web.archive.org/web/20220425194457/https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-Tools-Report.pdf)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/disabling_security_tools.yml) \| *version*: **2**