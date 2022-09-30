---
title: "AgentTesla"
last_modified_at: 2022-04-12
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

Leverage searches that allow you to detect and investigate unusual activities that might relate to the AgentTesla malware including .chm application child process, ftp/smtp connection, persistence and many more. AgentTesla is one of the advanced remote access trojans (RAT) that are capable of stealing sensitive information from the infected or targeted host machine. It can collect various types of data, including browser profile information, keystrokes, capture screenshots and vpn credentials. AgentTesla has been active malware since 2014 and often delivered as a malicious attachment in phishing emails.It is also the top malware in 2021 based on the CISA report.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-04-12
- **Author**: Teoderick Contreras, Splunk
- **ID**: 9bb6077a-843e-418b-b134-c57ef997103c

#### Narrative

Adversaries or threat actor may use this malware to maximize the impact of infection on the target organization in operations where network wide availability interruption is the goal.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Detect HTML Help Spawn Child Process](/endpoint/723716de-ee55-4cd4-9759-c44e7e55ba4b/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [Compiled HTML File](/tags/#compiled-html-file) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Excessive Usage Of Taskkill](/endpoint/fe5bca48-accb-11eb-a67c-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Executables Or Script Creation In Suspicious Path](/endpoint/a7e3f0f0-ae42-11eb-b245-acde48001122/) | [Masquerading](/tags/#masquerading) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Non Chrome Process Accessing Chrome Default Dir](/endpoint/81263de4-160a-11ec-944f-acde48001122/) | [Credentials from Password Stores](/tags/#credentials-from-password-stores), [Credentials from Web Browsers](/tags/#credentials-from-web-browsers) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Non Firefox Process Access Firefox Profile Dir](/endpoint/e6fc13b0-1609-11ec-b533-acde48001122/) | [Credentials from Password Stores](/tags/#credentials-from-password-stores), [Credentials from Web Browsers](/tags/#credentials-from-web-browsers) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Office Application Drop Executable](/endpoint/73ce70c4-146d-11ec-9184-acde48001122/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Office Application Spawn rundll32 process](/endpoint/958751e4-9c5f-11eb-b103-acde48001122/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Office Document Executing Macro Code](/endpoint/b12c89bc-9d06-11eb-a592-acde48001122/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [PowerShell - Connect To Internet With Hidden Window](/endpoint/ee18ed37-0802-4268-9435-b3b91aaa18db/) | [PowerShell](/tags/#powershell), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [PowerShell Loading DotNET into Memory via Reflection](/endpoint/85bc3f30-ca28-11eb-bd21-acde48001122/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Scheduled Task Deleted Or Created via CMD](/endpoint/d5af132c-7c17-439c-9d31-13d55340f36c/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Process File Path](/endpoint/9be25988-ad82-11eb-a14f-acde48001122/) | [Create or Modify System Process](/tags/#create-or-modify-system-process) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows File Transfer Protocol In Non-Common Process Path](/endpoint/0f43758f-1fe9-470a-a9e4-780acc4d5407/) | [Mail Protocols](/tags/#mail-protocols), [Application Layer Protocol](/tags/#application-layer-protocol) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows ISO LNK File Creation](/endpoint/d7c2c09b-9569-4a9e-a8b6-6a39a99c1d32/) | [Spearphishing Attachment](/tags/#spearphishing-attachment), [Phishing](/tags/#phishing), [Malicious Link](/tags/#malicious-link), [User Execution](/tags/#user-execution) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Mail Protocol In Non-Common Process Path](/endpoint/ac3311f5-661d-4e99-bd1f-3ec665b05441/) | [Mail Protocols](/tags/#mail-protocols), [Application Layer Protocol](/tags/#application-layer-protocol) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Multi hop Proxy TOR Website Query](/endpoint/4c2d198b-da58-48d7-ba27-9368732d0054/) | [Mail Protocols](/tags/#mail-protocols), [Application Layer Protocol](/tags/#application-layer-protocol) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Phishing Recent ISO Exec Registry](/endpoint/cb38ee66-8ae5-47de-bd66-231c7bbc0b2c/) | [Spearphishing Attachment](/tags/#spearphishing-attachment), [Phishing](/tags/#phishing) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://malpedia.caad.fkie.fraunhofer.de/details/win.agent_tesla](https://malpedia.caad.fkie.fraunhofer.de/details/win.agent_tesla)
* [https://cert.gov.ua/article/861292](https://cert.gov.ua/article/861292)
* [https://www.cisa.gov/uscert/ncas/alerts/aa22-216a](https://www.cisa.gov/uscert/ncas/alerts/aa22-216a)
* [https://www.joesandbox.com/analysis/702680/0/html](https://www.joesandbox.com/analysis/702680/0/html)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/agenttesla.yml) \| *version*: **1**