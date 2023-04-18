---
title: "Winter Vivern"
last_modified_at: 2023-02-16
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

Utilize searches that enable you to detect and investigate unusual activities potentially related to the Winter Vivern malicious software. This includes examining multiple timeout executions, scheduled task creations, screenshots, and downloading files through PowerShell, among other indicators.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2023-02-16
- **Author**: Teoderick Contreras, Splunk
- **ID**: 5ce5f311-b311-4568-90ca-0c36781d07a4

#### Narrative

The Winter Vivern malware, identified by CERT UA, is designed to download and run multiple PowerShell scripts on targeted hosts. These scripts aim to gather a variety of files with specific extensions, including (.edb, .ems, .eme, .emz, .key, .pem, .ovpn, .bat, .cer, .p12, .cfg, .log, .txt, .pdf, .doc, .docx, .xls, .xlsx, and .rdg), primarily from desktop directories. In addition to this, the malware captures desktop screenshots and performs data exfiltration using HTTP. To maintain its presence on the targeted host, Winter Vivern also establishes a persistence mechanism, such as creating a scheduled task.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Any Powershell DownloadString](/endpoint/4d015ef2-7adf-11eb-95da-acde48001122/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell), [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [CMD Carry Out String Command Parameter](/endpoint/54a6ed00-3256-11ec-b031-acde48001122/) | [Windows Command Shell](/tags/#windows-command-shell), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GetWmiObject User Account with PowerShell](/endpoint/b44f6ac6-0429-11ec-87e9-acde48001122/) | [Account Discovery](/tags/#account-discovery), [Local Account](/tags/#local-account) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [GetWmiObject User Account with PowerShell Script Block](/endpoint/640b0eda-0429-11ec-accd-acde48001122/) | [Account Discovery](/tags/#account-discovery), [Local Account](/tags/#local-account), [PowerShell](/tags/#powershell) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [PowerShell Loading DotNET into Memory via Reflection](/endpoint/85bc3f30-ca28-11eb-bd21-acde48001122/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Powershell Fileless Script Contains Base64 Encoded Content](/endpoint/8acbc04c-c882-11eb-b060-acde48001122/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [Obfuscated Files or Information](/tags/#obfuscated-files-or-information), [PowerShell](/tags/#powershell) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Schedule Task with HTTP Command Arguments](/endpoint/523c2684-a101-11eb-916b-acde48001122/) | [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Scheduled Task Deleted Or Created via CMD](/endpoint/d5af132c-7c17-439c-9d31-13d55340f36c/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [System User Discovery With Whoami](/endpoint/894fc43e-6f50-47d5-a68b-ee9ee23e18f4/) | [System Owner/User Discovery](/tags/#system-owner/user-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [WinEvent Scheduled Task Created Within Public Path](/endpoint/5d9c6eee-988c-11eb-8253-acde48001122/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [WinEvent Scheduled Task Created to Spawn Shell](/endpoint/203ef0ea-9bd8-11eb-8201-acde48001122/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [WinEvent Windows Task Scheduler Event Action Started](/endpoint/b3632472-310b-11ec-9aab-acde48001122/) | [Scheduled Task](/tags/#scheduled-task) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [WinEvent Windows Task Scheduler Event Action Started](/endpoint/b3632472-310b-11ec-9aab-acde48001122/) | [Scheduled Task](/tags/#scheduled-task) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Exfiltration Over C2 Via Invoke RestMethod](/endpoint/06ade821-f6fa-40d0-80af-15bc1d45b3ba/) | [Exfiltration Over C2 Channel](/tags/#exfiltration-over-c2-channel) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Exfiltration Over C2 Via Powershell UploadString](/endpoint/59e8bf41-7472-412a-90d3-00f3afa452e9/) | [Exfiltration Over C2 Channel](/tags/#exfiltration-over-c2-channel) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Scheduled Task Created Via XML](/endpoint/7e03b682-3965-4598-8e91-a60a40a3f7e4/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Screen Capture Via Powershell](/endpoint/5e0b1936-8f99-4399-8ee2-9edc5b32e170/) | [Screen Capture](/tags/#screen-capture) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://cert.gov.ua/article/3761023](https://cert.gov.ua/article/3761023)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/winter_vivern.yml) \| *version*: **1**