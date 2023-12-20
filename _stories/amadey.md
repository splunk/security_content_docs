---
title: "Amadey"
last_modified_at: 2023-06-16
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

This analytic story contains searches that aims to detect activities related to Amadey, a type of malware that primarily operates as a banking Trojan. It is designed to steal sensitive information such as login credentials, credit card details, and other financial data from infected systems. The malware typically targets Windows-based computers.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2023-06-16
- **Author**: Teoderick Contreras, Splunk
- **ID**: a919a01b-3ea5-4ed4-9cbe-11cd8b64c36c

#### Narrative

Amadey is one of the active trojans that are capable of stealing sensitive information via its from the infected or targeted host machine. It can collect various types of data, including browser profile information, clipboard data, capture screenshots and system information. Adversaries or threat actors may use this malware to maximize the impact of infection on the target organization in operations where data collection and exfiltration is the goal. The primary function is to steal information and further distribute malware. It aims to extract a variety of information from infected devices and attempts to evade the detection of security measures by reducing the volume of data exfiltration compared to that seen in other malicious instances.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Detect Outlook exe writing a zip file](/endpoint/a51bfe1a-94f0-4822-b1e4-16ae10145893/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Executables Or Script Creation In Suspicious Path](/endpoint/a7e3f0f0-ae42-11eb-b245-acde48001122/) | [Masquerading](/tags/#masquerading) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Process Creating LNK file in Suspicious Location](/endpoint/5d814af1-1041-47b5-a9ac-d754e82e9a26/) | [Phishing](/tags/#phishing), [Spearphishing Link](/tags/#spearphishing-link) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Registry Keys Used For Persistence](/endpoint/f5f6af30-7aa7-4295-bfe9-07fe87c01a4b/) | [Registry Run Keys / Startup Folder](/tags/#registry-run-keys-/-startup-folder), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Scheduled Task Deleted Or Created via CMD](/endpoint/d5af132c-7c17-439c-9d31-13d55340f36c/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Process Executed From Container File](/endpoint/d8120352-3b62-411c-8cb6-7b47584dd5e8/) | [Malicious File](/tags/#malicious-file), [Masquerade File Type](/tags/#masquerade-file-type) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Process File Path](/endpoint/9be25988-ad82-11eb-a14f-acde48001122/) | [Create or Modify System Process](/tags/#create-or-modify-system-process) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [WinEvent Windows Task Scheduler Event Action Started](/endpoint/b3632472-310b-11ec-9aab-acde48001122/) | [Scheduled Task](/tags/#scheduled-task) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Credentials from Password Stores Chrome Extension Access](/endpoint/2e65afe0-9a75-4487-bd87-ada9a9f1b9af/) | [Query Registry](/tags/#query-registry) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Credentials from Password Stores Chrome LocalState Access](/endpoint/3b1d09a8-a26f-473e-a510-6c6613573657/) | [Query Registry](/tags/#query-registry) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Credentials from Password Stores Chrome Login Data Access](/endpoint/0d32ba37-80fc-4429-809c-0ba15801aeaf/) | [Query Registry](/tags/#query-registry) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Files and Dirs Access Rights Modification Via Icacls](/endpoint/c76b796c-27e1-4520-91c4-4a58695c749e/) | [Windows File and Directory Permissions Modification](/tags/#windows-file-and-directory-permissions-modification), [File and Directory Permissions Modification](/tags/#file-and-directory-permissions-modification) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows ISO LNK File Creation](/endpoint/d7c2c09b-9569-4a9e-a8b6-6a39a99c1d32/) | [Spearphishing Attachment](/tags/#spearphishing-attachment), [Phishing](/tags/#phishing), [Malicious Link](/tags/#malicious-link), [User Execution](/tags/#user-execution) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Powershell RemoteSigned File](/endpoint/f7f7456b-470d-4a95-9703-698250645ff4/) | [PowerShell](/tags/#powershell), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://malpedia.caad.fkie.fraunhofer.de/details/win.amadey](https://malpedia.caad.fkie.fraunhofer.de/details/win.amadey)
* [https://darktrace.com/blog/amadey-info-stealer-exploiting-n-day-vulnerabilities](https://darktrace.com/blog/amadey-info-stealer-exploiting-n-day-vulnerabilities)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/amadey.yml) \| *version*: **1**