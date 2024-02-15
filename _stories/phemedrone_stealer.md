---
title: "Phemedrone Stealer"
last_modified_at: 2024-01-24
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

Phemedrone Stealer is a potent data-stealing malware designed to infiltrate systems discreetly, primarily targeting sensitive user information. Operating with a stealthy modus operandi, it covertly collects and exfiltrates critical data such as login credentials, personal details, and financial information. Notably evasive, Phemedrone employs sophisticated techniques to bypass security measures and remain undetected. Its capabilities extend to exploiting vulnerabilities, leveraging command and control infrastructure, and facilitating remote access. As a formidable threat, Phemedrone Stealer poses a significant risk to user privacy and system integrity, demanding vigilant cybersecurity measures to counteract its malicious activities.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2024-01-24
- **Author**: Teoderick Contreras, Splunk
- **ID**: 386f64dd-657b-4dcf-8eb3-5e297d30924c

#### Narrative

Phemedrone Stealer, spotlighted in a recent Trend Micro blog, unveils a concerning chapter in cyber threats. Leveraging the CVE-2023-36025 vulnerability for defense evasion, this malware exhibits a relentless pursuit of sensitive data. Originating from the shadows of the dark web, it capitalizes on forums where cybercriminals refine its evasive maneuvers. The blog sheds light on Phemedrone's exploitation of intricate tactics, illustrating its agility in sidestepping security protocols. As cybersecurity experts delve into the intricacies of CVE-2023-36025, the narrative surrounding Phemedrone Stealer underscores the urgency for heightened vigilance and proactive defense measures against this persistent and evolving digital adversary.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Any Powershell DownloadFile](/endpoint/1a93b7ea-7af7-11eb-adb5-acde48001122/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell), [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Any Powershell DownloadString](/endpoint/4d015ef2-7adf-11eb-95da-acde48001122/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell), [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Download Files Using Telegram](/endpoint/58194e28-ae5e-11eb-8912-acde48001122/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Non Chrome Process Accessing Chrome Default Dir](/endpoint/81263de4-160a-11ec-944f-acde48001122/) | [Credentials from Password Stores](/tags/#credentials-from-password-stores), [Credentials from Web Browsers](/tags/#credentials-from-web-browsers) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Non Firefox Process Access Firefox Profile Dir](/endpoint/e6fc13b0-1609-11ec-b533-acde48001122/) | [Credentials from Password Stores](/tags/#credentials-from-password-stores), [Credentials from Web Browsers](/tags/#credentials-from-web-browsers) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Scheduled Task Deleted Or Created via CMD](/endpoint/d5af132c-7c17-439c-9d31-13d55340f36c/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Schtasks scheduling job on remote system](/endpoint/1297fb80-f42a-4b4a-9c8a-88c066237cf6/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Process DNS Query Known Abuse Web Services](/endpoint/3cf0dc36-484d-11ec-a6bc-acde48001122/) | [Visual Basic](/tags/#visual-basic), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Process File Path](/endpoint/9be25988-ad82-11eb-a14f-acde48001122/) | [Create or Modify System Process](/tags/#create-or-modify-system-process) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Credentials from Password Stores Chrome Extension Access](/endpoint/2e65afe0-9a75-4487-bd87-ada9a9f1b9af/) | [Query Registry](/tags/#query-registry) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Credentials from Password Stores Chrome LocalState Access](/endpoint/3b1d09a8-a26f-473e-a510-6c6613573657/) | [Query Registry](/tags/#query-registry) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Credentials from Password Stores Chrome Login Data Access](/endpoint/0d32ba37-80fc-4429-809c-0ba15801aeaf/) | [Query Registry](/tags/#query-registry) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Gather Victim Network Info Through Ip Check Web Services](/endpoint/70f7c952-0758-46d6-9148-d8969c4481d1/) | [IP Addresses](/tags/#ip-addresses), [Gather Victim Network Information](/tags/#gather-victim-network-information) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://www.trendmicro.com/en_vn/research/23/b/investigating-the-plugx-trojan-disguised-as-a-legitimate-windows.html](https://www.trendmicro.com/en_vn/research/23/b/investigating-the-plugx-trojan-disguised-as-a-legitimate-windows.html)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/phemedrone_stealer.yml) \| *version*: **2**