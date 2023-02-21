---
title: "AwfulShred"
last_modified_at: 2023-01-24
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

Leverage searches that allow you to detect and investigate unusual activities that might relate to the AwfulShred malware including wiping files, process kill, system reboot via system request, shred,  and service stops.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2023-01-24
- **Author**: Teoderick Contreras, Splunk
- **ID**: e36935ce-f48c-4fb2-8109-7e80c1cdc9e2

#### Narrative

AwfulShred is a malicious linux shell script designed to corrupt or wipe the linux targeted system. It uses shred command to overwrite files and to increase data damage. This obfuscated malicious script can also disable and corrupts apache, HTTP and SSH services, deactivate swap files, clear bash history and finally reboot the system.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Linux Data Destruction Command](/endpoint/b11d3979-b2f7-411b-bb1a-bd00e642173b/) | [Data Destruction](/tags/#data-destruction) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Deleting Critical Directory Using RM Command](/endpoint/33f89303-cc6f-49ad-921d-2eaea38a6f7a/) | [Data Destruction](/tags/#data-destruction) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Deletion Of Services](/endpoint/b509bbd3-0331-4aaa-8e4a-d2affe100af6/) | [Data Destruction](/tags/#data-destruction), [File Deletion](/tags/#file-deletion), [Indicator Removal](/tags/#indicator-removal) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Disable Services](/endpoint/f2e08a38-6689-4df4-ad8c-b51c16262316/) | [Service Stop](/tags/#service-stop) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Hardware Addition SwapOff](/endpoint/c1eea697-99ed-44c2-9b70-d8935464c499/) | [Hardware Additions](/tags/#hardware-additions) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Impair Defenses Process Kill](/endpoint/435c6b33-adf9-47fe-be87-8e29fd6654f5/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Indicator Removal Clear Cache](/endpoint/e0940505-0b73-4719-84e6-cb94c44a5245/) | [Indicator Removal](/tags/#indicator-removal) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Indicator Removal Service File Deletion](/endpoint/6c077f81-2a83-4537-afbc-0e62e3215d55/) | [File Deletion](/tags/#file-deletion), [Indicator Removal](/tags/#indicator-removal) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Service Restarted](/endpoint/084275ba-61b8-11ec-8d64-acde48001122/) | [Systemd Timers](/tags/#systemd-timers), [Scheduled Task/Job](/tags/#scheduled-task/job) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Shred Overwrite Command](/endpoint/c1952cf1-643c-4965-82de-11c067cbae76/) | [Data Destruction](/tags/#data-destruction) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Stop Services](/endpoint/d05204a5-9f1c-4946-a7f3-4fa58d76d5fd/) | [Service Stop](/tags/#service-stop) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux System Reboot Via System Request Key](/endpoint/e1912b58-ed9c-422c-bbb0-2dbc70398345/) | [System Shutdown/Reboot](/tags/#system-shutdown/reboot) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Unix Shell Enable All SysRq Functions](/endpoint/e7a96937-3b58-4962-8dce-538e4763cf15/) | [Unix Shell](/tags/#unix-shell), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/overview-of-the-cyber-weapons-used-in-the-ukraine-russia-war/](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/overview-of-the-cyber-weapons-used-in-the-ukraine-russia-war/)
* [https://cert.gov.ua/article/3718487](https://cert.gov.ua/article/3718487)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/awfulshred.yml) \| *version*: **1**