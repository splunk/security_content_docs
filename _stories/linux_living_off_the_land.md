---
title: "Linux Living Off The Land"
last_modified_at: 2022-07-27
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

Linux Living Off The Land consists of binaries that may be used to bypass local security restrictions within misconfigured systems.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-07-27
- **Author**: Michael Haag, Splunk
- **ID**: e405a2d7-dc8e-4227-8e9d-f60267b8c0cd

#### Narrative

Similar to Windows LOLBAS project, the GTFOBins project focuses solely on Unix binaries that may be abused in multiple categories including Reverse Shell, File Upload, File Download and much more. These binaries are native to the operating system and the functionality is typically native. The behaviors are typically not malicious by default or vulnerable, but these are built in functionality of the applications. When reviewing any notables or hunting through mountains of events of interest, it's important to identify the binary, review command-line arguments, path of file, and capture any network and file modifications. Linux analysis may be a bit cumbersome due to volume and how process behavior is seen in EDR products. Piecing it together will require some effort.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Curl Download and Bash Execution](/endpoint/900bc324-59f3-11ec-9fb4-acde48001122/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Add Files In Known Crontab Directories](/endpoint/023f3452-5f27-11ec-bf00-acde48001122/) | [Cron](/tags/#cron), [Scheduled Task/Job](/tags/#scheduled-task/job) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Adding Crontab Using List Parameter](/endpoint/52f6d751-1fd4-4c74-a4c9-777ecfeb5c58/) | [Cron](/tags/#cron), [Scheduled Task/Job](/tags/#scheduled-task/job) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux At Allow Config File Creation](/endpoint/977b3082-5f3d-11ec-b954-acde48001122/) | [Cron](/tags/#cron), [Scheduled Task/Job](/tags/#scheduled-task/job) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux At Application Execution](/endpoint/bf0a378e-5f3c-11ec-a6de-acde48001122/) | [At](/tags/#at), [Scheduled Task/Job](/tags/#scheduled-task/job) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Change File Owner To Root](/endpoint/c1400ea2-6257-11ec-ad49-acde48001122/) | [Linux and Mac File and Directory Permissions Modification](/tags/#linux-and-mac-file-and-directory-permissions-modification), [File and Directory Permissions Modification](/tags/#file-and-directory-permissions-modification) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Clipboard Data Copy](/endpoint/7173b2ad-6146-418f-85ae-c3479e4515fc/) | [Clipboard Data](/tags/#clipboard-data) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Common Process For Elevation Control](/endpoint/66ab15c0-63d0-11ec-9e70-acde48001122/) | [Setuid and Setgid](/tags/#setuid-and-setgid), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Decode Base64 to Shell](/endpoint/637b603e-1799-40fd-bf87-47ecbd551b66/) | [Obfuscated Files or Information](/tags/#obfuscated-files-or-information), [Unix Shell](/tags/#unix-shell) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Edit Cron Table Parameter](/endpoint/0d370304-5f26-11ec-a4bb-acde48001122/) | [Cron](/tags/#cron), [Scheduled Task/Job](/tags/#scheduled-task/job) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Obfuscated Files or Information Base64 Decode](/endpoint/303b38b2-c03f-44e2-8f41-4594606fcfc7/) | [Obfuscated Files or Information](/tags/#obfuscated-files-or-information) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Possible Access Or Modification Of sshd Config File](/endpoint/7a85eb24-72da-11ec-ac76-acde48001122/) | [SSH Authorized Keys](/tags/#ssh-authorized-keys), [Account Manipulation](/tags/#account-manipulation) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Possible Append Cronjob Entry on Existing Cronjob File](/endpoint/b5b91200-5f27-11ec-bb4e-acde48001122/) | [Cron](/tags/#cron), [Scheduled Task/Job](/tags/#scheduled-task/job) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Possible Cronjob Modification With Editor](/endpoint/dcc89bde-5f24-11ec-87ca-acde48001122/) | [Cron](/tags/#cron), [Scheduled Task/Job](/tags/#scheduled-task/job) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Possible Ssh Key File Creation](/endpoint/c04ef40c-72da-11ec-8eac-acde48001122/) | [SSH Authorized Keys](/tags/#ssh-authorized-keys), [Account Manipulation](/tags/#account-manipulation) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux SSH Authorized Keys Modification](/endpoint/f5ab595e-28e5-4327-8077-5008ba97c850/) | [SSH Authorized Keys](/tags/#ssh-authorized-keys) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux SSH Remote Services Script Execute](/endpoint/aa1748dd-4a5c-457a-9cf6-ca7b4eb711b3/) | [SSH](/tags/#ssh) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Service File Created In Systemd Directory](/endpoint/c7495048-61b6-11ec-9a37-acde48001122/) | [Systemd Timers](/tags/#systemd-timers), [Scheduled Task/Job](/tags/#scheduled-task/job) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Service Restarted](/endpoint/084275ba-61b8-11ec-8d64-acde48001122/) | [Systemd Timers](/tags/#systemd-timers), [Scheduled Task/Job](/tags/#scheduled-task/job) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Service Started Or Enabled](/endpoint/e0428212-61b7-11ec-88a3-acde48001122/) | [Systemd Timers](/tags/#systemd-timers), [Scheduled Task/Job](/tags/#scheduled-task/job) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Setuid Using Chmod Utility](/endpoint/bf0304b6-6250-11ec-9d7c-acde48001122/) | [Setuid and Setgid](/tags/#setuid-and-setgid), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux pkexec Privilege Escalation](/endpoint/03e22c1c-8086-11ec-ac2e-acde48001122/) | [Exploitation for Privilege Escalation](/tags/#exploitation-for-privilege-escalation) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Curl Network Connection](/endpoint/3f613dc0-21f2-4063-93b1-5d3c15eef22f/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://gtfobins.github.io/](https://gtfobins.github.io/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/linux_living_off_the_land.yml) \| *version*: **1**