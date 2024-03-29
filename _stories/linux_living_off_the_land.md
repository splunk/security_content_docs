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
| [Linux APT Privilege Escalation](/endpoint/4d5a05fa-77d9-4fd0-af9c-05704f9f9a88/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux AWK Privilege Escalation](/endpoint/4510cae0-96a2-4840-9919-91d262db210a/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Add Files In Known Crontab Directories](/endpoint/023f3452-5f27-11ec-bf00-acde48001122/) | [Cron](/tags/#cron), [Scheduled Task/Job](/tags/#scheduled-task/job) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Adding Crontab Using List Parameter](/endpoint/52f6d751-1fd4-4c74-a4c9-777ecfeb5c58/) | [Cron](/tags/#cron), [Scheduled Task/Job](/tags/#scheduled-task/job) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux At Allow Config File Creation](/endpoint/977b3082-5f3d-11ec-b954-acde48001122/) | [Cron](/tags/#cron), [Scheduled Task/Job](/tags/#scheduled-task/job) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux At Application Execution](/endpoint/bf0a378e-5f3c-11ec-a6de-acde48001122/) | [At](/tags/#at), [Scheduled Task/Job](/tags/#scheduled-task/job) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Busybox Privilege Escalation](/endpoint/387c4e78-f4a4-413d-ad44-e9f7bc4642c9/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Change File Owner To Root](/endpoint/c1400ea2-6257-11ec-ad49-acde48001122/) | [Linux and Mac File and Directory Permissions Modification](/tags/#linux-and-mac-file-and-directory-permissions-modification), [File and Directory Permissions Modification](/tags/#file-and-directory-permissions-modification) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Clipboard Data Copy](/endpoint/7173b2ad-6146-418f-85ae-c3479e4515fc/) | [Clipboard Data](/tags/#clipboard-data) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Common Process For Elevation Control](/endpoint/66ab15c0-63d0-11ec-9e70-acde48001122/) | [Setuid and Setgid](/tags/#setuid-and-setgid), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Composer Privilege Escalation](/endpoint/a3bddf71-6ba3-42ab-a6b2-396929b16d92/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Cpulimit Privilege Escalation](/endpoint/d4e40b7e-aad3-4a7d-aac8-550ea5222be5/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Csvtool Privilege Escalation](/endpoint/f8384f9e-1a5c-4c3a-96d6-8a7e5a38a8b8/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Curl Upload File](/endpoint/c1de2d9a-0c02-4bb4-a49a-510c6e9cf2bf/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Decode Base64 to Shell](/endpoint/637b603e-1799-40fd-bf87-47ecbd551b66/) | [Obfuscated Files or Information](/tags/#obfuscated-files-or-information), [Unix Shell](/tags/#unix-shell) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Docker Privilege Escalation](/endpoint/2e7bfb78-85f6-47b5-bc2f-15813a4ef2b3/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Edit Cron Table Parameter](/endpoint/0d370304-5f26-11ec-a4bb-acde48001122/) | [Cron](/tags/#cron), [Scheduled Task/Job](/tags/#scheduled-task/job) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Emacs Privilege Escalation](/endpoint/92033cab-1871-483d-a03b-a7ce98665cfc/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Find Privilege Escalation](/endpoint/2ff4e0c2-8256-4143-9c07-1e39c7231111/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux GDB Privilege Escalation](/endpoint/310b7da2-ab52-437f-b1bf-0bd458674308/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux GNU Awk Privilege Escalation](/endpoint/0dcf43b9-50d8-42a6-acd9-d1c9201fe6ae/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Gem Privilege Escalation](/endpoint/0115482a-5dcb-4bb0-bcca-5d095d224236/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Ingress Tool Transfer Hunting](/endpoint/52fd468b-cb6d-48f5-b16a-92f1c9bb10cf/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Ingress Tool Transfer with Curl](/endpoint/8c1de57d-abc1-4b41-a727-a7a8fc5e0857/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Make Privilege Escalation](/endpoint/80b22836-5091-4944-80ee-f733ac443f4f/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux MySQL Privilege Escalation](/endpoint/c0d810f4-230c-44ea-b703-989da02ff145/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Node Privilege Escalation](/endpoint/2e58a4ff-398f-42f4-8fd0-e01ebfe2a8ce/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Obfuscated Files or Information Base64 Decode](/endpoint/303b38b2-c03f-44e2-8f41-4594606fcfc7/) | [Obfuscated Files or Information](/tags/#obfuscated-files-or-information) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Octave Privilege Escalation](/endpoint/78f7487d-42ce-4f7f-8685-2159b25fb477/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux OpenVPN Privilege Escalation](/endpoint/d25feebe-fa1c-4754-8a1e-afb03bedc0f2/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux PHP Privilege Escalation](/endpoint/4fc4c031-e5be-4cc0-8cf9-49f9f507bcb5/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Possible Access Or Modification Of sshd Config File](/endpoint/7a85eb24-72da-11ec-ac76-acde48001122/) | [SSH Authorized Keys](/tags/#ssh-authorized-keys), [Account Manipulation](/tags/#account-manipulation) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Possible Append Cronjob Entry on Existing Cronjob File](/endpoint/b5b91200-5f27-11ec-bb4e-acde48001122/) | [Cron](/tags/#cron), [Scheduled Task/Job](/tags/#scheduled-task/job) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Possible Cronjob Modification With Editor](/endpoint/dcc89bde-5f24-11ec-87ca-acde48001122/) | [Cron](/tags/#cron), [Scheduled Task/Job](/tags/#scheduled-task/job) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Possible Ssh Key File Creation](/endpoint/c04ef40c-72da-11ec-8eac-acde48001122/) | [SSH Authorized Keys](/tags/#ssh-authorized-keys), [Account Manipulation](/tags/#account-manipulation) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Proxy Socks Curl](/endpoint/bd596c22-ad1e-44fc-b242-817253ce8b08/) | [Proxy](/tags/#proxy), [Non-Application Layer Protocol](/tags/#non-application-layer-protocol) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Puppet Privilege Escalation](/endpoint/1d19037f-466e-4d56-8d87-36fafd9aa3ce/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux RPM Privilege Escalation](/endpoint/f8e58a23-cecd-495f-9c65-6c76b4cb9774/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Ruby Privilege Escalation](/endpoint/097b28b5-7004-4d40-a715-7e390501788b/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux SSH Authorized Keys Modification](/endpoint/f5ab595e-28e5-4327-8077-5008ba97c850/) | [SSH Authorized Keys](/tags/#ssh-authorized-keys) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux SSH Remote Services Script Execute](/endpoint/aa1748dd-4a5c-457a-9cf6-ca7b4eb711b3/) | [SSH](/tags/#ssh) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Service File Created In Systemd Directory](/endpoint/c7495048-61b6-11ec-9a37-acde48001122/) | [Systemd Timers](/tags/#systemd-timers), [Scheduled Task/Job](/tags/#scheduled-task/job) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Service Restarted](/endpoint/084275ba-61b8-11ec-8d64-acde48001122/) | [Systemd Timers](/tags/#systemd-timers), [Scheduled Task/Job](/tags/#scheduled-task/job) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Service Started Or Enabled](/endpoint/e0428212-61b7-11ec-88a3-acde48001122/) | [Systemd Timers](/tags/#systemd-timers), [Scheduled Task/Job](/tags/#scheduled-task/job) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Setuid Using Chmod Utility](/endpoint/bf0304b6-6250-11ec-9d7c-acde48001122/) | [Setuid and Setgid](/tags/#setuid-and-setgid), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Sqlite3 Privilege Escalation](/endpoint/ab75dbb7-c3ba-4689-9c1b-8d2717bdcba1/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux apt-get Privilege Escalation](/endpoint/d870ce3b-e796-402f-b2af-cab4da1223f2/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux c89 Privilege Escalation](/endpoint/54c95f4d-3e5d-44be-9521-ea19ba62f7a8/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux c99 Privilege Escalation](/endpoint/e1c6dec5-2249-442d-a1f9-99a4bd228183/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux pkexec Privilege Escalation](/endpoint/03e22c1c-8086-11ec-ac2e-acde48001122/) | [Exploitation for Privilege Escalation](/tags/#exploitation-for-privilege-escalation) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Curl Network Connection](/endpoint/3f613dc0-21f2-4063-93b1-5d3c15eef22f/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://gtfobins.github.io/](https://gtfobins.github.io/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/linux_living_off_the_land.yml) \| *version*: **1**