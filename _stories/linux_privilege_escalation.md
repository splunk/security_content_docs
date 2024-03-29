---
title: "Linux Privilege Escalation"
last_modified_at: 2021-12-17
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Risk
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Monitor for and investigate activities that may be associated with a Linux privilege-escalation attack, including unusual processes running on endpoints, schedule task, services, setuid, root execution and more.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Risk](https://docs.splunk.com/Documentation/CIM/latest/User/Risk)
- **Last Updated**: 2021-12-17
- **Author**: Teoderick Contreras, Splunk
- **ID**: b9879c24-670a-44c0-895e-98cdb7d0e848

#### Narrative

Privilege escalation is a "land-and-expand" technique, wherein an adversary gains an initial foothold on a host and then exploits its weaknesses to increase his privileges. The motivation is simple: certain actions on a Linux machine--such as installing software--may require higher-level privileges than those the attacker initially acquired. By increasing his privilege level, the attacker can gain the control required to carry out his malicious ends. This Analytic Story provides searches to detect and investigate behaviors that attackers may use to elevate their privileges in your environment.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Linux APT Privilege Escalation](/endpoint/4d5a05fa-77d9-4fd0-af9c-05704f9f9a88/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux AWK Privilege Escalation](/endpoint/4510cae0-96a2-4840-9919-91d262db210a/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Add Files In Known Crontab Directories](/endpoint/023f3452-5f27-11ec-bf00-acde48001122/) | [Cron](/tags/#cron), [Scheduled Task/Job](/tags/#scheduled-task/job) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Add User Account](/endpoint/51fbcaf2-6259-11ec-b0f3-acde48001122/) | [Local Account](/tags/#local-account), [Create Account](/tags/#create-account) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Adding Crontab Using List Parameter](/endpoint/52f6d751-1fd4-4c74-a4c9-777ecfeb5c58/) | [Cron](/tags/#cron), [Scheduled Task/Job](/tags/#scheduled-task/job) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux At Allow Config File Creation](/endpoint/977b3082-5f3d-11ec-b954-acde48001122/) | [Cron](/tags/#cron), [Scheduled Task/Job](/tags/#scheduled-task/job) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux At Application Execution](/endpoint/bf0a378e-5f3c-11ec-a6de-acde48001122/) | [At](/tags/#at), [Scheduled Task/Job](/tags/#scheduled-task/job) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Busybox Privilege Escalation](/endpoint/387c4e78-f4a4-413d-ad44-e9f7bc4642c9/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Change File Owner To Root](/endpoint/c1400ea2-6257-11ec-ad49-acde48001122/) | [Linux and Mac File and Directory Permissions Modification](/tags/#linux-and-mac-file-and-directory-permissions-modification), [File and Directory Permissions Modification](/tags/#file-and-directory-permissions-modification) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Common Process For Elevation Control](/endpoint/66ab15c0-63d0-11ec-9e70-acde48001122/) | [Setuid and Setgid](/tags/#setuid-and-setgid), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Composer Privilege Escalation](/endpoint/a3bddf71-6ba3-42ab-a6b2-396929b16d92/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Cpulimit Privilege Escalation](/endpoint/d4e40b7e-aad3-4a7d-aac8-550ea5222be5/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Csvtool Privilege Escalation](/endpoint/f8384f9e-1a5c-4c3a-96d6-8a7e5a38a8b8/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Doas Conf File Creation](/endpoint/f6343e86-6e09-11ec-9376-acde48001122/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Doas Tool Execution](/endpoint/d5a62490-6e09-11ec-884e-acde48001122/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Docker Privilege Escalation](/endpoint/2e7bfb78-85f6-47b5-bc2f-15813a4ef2b3/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Edit Cron Table Parameter](/endpoint/0d370304-5f26-11ec-a4bb-acde48001122/) | [Cron](/tags/#cron), [Scheduled Task/Job](/tags/#scheduled-task/job) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Emacs Privilege Escalation](/endpoint/92033cab-1871-483d-a03b-a7ce98665cfc/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux File Created In Kernel Driver Directory](/endpoint/b85bbeec-6326-11ec-9311-acde48001122/) | [Kernel Modules and Extensions](/tags/#kernel-modules-and-extensions), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux File Creation In Init Boot Directory](/endpoint/97d9cfb2-61ad-11ec-bb2d-acde48001122/) | [RC Scripts](/tags/#rc-scripts), [Boot or Logon Initialization Scripts](/tags/#boot-or-logon-initialization-scripts) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux File Creation In Profile Directory](/endpoint/46ba0082-61af-11ec-9826-acde48001122/) | [Unix Shell Configuration Modification](/tags/#unix-shell-configuration-modification), [Event Triggered Execution](/tags/#event-triggered-execution) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Find Privilege Escalation](/endpoint/2ff4e0c2-8256-4143-9c07-1e39c7231111/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux GDB Privilege Escalation](/endpoint/310b7da2-ab52-437f-b1bf-0bd458674308/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux GNU Awk Privilege Escalation](/endpoint/0dcf43b9-50d8-42a6-acd9-d1c9201fe6ae/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Gem Privilege Escalation](/endpoint/0115482a-5dcb-4bb0-bcca-5d095d224236/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Insert Kernel Module Using Insmod Utility](/endpoint/18b5a1a0-6326-11ec-943a-acde48001122/) | [Kernel Modules and Extensions](/tags/#kernel-modules-and-extensions), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Install Kernel Module Using Modprobe Utility](/endpoint/387b278a-6326-11ec-aa2c-acde48001122/) | [Kernel Modules and Extensions](/tags/#kernel-modules-and-extensions), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Make Privilege Escalation](/endpoint/80b22836-5091-4944-80ee-f733ac443f4f/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux MySQL Privilege Escalation](/endpoint/c0d810f4-230c-44ea-b703-989da02ff145/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux NOPASSWD Entry In Sudoers File](/endpoint/ab1e0d52-624a-11ec-8e0b-acde48001122/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Node Privilege Escalation](/endpoint/2e58a4ff-398f-42f4-8fd0-e01ebfe2a8ce/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Octave Privilege Escalation](/endpoint/78f7487d-42ce-4f7f-8685-2159b25fb477/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux OpenVPN Privilege Escalation](/endpoint/d25feebe-fa1c-4754-8a1e-afb03bedc0f2/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux PHP Privilege Escalation](/endpoint/4fc4c031-e5be-4cc0-8cf9-49f9f507bcb5/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Persistence and Privilege Escalation Risk Behavior](/endpoint/ad5ac21b-3b1e-492c-8e19-ea5d5e8e5cf1/) | [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Correlation](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Possible Access Or Modification Of sshd Config File](/endpoint/7a85eb24-72da-11ec-ac76-acde48001122/) | [SSH Authorized Keys](/tags/#ssh-authorized-keys), [Account Manipulation](/tags/#account-manipulation) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Possible Access To Credential Files](/endpoint/16107e0e-71fc-11ec-b862-acde48001122/) | [/etc/passwd and /etc/shadow](/tags/#/etc/passwd-and-/etc/shadow), [OS Credential Dumping](/tags/#os-credential-dumping) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Possible Access To Sudoers File](/endpoint/4479539c-71fc-11ec-b2e2-acde48001122/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Possible Append Command To At Allow Config File](/endpoint/7bc20606-5f40-11ec-a586-acde48001122/) | [At](/tags/#at), [Scheduled Task/Job](/tags/#scheduled-task/job) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Possible Append Command To Profile Config File](/endpoint/9c94732a-61af-11ec-91e3-acde48001122/) | [Unix Shell Configuration Modification](/tags/#unix-shell-configuration-modification), [Event Triggered Execution](/tags/#event-triggered-execution) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Possible Append Cronjob Entry on Existing Cronjob File](/endpoint/b5b91200-5f27-11ec-bb4e-acde48001122/) | [Cron](/tags/#cron), [Scheduled Task/Job](/tags/#scheduled-task/job) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Possible Cronjob Modification With Editor](/endpoint/dcc89bde-5f24-11ec-87ca-acde48001122/) | [Cron](/tags/#cron), [Scheduled Task/Job](/tags/#scheduled-task/job) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Possible Ssh Key File Creation](/endpoint/c04ef40c-72da-11ec-8eac-acde48001122/) | [SSH Authorized Keys](/tags/#ssh-authorized-keys), [Account Manipulation](/tags/#account-manipulation) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Preload Hijack Library Calls](/endpoint/cbe2ca30-631e-11ec-8670-acde48001122/) | [Dynamic Linker Hijacking](/tags/#dynamic-linker-hijacking), [Hijack Execution Flow](/tags/#hijack-execution-flow) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Puppet Privilege Escalation](/endpoint/1d19037f-466e-4d56-8d87-36fafd9aa3ce/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux RPM Privilege Escalation](/endpoint/f8e58a23-cecd-495f-9c65-6c76b4cb9774/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Ruby Privilege Escalation](/endpoint/097b28b5-7004-4d40-a715-7e390501788b/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Service File Created In Systemd Directory](/endpoint/c7495048-61b6-11ec-9a37-acde48001122/) | [Systemd Timers](/tags/#systemd-timers), [Scheduled Task/Job](/tags/#scheduled-task/job) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Service Restarted](/endpoint/084275ba-61b8-11ec-8d64-acde48001122/) | [Systemd Timers](/tags/#systemd-timers), [Scheduled Task/Job](/tags/#scheduled-task/job) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Service Started Or Enabled](/endpoint/e0428212-61b7-11ec-88a3-acde48001122/) | [Systemd Timers](/tags/#systemd-timers), [Scheduled Task/Job](/tags/#scheduled-task/job) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Setuid Using Chmod Utility](/endpoint/bf0304b6-6250-11ec-9d7c-acde48001122/) | [Setuid and Setgid](/tags/#setuid-and-setgid), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Setuid Using Setcap Utility](/endpoint/9d96022e-6250-11ec-9a19-acde48001122/) | [Setuid and Setgid](/tags/#setuid-and-setgid), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Shred Overwrite Command](/endpoint/c1952cf1-643c-4965-82de-11c067cbae76/) | [Data Destruction](/tags/#data-destruction) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Sqlite3 Privilege Escalation](/endpoint/ab75dbb7-c3ba-4689-9c1b-8d2717bdcba1/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Sudo OR Su Execution](/endpoint/4b00f134-6d6a-11ec-a90c-acde48001122/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Sudoers Tmp File Creation](/endpoint/be254a5c-63e7-11ec-89da-acde48001122/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Visudo Utility Execution](/endpoint/08c41040-624c-11ec-a71f-acde48001122/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux apt-get Privilege Escalation](/endpoint/d870ce3b-e796-402f-b2af-cab4da1223f2/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux c89 Privilege Escalation](/endpoint/54c95f4d-3e5d-44be-9521-ea19ba62f7a8/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux c99 Privilege Escalation](/endpoint/e1c6dec5-2249-442d-a1f9-99a4bd228183/) | [Sudo and Sudo Caching](/tags/#sudo-and-sudo-caching), [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux pkexec Privilege Escalation](/endpoint/03e22c1c-8086-11ec-ac2e-acde48001122/) | [Exploitation for Privilege Escalation](/tags/#exploitation-for-privilege-escalation) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://attack.mitre.org/tactics/TA0004/](https://attack.mitre.org/tactics/TA0004/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/linux_privilege_escalation.yml) \| *version*: **1**