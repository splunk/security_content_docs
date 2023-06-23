---
title: "Scheduled Tasks"
last_modified_at: 2023-06-12
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

The MITRE ATT&CK technique T1053 refers to Scheduled Task/Job. Adversaries might use task scheduling utilities to execute programs or scripts at a predefined date and time. This method is often used for persistence but can also be used for privilege escalation or to execute tasks under certain conditions. Scheduling tasks can be beneficial for an attacker as it can allow them to execute actions at times when the system is less likely to be monitored actively. Different operating systems have different utilities for task scheduling, for example, Unix-like systems have Cron, while Windows has Scheduled Tasks and At Jobs.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2023-06-12
- **Author**: Michael Haag, Splunk
- **ID**: 94cff925-d05c-40cf-b925-d6c5702a2399

#### Narrative

MITRE ATT&CK technique T1053, labeled "Scheduled Task/Job", is a categorization of methods that adversaries use to execute malicious code by scheduling tasks or jobs on a system. This technique is widely utilized for persistence, privilege escalation, and the remote execution of tasks. The technique is applicable across various environments and platforms, including Windows, Linux, and macOS.\
The technique consists of multiple sub-techniques, each highlighting a distinct mechanism for scheduling tasks or jobs. These sub-techniques include T1053.001 (Scheduled Task), T1053.002 (At for Windows), T1053.003 (Cron), T1053.004 (Launchd), T1053.005 (At for Linux), and T1053.006 (Systemd Timers).\
Scheduled Task (T1053.001) focuses on adversaries' methods for scheduling tasks on a Windows system to maintain persistence or escalate privileges. These tasks can be set to execute at specified times, in response to particular events, or after a defined time interval.\
The At command for Windows (T1053.002) enables administrators to schedule tasks on a Windows system. Adversaries may exploit this command to execute programs at system startup or at a predetermined schedule for persistence.\
Cron (T1053.003) is a built-in job scheduler found in Unix-like operating systems. Adversaries can use cron jobs to execute programs at system startup or on a scheduled basis for persistence.\
Launchd (T1053.004) is a service management framework present in macOS. Adversaries may utilize launchd to maintain persistence on macOS systems by setting up daemons or agents to execute at specific times or in response to defined events.\
The At command for Linux (T1053.005) enables administrators to schedule tasks on a Linux system. Adversaries can use this command to execute programs at system startup or on a scheduled basis for persistence.\
Systemd Timers (T1053.006) offer a means of scheduling tasks on Linux systems using systemd. Adversaries can use systemd timers to execute programs at system startup or on a scheduled basis for persistence.\
Detection and mitigation strategies vary for each sub-technique. For instance, monitoring the creation of scheduled tasks or looking for uncorrelated changes to tasks that do not align with known software or patch cycles can be effective for detecting malicious activity related to this technique. Mitigation strategies may involve restricting permissions and applying application control solutions to prevent adversaries from scheduling tasks.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Linux Add Files In Known Crontab Directories](/endpoint/023f3452-5f27-11ec-bf00-acde48001122/) | [Cron](/tags/#cron), [Scheduled Task/Job](/tags/#scheduled-task/job) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Adding Crontab Using List Parameter](/endpoint/52f6d751-1fd4-4c74-a4c9-777ecfeb5c58/) | [Cron](/tags/#cron), [Scheduled Task/Job](/tags/#scheduled-task/job) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux At Allow Config File Creation](/endpoint/977b3082-5f3d-11ec-b954-acde48001122/) | [Cron](/tags/#cron), [Scheduled Task/Job](/tags/#scheduled-task/job) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux At Application Execution](/endpoint/bf0a378e-5f3c-11ec-a6de-acde48001122/) | [At](/tags/#at), [Scheduled Task/Job](/tags/#scheduled-task/job) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Edit Cron Table Parameter](/endpoint/0d370304-5f26-11ec-a4bb-acde48001122/) | [Cron](/tags/#cron), [Scheduled Task/Job](/tags/#scheduled-task/job) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Possible Append Command To At Allow Config File](/endpoint/7bc20606-5f40-11ec-a586-acde48001122/) | [At](/tags/#at), [Scheduled Task/Job](/tags/#scheduled-task/job) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Possible Append Cronjob Entry on Existing Cronjob File](/endpoint/b5b91200-5f27-11ec-bb4e-acde48001122/) | [Cron](/tags/#cron), [Scheduled Task/Job](/tags/#scheduled-task/job) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Possible Cronjob Modification With Editor](/endpoint/dcc89bde-5f24-11ec-87ca-acde48001122/) | [Cron](/tags/#cron), [Scheduled Task/Job](/tags/#scheduled-task/job) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Service File Created In Systemd Directory](/endpoint/c7495048-61b6-11ec-9a37-acde48001122/) | [Systemd Timers](/tags/#systemd-timers), [Scheduled Task/Job](/tags/#scheduled-task/job) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Service Restarted](/endpoint/084275ba-61b8-11ec-8d64-acde48001122/) | [Systemd Timers](/tags/#systemd-timers), [Scheduled Task/Job](/tags/#scheduled-task/job) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Service Started Or Enabled](/endpoint/e0428212-61b7-11ec-88a3-acde48001122/) | [Systemd Timers](/tags/#systemd-timers), [Scheduled Task/Job](/tags/#scheduled-task/job) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Possible Lateral Movement PowerShell Spawn](/endpoint/cb909b3e-512b-11ec-aa31-3e22fbd008af/) | [Remote Services](/tags/#remote-services), [Distributed Component Object Model](/tags/#distributed-component-object-model), [Windows Remote Management](/tags/#windows-remote-management), [Windows Management Instrumentation](/tags/#windows-management-instrumentation), [Scheduled Task](/tags/#scheduled-task), [Windows Service](/tags/#windows-service), [PowerShell](/tags/#powershell), [MMC](/tags/#mmc) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Randomly Generated Scheduled Task Name](/endpoint/9d22a780-5165-11ec-ad4f-3e22fbd008af/) | [Scheduled Task/Job](/tags/#scheduled-task/job), [Scheduled Task](/tags/#scheduled-task) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Schedule Task with HTTP Command Arguments](/endpoint/523c2684-a101-11eb-916b-acde48001122/) | [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Schedule Task with Rundll32 Command Trigger](/endpoint/75b00fd8-a0ff-11eb-8b31-acde48001122/) | [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Scheduled Task Creation on Remote Endpoint using At](/endpoint/4be54858-432f-11ec-8209-3e22fbd008af/) | [Scheduled Task/Job](/tags/#scheduled-task/job), [At](/tags/#at) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Scheduled Task Deleted Or Created via CMD](/endpoint/d5af132c-7c17-439c-9d31-13d55340f36c/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Scheduled Task Initiation on Remote Endpoint](/endpoint/95cf4608-4302-11ec-8194-3e22fbd008af/) | [Scheduled Task/Job](/tags/#scheduled-task/job), [Scheduled Task](/tags/#scheduled-task) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Schtasks Run Task On Demand](/endpoint/bb37061e-af1f-11eb-a159-acde48001122/) | [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Schtasks scheduling job on remote system](/endpoint/1297fb80-f42a-4b4a-9c8a-88c066237cf6/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Schtasks used for forcing a reboot](/endpoint/1297fb80-f42a-4b4a-9c8a-88c066437cf6/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Short Lived Scheduled Task](/endpoint/6fa31414-546e-11ec-adfa-acde48001122/) | [Scheduled Task](/tags/#scheduled-task) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Scheduled Task from Public Directory](/endpoint/7feb7972-7ac3-11eb-bac8-acde48001122/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Svchost LOLBAS Execution Process Spawn](/endpoint/09e5c72a-4c0d-11ec-aa29-3e22fbd008af/) | [Scheduled Task/Job](/tags/#scheduled-task/job), [Scheduled Task](/tags/#scheduled-task) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [WinEvent Scheduled Task Created Within Public Path](/endpoint/5d9c6eee-988c-11eb-8253-acde48001122/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [WinEvent Scheduled Task Created to Spawn Shell](/endpoint/203ef0ea-9bd8-11eb-8201-acde48001122/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [WinEvent Windows Task Scheduler Event Action Started](/endpoint/b3632472-310b-11ec-9aab-acde48001122/) | [Scheduled Task](/tags/#scheduled-task) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Enable Win32 ScheduledJob via Registry](/endpoint/12c80db8-ef62-4456-92df-b23e1b3219f6/) | [Scheduled Task](/tags/#scheduled-task) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Hidden Schedule Task Settings](/endpoint/0b730470-5fe8-4b13-93a7-fe0ad014d0cc/) | [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows PowerShell ScheduleTask](/endpoint/ddf82fcb-e9ee-40e3-8712-a50b5bf323fc/) | [Scheduled Task](/tags/#scheduled-task), [PowerShell](/tags/#powershell), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Registry Delete Task SD](/endpoint/ffeb7893-ff06-446f-815b-33ca73224e92/) | [Scheduled Task](/tags/#scheduled-task), [Impair Defenses](/tags/#impair-defenses) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Scheduled Task Created Via XML](/endpoint/7e03b682-3965-4598-8e91-a60a40a3f7e4/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Scheduled Task with Highest Privileges](/endpoint/2f15e1a4-0fc2-49dd-919e-cbbe60699218/) | [Scheduled Task/Job](/tags/#scheduled-task/job), [Scheduled Task](/tags/#scheduled-task) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Schtasks Create Run As System](/endpoint/41a0e58e-884c-11ec-9976-acde48001122/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://attack.mitre.org/techniques/T1053/](https://attack.mitre.org/techniques/T1053/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/scheduled_tasks.yml) \| *version*: **1**