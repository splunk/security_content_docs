---
title: "Suspicious WMI Use"
last_modified_at: 2018-10-23
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

Attackers are increasingly abusing Windows Management Instrumentation (WMI), a framework and associated utilities available on all modern Windows operating systems. Because WMI can be leveraged to manage both local and remote systems, it is important to identify the processes executed and the user context within which the activity occurred.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2018-10-23
- **Author**: Rico Valdez, Splunk
- **ID**: c8ddc5be-69bc-4202-b3ab-4010b27d7ad5

#### Narrative

WMI is a Microsoft infrastructure for management data and operations on Windows operating systems. It includes of a set of utilities that can be leveraged to manage both local and remote Windows systems. Attackers are increasingly turning to WMI abuse in their efforts to conduct nefarious tasks, such as reconnaissance, detection of antivirus and virtual machines, code execution, lateral movement, persistence, and data exfiltration. The detection searches included in this Analytic Story are used to look for suspicious use of WMI commands that attackers may leverage to interact with remote systems. The searches specifically look for the use of WMI to run processes on remote systems. In the event that unauthorized WMI execution occurs, it will be important for analysts and investigators to determine the context of the event. These details may provide insights related to how WMI was used and to what end.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Detect WMI Event Subscription Persistence](/endpoint/01d9a0c2-cece-11eb-ab46-acde48001122/) | [Windows Management Instrumentation Event Subscription](/tags/#windows-management-instrumentation-event-subscription), [Event Triggered Execution](/tags/#event-triggered-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [PowerShell Invoke WmiExec Usage](/endpoint/0734bd21-2769-4972-a5f1-78bb1e011224/) | [Windows Management Instrumentation](/tags/#windows-management-instrumentation) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Process Execution via WMI](/endpoint/24869767-8579-485d-9a4f-d9ddfd8f0cac/) | [Windows Management Instrumentation](/tags/#windows-management-instrumentation) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Remote Process Instantiation via WMI](/endpoint/d25d2c3d-d9d8-40ec-8fdf-e86fe155a3da/) | [Windows Management Instrumentation](/tags/#windows-management-instrumentation) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Remote WMI Command Attempt](/endpoint/272df6de-61f1-4784-877c-1fbc3e2d0838/) | [Windows Management Instrumentation](/tags/#windows-management-instrumentation) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Script Execution via WMI](/endpoint/aa73f80d-d728-4077-b226-81ea0c8be589/) | [Windows Management Instrumentation](/tags/#windows-management-instrumentation) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [WMI Permanent Event Subscription](/endpoint/71bfdb13-f200-4c6c-b2c9-a2e07adf437d/) | [Windows Management Instrumentation](/tags/#windows-management-instrumentation) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [WMI Permanent Event Subscription - Sysmon](/endpoint/ad05aae6-3b2a-4f73-af97-57bd26cee3b9/) | [Windows Management Instrumentation Event Subscription](/tags/#windows-management-instrumentation-event-subscription), [Event Triggered Execution](/tags/#event-triggered-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [WMI Temporary Event Subscription](/endpoint/38cbd42c-1098-41bb-99cf-9d6d2b296d83/) | [Windows Management Instrumentation](/tags/#windows-management-instrumentation) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [WMIC XSL Execution via URL](/endpoint/787e9dd0-4328-11ec-a029-acde48001122/) | [XSL Script Processing](/tags/#xsl-script-processing) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows WMI Process Call Create](/endpoint/0661c2de-93de-11ec-9833-acde48001122/) | [Windows Management Instrumentation](/tags/#windows-management-instrumentation) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [XSL Script Execution With WMIC](/endpoint/004e32e2-146d-11ec-a83f-acde48001122/) | [XSL Script Processing](/tags/#xsl-script-processing) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor-wp.pdf](https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor-wp.pdf)
* [https://web.archive.org/web/20210921091529/https://www.fireeye.com/blog/threat-research/2017/03/wmimplant_a_wmi_ba.html](https://web.archive.org/web/20210921091529/https://www.fireeye.com/blog/threat-research/2017/03/wmimplant_a_wmi_ba.html)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/suspicious_wmi_use.yml) \| *version*: **2**