---
title: "Windows Log Manipulation"
last_modified_at: 2017-09-12
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Endpoint_Processes
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Adversaries often try to cover their tracks by manipulating Windows logs. Use these searches to help you monitor for suspicious activity surrounding log files--an essential component of an effective defense.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Endpoint_Processes](https://docs.splunk.com/Documentation/CIM/latest/User/EndpointProcesses)
- **Last Updated**: 2017-09-12
- **Author**: Rico Valdez, Splunk
- **ID**: b6db2c60-a281-48b4-95f1-2cd99ed56835

#### Narrative

Because attackers often modify system logs to cover their tracks and/or to thwart the investigative process, log monitoring is an industry-recognized best practice. While there are legitimate reasons to manipulate system logs, it is still worthwhile to keep track of who manipulated the logs, when they manipulated them, and in what way they manipulated them (determining which accesses, tools, or utilities were employed). Even if no malicious activity is detected, the knowledge of an attempt to manipulate system logs may be indicative of a broader security risk that should be thoroughly investigated.\
The Analytic Story gives users two different ways to detect manipulation of Windows Event Logs and one way to detect deletion of the Update Sequence Number (USN) Change Journal. The story helps determine the history of the host and the users who have accessed it. Finally, the story aides in investigation by retrieving all the information on the process that caused these events (if the process has been identified).

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Deleting Shadow Copies](/endpoint/b89919ed-ee5f-492c-b139-95dbb162039e/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Event Log Service Behavior](/endpoint/2b85aa3d-f5f6-4c2e-a081-a09f6e1c2e40/) | [Indicator Removal on Host](/tags/#indicator-removal-on-host), [Clear Windows Event Logs](/tags/#clear-windows-event-logs) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious wevtutil Usage](/endpoint/2827c0fd-e1be-4868-ae25-59d28e0f9d4f/) | [Clear Windows Event Logs](/tags/#clear-windows-event-logs), [Indicator Removal on Host](/tags/#indicator-removal-on-host) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [USN Journal Deletion](/endpoint/b6e0ff70-b122-4227-9368-4cf322ab43c3/) | [Indicator Removal on Host](/tags/#indicator-removal-on-host) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [WevtUtil Usage To Clear Logs](/endpoint/5438113c-cdd9-11eb-93b8-acde48001122/) | [Indicator Removal on Host](/tags/#indicator-removal-on-host), [Clear Windows Event Logs](/tags/#clear-windows-event-logs) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Wevtutil Usage To Disable Logs](/endpoint/a4bdc944-cdd9-11eb-ac97-acde48001122/) | [Indicator Removal on Host](/tags/#indicator-removal-on-host), [Clear Windows Event Logs](/tags/#clear-windows-event-logs) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Event Log Cleared](/endpoint/ad517544-aff9-4c96-bd99-d6eb43bfbb6a/) | [Indicator Removal on Host](/tags/#indicator-removal-on-host), [Clear Windows Event Logs](/tags/#clear-windows-event-logs) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/](https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/)
* [https://zeltser.com/security-incident-log-review-checklist/](https://zeltser.com/security-incident-log-review-checklist/)
* [http://journeyintoir.blogspot.com/2013/01/re-introducing-usnjrnl.html](http://journeyintoir.blogspot.com/2013/01/re-introducing-usnjrnl.html)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/windows_log_manipulation.yml) \| *version*: **2**