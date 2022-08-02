---
title: "Suspicious Command-Line Executions"
last_modified_at: 2020-02-03
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

Leveraging the Windows command-line interface (CLI) is one of the most common attack techniques--one that is also detailed in the MITRE ATT&CK framework. Use this Analytic Story to help you identify unusual or suspicious use of the CLI on Windows systems.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Endpoint_Processes](https://docs.splunk.com/Documentation/CIM/latest/User/EndpointProcesses)
- **Last Updated**: 2020-02-03
- **Author**: Bhavin Patel, Splunk
- **ID**: f4368ddf-d59f-4192-84f6-778ac5a3ffc7

#### Narrative

The ability to execute arbitrary commands via the Windows CLI is a primary goal for the adversary. With access to the shell, an attacker can easily run scripts and interact with the target system. Often, attackers may only have limited access to the shell or may obtain access in unusual ways. In addition, malware may execute and interact with the CLI in ways that would be considered unusual and inconsistent with typical user activity. This provides defenders with opportunities to identify suspicious use and investigate, as appropriate. This Analytic Story contains various searches to help identify this suspicious activity, as well as others to aid you in deeper investigation.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Detect Prohibited Applications Spawning cmd exe](/endpoint/dcfd6b40-42f9-469d-a433-2e53f7486664/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [Windows Command Shell](/tags/#windows-command-shell) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Prohibited Applications Spawning cmd exe](/endpoint/c10a18cb-fd80-4ffa-a844-25026e0a0c94/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Use of cmd exe to Launch Script Interpreters](/endpoint/b89919ed-fe5f-492c-b139-95dbb162039e/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [Windows Command Shell](/tags/#windows-command-shell) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [First time seen command line argument](/deprecated/a1b6e73f-98d5-470f-99ac-77aacd578473/) | [PowerShell](/tags/#powershell), [Windows Command Shell](/tags/#windows-command-shell) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Potentially malicious code on commandline](/endpoint/9c53c446-757e-11ec-871d-acde48001122/) | [Windows Command Shell](/tags/#windows-command-shell) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [System Processes Run From Unexpected Locations](/endpoint/a34aae96-ccf8-4aef-952c-3ea21444444d/) | [Masquerading](/tags/#masquerading), [Rename System Utilities](/tags/#rename-system-utilities) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Unusually Long Command Line](/endpoint/c77162d3-f93c-45cc-80c8-22f6a4264e7f/) |  | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Unusually Long Command Line - MLTK](/endpoint/57edaefa-a73b-45e5-bbae-f39c1473f941/) |  | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://attack.mitre.org/wiki/Technique/T1059](https://attack.mitre.org/wiki/Technique/T1059)
* [https://www.microsoft.com/en-us/wdsi/threats/macro-malware](https://www.microsoft.com/en-us/wdsi/threats/macro-malware)
* [https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/mandiant-apt1-report.pdf](https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/mandiant-apt1-report.pdf)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/suspicious_command_line_executions.yml) \| *version*: **2**