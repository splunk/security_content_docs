---
title: "Clop Ransomware"
last_modified_at: 2021-03-17
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Endpoint_Filesystem
  - Endpoint_Processes
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Leverage searches that allow you to detect and investigate unusual activities that might relate to the Clop ransomware, including looking for file writes associated with Clope, encrypting network shares, deleting and resizing shadow volume storage, registry key modification, deleting of security logs, and more.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Endpoint_Filesystem](https://docs.splunk.com/Documentation/CIM/latest/User/EndpointFilesystem), [Endpoint_Processes](https://docs.splunk.com/Documentation/CIM/latest/User/EndpointProcesses)
- **Last Updated**: 2021-03-17
- **Author**: Rod Soto, Teoderick Contreras, Splunk
- **ID**: 5a6f6849-1a26-4fae-aa05-fa730556eeb6

#### Narrative

Clop ransomware campaigns targeting healthcare and other vertical sectors, involve the use of ransomware payloads along with exfiltration of data per HHS bulletin. Malicious actors demand payment for ransome of data and threaten deletion and exposure of exfiltrated data.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Clop Common Exec Parameter](/endpoint/5a8a2a72-8322-11eb-9ee9-acde48001122/) | [User Execution](/tags/#user-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Clop Ransomware Known Service Name](/endpoint/07e08a12-870c-11eb-b5f9-acde48001122/) | [Create or Modify System Process](/tags/#create-or-modify-system-process) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Common Ransomware Extensions](/endpoint/a9e5c5db-db11-43ca-86a8-c852d1b2c0ec/) | [Data Destruction](/tags/#data-destruction) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Common Ransomware Notes](/endpoint/ada0f478-84a8-4641-a3f1-d82362d6bd71/) | [Data Destruction](/tags/#data-destruction) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Deleting Shadow Copies](/endpoint/b89919ed-ee5f-492c-b139-95dbb162039e/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [High File Deletion Frequency](/endpoint/b6200efd-13bd-4336-920a-057b25bbcfaf/) | [Data Destruction](/tags/#data-destruction) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [High Process Termination Frequency](/endpoint/17cd75b2-8666-11eb-9ab4-acde48001122/) | [Data Encrypted for Impact](/tags/#data-encrypted-for-impact) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Process Deleting Its Process File Path](/endpoint/f7eda4bc-871c-11eb-b110-acde48001122/) | [Indicator Removal on Host](/tags/#indicator-removal-on-host) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Ransomware Notes bulk creation](/endpoint/eff7919a-8330-11eb-83f8-acde48001122/) | [Data Encrypted for Impact](/tags/#data-encrypted-for-impact) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Resize ShadowStorage volume](/endpoint/bc760ca6-8336-11eb-bcbb-acde48001122/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Resize Shadowstorage Volume](/endpoint/dbc30554-d27e-11eb-9e5e-acde48001122/) | [Service Stop](/tags/#service-stop) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Event Log Service Behavior](/endpoint/2b85aa3d-f5f6-4c2e-a081-a09f6e1c2e40/) | [Indicator Removal on Host](/tags/#indicator-removal-on-host), [Clear Windows Event Logs](/tags/#clear-windows-event-logs) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious wevtutil Usage](/endpoint/2827c0fd-e1be-4868-ae25-59d28e0f9d4f/) | [Clear Windows Event Logs](/tags/#clear-windows-event-logs), [Indicator Removal on Host](/tags/#indicator-removal-on-host) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [WevtUtil Usage To Clear Logs](/endpoint/5438113c-cdd9-11eb-93b8-acde48001122/) | [Indicator Removal on Host](/tags/#indicator-removal-on-host), [Clear Windows Event Logs](/tags/#clear-windows-event-logs) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Event Log Cleared](/endpoint/ad517544-aff9-4c96-bd99-d6eb43bfbb6a/) | [Indicator Removal on Host](/tags/#indicator-removal-on-host), [Clear Windows Event Logs](/tags/#clear-windows-event-logs) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows High File Deletion Frequency](/endpoint/45b125c4-866f-11eb-a95a-acde48001122/) | [Data Destruction](/tags/#data-destruction) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Service Created with Suspicious Service Path](/endpoint/429141be-8311-11eb-adb6-acde48001122/) | [System Services](/tags/#system-services), [Service Execution](/tags/#service-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://www.hhs.gov/sites/default/files/analyst-note-cl0p-tlp-white.pdf](https://www.hhs.gov/sites/default/files/analyst-note-cl0p-tlp-white.pdf)
* [https://securityaffairs.co/wordpress/115250/data-breach/qualys-clop-ransomware.html](https://securityaffairs.co/wordpress/115250/data-breach/qualys-clop-ransomware.html)
* [https://www.darkreading.com/attacks-breaches/qualys-is-the-latest-victim-of-accellion-data-breach/d/d-id/1340323](https://www.darkreading.com/attacks-breaches/qualys-is-the-latest-victim-of-accellion-data-breach/d/d-id/1340323)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/clop_ransomware.yml) \| *version*: **1**