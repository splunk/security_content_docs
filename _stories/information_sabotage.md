---
title: "Information Sabotage"
last_modified_at: 2021-11-17
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Splunk Behavioral Analytics
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Leverage searches that allow you to detect and investigate unusual activities that might correlate to insider threat specially in terms of information sabotage.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud, Splunk Behavioral Analytics
- **Datamodel**: 
- **Last Updated**: 2021-11-17
- **Author**: Teoderick Contreras, Splunk
- **ID**: b71ba595-ef80-4e39-8b66-887578a7a71b

#### Narrative

Information sabotage is the type of crime many people associate with insider threat. Where the current or former employees, contractors, or business partners intentionally exceeded or misused an authorized level of access to networks, systems, or data with the intention of harming a specific individual, the organization, or the organization's data, systems, and/or daily business operations.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [BCDEdit Failure Recovery Modification](/endpoint/76d79d6e-25bb-40f6-b3b2-e0a6b7e5ea13/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Clear Unallocated Sector Using Cipher App](/endpoint/8f907d90-6173-11ec-9c23-acde48001122/) | [File Deletion](/tags/#file-deletion), [Indicator Removal](/tags/#indicator-removal) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Deny Permission using Cacls Utility](/endpoint/b76eae28-cd25-11eb-9c92-acde48001122/) | [File and Directory Permissions Modification](/tags/#file-and-directory-permissions-modification) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Fsutil Zeroing File](/endpoint/f792cdc9-43ee-4429-a3c0-ffce4fed1a85/) | [Indicator Removal](/tags/#indicator-removal) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Hiding Files And Directories With Attrib exe](/endpoint/028e4406-6176-11ec-aec2-acde48001122/) | [Windows File and Directory Permissions Modification](/tags/#windows-file-and-directory-permissions-modification), [File and Directory Permissions Modification](/tags/#file-and-directory-permissions-modification) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [High Frequency Copy Of Files In Network Share](/endpoint/40925f12-4709-11ec-bb43-acde48001122/) | [Transfer Data to Cloud Account](/tags/#transfer-data-to-cloud-account) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Sdelete Application Execution](/endpoint/fcc52b9a-4616-11ec-8454-acde48001122/) | [Data Destruction](/tags/#data-destruction), [File Deletion](/tags/#file-deletion), [Indicator Removal](/tags/#indicator-removal) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Wevtutil Usage To Disable Logs](/endpoint/a4bdc944-cdd9-11eb-ac97-acde48001122/) | [Indicator Removal](/tags/#indicator-removal), [Clear Windows Event Logs](/tags/#clear-windows-event-logs) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://insights.sei.cmu.edu/blog/insider-threat-deep-dive-it-sabotage/](https://insights.sei.cmu.edu/blog/insider-threat-deep-dive-it-sabotage/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/information_sabotage.yml) \| *version*: **1**