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
  - Endpoint
  - Endpoint_Processes
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Leverage searches that allow you to detect and investigate unusual activities that might correlate to insider threat specially in terms of information sabotage.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud, Splunk Behavioral Analytics
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Endpoint_Processes](https://docs.splunk.com/Documentation/CIM/latest/User/EndpointProcesses)
- **Last Updated**: 2021-11-17
- **Author**: Teoderick Contreras, Splunk
- **ID**: b71ba595-ef80-4e39-8b66-887578a7a71b

#### Narrative

Information sabotage is the type of crime many people associate with insider threat. Where the current or former employees, contractors, or business partners intentionally exceeded or misused an authorized level of access to networks, systems, or data with the intention of harming a specific individual, the organization, or the organization's data, systems, and/or daily business operations.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Clear Unallocated Sector Using Cipher App](/endpoint/8f907d90-6173-11ec-9c23-acde48001122/) | [File Deletion](/tags/#file-deletion), [Indicator Removal on Host](/tags/#indicator-removal-on-host) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Hiding Files And Directories With Attrib exe](/endpoint/028e4406-6176-11ec-aec2-acde48001122/) | [Windows File and Directory Permissions Modification](/tags/#windows-file-and-directory-permissions-modification), [File and Directory Permissions Modification](/tags/#file-and-directory-permissions-modification) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [High Frequency Copy Of Files In Network Share](/endpoint/40925f12-4709-11ec-bb43-acde48001122/) | [Transfer Data to Cloud Account](/tags/#transfer-data-to-cloud-account) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Sdelete Application Execution](/endpoint/fcc52b9a-4616-11ec-8454-acde48001122/) | [Data Destruction](/tags/#data-destruction), [File Deletion](/tags/#file-deletion), [Indicator Removal on Host](/tags/#indicator-removal-on-host) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://insights.sei.cmu.edu/blog/insider-threat-deep-dive-it-sabotage/](https://insights.sei.cmu.edu/blog/insider-threat-deep-dive-it-sabotage/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/information_sabotage.yml) \| *version*: **1**