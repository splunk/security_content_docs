---
title: "AcidRain"
last_modified_at: 2022-04-12
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

Leverage searches that allow you to detect and investigate unusual activities that might relate to the acidrain malware including deleting of files and etc. AcidRain is an ELF MIPS malware specifically designed to wipe modems and routers. The complete list of targeted devices is unknown at this time, but WatchGuard FireBox has specifically been listed as a target. This malware is capable of wiping and deleting non-standard linux files and overwriting storage device files that might related to router, ssd card and many more.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2022-04-12
- **Author**: Teoderick Contreras, Splunk
- **ID**: c68717c6-4938-434b-987c-e1ce9d516124

#### Narrative

Adversaries may use this technique to maximize the impact on the target organization in operations where network wide availability interruption is the goal.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Linux Deletion Of Cron Jobs](/endpoint/3b132a71-9335-4f33-9932-00bb4f6ac7e8/) | [Data Destruction](/tags/#data-destruction), [File Deletion](/tags/#file-deletion), [Indicator Removal on Host](/tags/#indicator-removal-on-host) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Deletion Of Init Daemon Script](/endpoint/729aab57-d26f-4156-b97f-ab8dda8f44b1/) | [Data Destruction](/tags/#data-destruction), [File Deletion](/tags/#file-deletion), [Indicator Removal on Host](/tags/#indicator-removal-on-host) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Deletion Of Services](/endpoint/b509bbd3-0331-4aaa-8e4a-d2affe100af6/) | [Data Destruction](/tags/#data-destruction), [File Deletion](/tags/#file-deletion), [Indicator Removal on Host](/tags/#indicator-removal-on-host) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux High Frequency Of File Deletion In Etc Folder](/endpoint/9d867448-2aff-4d07-876c-89409a752ff8/) | [Data Destruction](/tags/#data-destruction), [File Deletion](/tags/#file-deletion), [Indicator Removal on Host](/tags/#indicator-removal-on-host) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://www.sentinelone.com/labs/acidrain-a-modem-wiper-rains-down-on-europe/](https://www.sentinelone.com/labs/acidrain-a-modem-wiper-rains-down-on-europe/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/acidrain.yml) \| *version*: **1**