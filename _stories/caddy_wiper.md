---
title: "Caddy Wiper"
last_modified_at: 2022-03-25
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Caddy Wiper is a destructive payload that detects if its running on a Domain Controller and executes killswitch if detected. If not in a DC it destroys Users and subsequent mapped drives. This wiper also destroys drive partitions inculding boot partitions.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2022-03-25
- **Author**: Teoderick Contreras, Rod Soto, Splunk
- **ID**: 435a156a-8ef1-4184-bd52-22328fb65d3a

#### Narrative

Caddy Wiper is destructive malware operation found by ESET multiple organizations in Ukraine. This malicious payload destroys user files, avoids executing on Dnomain Controllers and destroys boot and drive partitions.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Windows Raw Access To Disk Volume Partition](/endpoint/a85aa37e-9647-11ec-90c5-acde48001122/) | [Disk Structure Wipe](/tags/#disk-structure-wipe), [Disk Wipe](/tags/#disk-wipe) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Raw Access To Master Boot Record Drive](/endpoint/7b83f666-900c-11ec-a2d9-acde48001122/) | [Disk Structure Wipe](/tags/#disk-structure-wipe), [Disk Wipe](/tags/#disk-wipe) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://twitter.com/ESETresearch/status/1503436420886712321](https://twitter.com/ESETresearch/status/1503436420886712321)
* [https://www.welivesecurity.com/2022/03/15/caddywiper-new-wiper-malware-discovered-ukraine/](https://www.welivesecurity.com/2022/03/15/caddywiper-new-wiper-malware-discovered-ukraine/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/caddy_wiper.yml) \| *version*: **1**