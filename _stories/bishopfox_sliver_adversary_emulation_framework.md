---
title: "BishopFox Sliver Adversary Emulation Framework"
last_modified_at: 2023-01-24
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

The following analytic story providers visibility into the latest adversary TTPs in regard to the use of Sliver. Sliver has gained more traction with adversaries as it is often seen as an alternative to Cobalt Strike. It is designed to be scalable and can be used by organizations of all sizes to perform security testing. Sliver is highly modular and contains an Extension package manager (armory) allowing easy install (automatic compilation) of various 3rd party tools such as BOFs and .NET tooling like Ghostpack (Rubeus, Seatbelt, SharpUp, Certify, and so forth) (CyberReason,2023).

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2023-01-24
- **Author**: Michael Haag, Splunk
- **ID**: 8c2e2cba-3fd8-424f-a890-5080bdaf3f31

#### Narrative

Sliver is an open source cross-platform adversary emulation/red team framework produced by BishopFox.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Notepad with no Command Line Arguments](/endpoint/5adbc5f1-9a2f-41c1-a810-f37e015f8179/) | [Process Injection](/tags/#process-injection) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Process Injection into Notepad](/endpoint/b8340d0f-ba48-4391-bea7-9e793c5aae36/) | [Process Injection](/tags/#process-injection), [Portable Executable Injection](/tags/#portable-executable-injection) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Service Create SliverC2](/endpoint/89dad3ee-57ec-43dc-9044-131c4edd663f/) | [System Services](/tags/#system-services), [Service Execution](/tags/#service-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://www.cybereason.com/blog/sliver-c2-leveraged-by-many-threat-actors](https://www.cybereason.com/blog/sliver-c2-leveraged-by-many-threat-actors)
* [https://www.ncsc.gov.uk/files/Advisory%20Further%20TTPs%20associated%20with%20SVR%20cyber%20actors.pdf](https://www.ncsc.gov.uk/files/Advisory%20Further%20TTPs%20associated%20with%20SVR%20cyber%20actors.pdf)
* [https://www.proofpoint.com/uk/blog/security-briefs/ta551-uses-sliver-red-team-tool-new-activity](https://www.proofpoint.com/uk/blog/security-briefs/ta551-uses-sliver-red-team-tool-new-activity)
* [https://www.cybereason.com/blog/threat-analysis-report-bumblebee-loader-the-high-road-to-enterprise-domain-control](https://www.cybereason.com/blog/threat-analysis-report-bumblebee-loader-the-high-road-to-enterprise-domain-control)
* [https://github.com/sliverarmory/armory](https://github.com/sliverarmory/armory)
* [https://github.com/BishopFox/sliver](https://github.com/BishopFox/sliver)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/bishopfox_sliver_adversary_emulation_framework.yml) \| *version*: **1**