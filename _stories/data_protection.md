---
title: "Data Protection"
last_modified_at: 2017-09-14
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Change_Analysis
  - Network_Resolution
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Fortify your data-protection arsenal--while continuing to ensure data confidentiality and integrity--with searches that monitor for and help you investigate possible signs of data exfiltration.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Change_Analysis](https://docs.splunk.com/Documentation/CIM/latest/User/ChangeAnalysis), [Network_Resolution](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkResolution)
- **Last Updated**: 2017-09-14
- **Author**: Bhavin Patel, Splunk
- **ID**: 91c676cf-0b23-438d-abee-f6335e1fce33

#### Narrative

Attackers can leverage a variety of resources to compromise or exfiltrate enterprise data. Common exfiltration techniques include remote-access channels via low-risk, high-payoff active-collections operations and close-access operations using insiders and removable media. While this Analytic Story is not a comprehensive listing of all the methods by which attackers can exfiltrate data, it provides a useful starting point.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Detect USB device insertion](/deprecated/104658f4-afdc-499f-9719-17a43f9826f5/) |  | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect hosts connecting to dynamic domain providers](/network/a1e761ac-1344-4dbd-88b2-3f34c912d359/) | [Drive-by Compromise](/tags/#drive-by-compromise) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detection of DNS Tunnels](/deprecated/104658f4-afdc-499f-9719-17a43f9826f4/) | [Exfiltration Over Unencrypted Non-C2 Protocol](/tags/#exfiltration-over-unencrypted-non-c2-protocol) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://www.cisecurity.org/controls/data-protection/](https://www.cisecurity.org/controls/data-protection/)
* [https://www.sans.org/reading-room/whitepapers/dns/splunk-detect-dns-tunneling-37022](https://www.sans.org/reading-room/whitepapers/dns/splunk-detect-dns-tunneling-37022)
* [https://umbrella.cisco.com/blog/2013/04/15/on-the-trail-of-malicious-dynamic-dns-domains/](https://umbrella.cisco.com/blog/2013/04/15/on-the-trail-of-malicious-dynamic-dns-domains/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/data_protection.yml) \| *version*: **1**