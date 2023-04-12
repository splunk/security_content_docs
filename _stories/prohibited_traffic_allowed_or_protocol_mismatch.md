---
title: "Prohibited Traffic Allowed or Protocol Mismatch"
last_modified_at: 2017-09-11
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Network_Resolution
  - Network_Traffic
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Detect instances of prohibited network traffic allowed in the environment, as well as protocols running on non-standard ports. Both of these types of behaviors typically violate policy and can be leveraged by attackers.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Network_Resolution](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkResolution), [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic)
- **Last Updated**: 2017-09-11
- **Author**: Rico Valdez, Splunk
- **ID**: 6d13121c-90f3-446d-8ac3-27efbbc65218

#### Narrative

A traditional security best practice is to control the ports, protocols, and services allowed within your environment. By limiting the services and protocols to those explicitly approved by policy, administrators can minimize the attack surface. The combined effect allows both network defenders and security controls to focus and not be mired in superfluous traffic or data types. Looking for deviations to policy can identify attacker activity that abuses services and protocols to run on alternate or non-standard ports in the attempt to avoid detection or frustrate forensic analysts.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Allow Inbound Traffic By Firewall Rule Registry](/endpoint/0a46537c-be02-11eb-92ca-acde48001122/) | [Remote Desktop Protocol](/tags/#remote-desktop-protocol), [Remote Services](/tags/#remote-services) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Allow Inbound Traffic In Firewall Rule](/endpoint/a5d85486-b89c-11eb-8267-acde48001122/) | [Remote Desktop Protocol](/tags/#remote-desktop-protocol), [Remote Services](/tags/#remote-services) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect hosts connecting to dynamic domain providers](/network/a1e761ac-1344-4dbd-88b2-3f34c912d359/) | [Drive-by Compromise](/tags/#drive-by-compromise) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Enable RDP In Other Port Number](/endpoint/99495452-b899-11eb-96dc-acde48001122/) | [Remote Services](/tags/#remote-services) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Prohibited Network Traffic Allowed](/network/ce5a0962-849f-4720-a678-753fe6674479/) | [Exfiltration Over Alternative Protocol](/tags/#exfiltration-over-alternative-protocol) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Protocol or Port Mismatch](/network/54dc1265-2f74-4b6d-b30d-49eb506a31b3/) | [Exfiltration Over Unencrypted Non-C2 Protocol](/tags/#exfiltration-over-unencrypted-non-c2-protocol), [Exfiltration Over Alternative Protocol](/tags/#exfiltration-over-alternative-protocol) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [TOR Traffic](/network/ea688274-9c06-4473-b951-e4cb7a5d7a45/) | [Application Layer Protocol](/tags/#application-layer-protocol), [Web Protocols](/tags/#web-protocols) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [http://www.novetta.com/2015/02/advanced-methods-to-detect-advanced-cyber-attacks-protocol-abuse/](http://www.novetta.com/2015/02/advanced-methods-to-detect-advanced-cyber-attacks-protocol-abuse/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/prohibited_traffic_allowed_or_protocol_mismatch.yml) \| *version*: **1**