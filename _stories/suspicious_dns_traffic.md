---
title: "Suspicious DNS Traffic"
last_modified_at: 2017-09-18
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Endpoint_Processes
  - Network_Resolution
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Attackers often attempt to hide within or otherwise abuse the domain name system (DNS). You can thwart attempts to manipulate this omnipresent protocol by monitoring for these types of abuses.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Endpoint_Processes](https://docs.splunk.com/Documentation/CIM/latest/User/EndpointProcesses), [Network_Resolution](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkResolution)
- **Last Updated**: 2017-09-18
- **Author**: Rico Valdez, Splunk
- **ID**: 3c3835c0-255d-4f9e-ab84-e29ec9ec9b56

#### Narrative

Although DNS is one of the fundamental underlying protocols that make the Internet work, it is often ignored (perhaps because of its complexity and effectiveness).  However, attackers have discovered ways to abuse the protocol to meet their objectives. One potential abuse involves manipulating DNS to hijack traffic and redirect it to an IP address under the attacker's control. This could inadvertently send users intending to visit google.com, for example, to an unrelated malicious website. Another technique involves using the DNS protocol for command-and-control activities with the attacker's malicious code or to covertly exfiltrate data. The searches within this Analytic Story look for these types of abuses.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Clients Connecting to Multiple DNS Servers](/deprecated/74ec6f18-604b-4202-a567-86b2066be3ce/) | [Exfiltration Over Unencrypted Non-C2 Protocol](/tags/#exfiltration-over-unencrypted-non-c2-protocol) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [DNS Exfiltration Using Nslookup App](/endpoint/2452e632-9e0d-11eb-bacd-acde48001122/) | [Exfiltration Over Alternative Protocol](/tags/#exfiltration-over-alternative-protocol) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [DNS Exfiltration Using Nslookup App](/endpoint/2452e632-9e0d-11eb-34ba-acde48001122/) | [Exfiltration Over Alternative Protocol](/tags/#exfiltration-over-alternative-protocol) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [DNS Query Length Outliers - MLTK](/network/85fbcfe8-9718-4911-adf6-7000d077a3a9/) | [DNS](/tags/#dns), [Application Layer Protocol](/tags/#application-layer-protocol) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [DNS Query Length With High Standard Deviation](/network/1a67f15a-f4ff-4170-84e9-08cf6f75d6f5/) | [Exfiltration Over Unencrypted Non-C2 Protocol](/tags/#exfiltration-over-unencrypted-non-c2-protocol), [Exfiltration Over Alternative Protocol](/tags/#exfiltration-over-alternative-protocol) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [DNS Query Requests Resolved by Unauthorized DNS Servers](/deprecated/1a67f15a-f4ff-4170-84e9-08cf6f75d6f6/) | [DNS](/tags/#dns) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Long DNS TXT Record Response](/deprecated/05437c07-62f5-452e-afdc-04dd44815bb9/) | [Exfiltration Over Unencrypted Non-C2 Protocol](/tags/#exfiltration-over-unencrypted-non-c2-protocol) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect hosts connecting to dynamic domain providers](/network/a1e761ac-1344-4dbd-88b2-3f34c912d359/) | [Drive-by Compromise](/tags/#drive-by-compromise) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detection of DNS Tunnels](/deprecated/104658f4-afdc-499f-9719-17a43f9826f4/) | [Exfiltration Over Unencrypted Non-C2 Protocol](/tags/#exfiltration-over-unencrypted-non-c2-protocol) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Excessive DNS Failures](/network/104658f4-afdc-499e-9719-17243f9826f1/) | [DNS](/tags/#dns), [Application Layer Protocol](/tags/#application-layer-protocol) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Excessive Usage of NSLOOKUP App](/endpoint/0a69fdaa-a2b8-11eb-b16d-acde48001122/) | [Exfiltration Over Alternative Protocol](/tags/#exfiltration-over-alternative-protocol) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [http://blogs.splunk.com/2015/10/01/random-words-on-entropy-and-dns/](http://blogs.splunk.com/2015/10/01/random-words-on-entropy-and-dns/)
* [http://www.darkreading.com/analytics/security-monitoring/got-malware-three-signs-revealed-in-dns-traffic/d/d-id/1139680](http://www.darkreading.com/analytics/security-monitoring/got-malware-three-signs-revealed-in-dns-traffic/d/d-id/1139680)
* [https://live.paloaltonetworks.com/t5/Threat-Vulnerability-Articles/What-are-suspicious-DNS-queries/ta-p/71454](https://live.paloaltonetworks.com/t5/Threat-Vulnerability-Articles/What-are-suspicious-DNS-queries/ta-p/71454)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/suspicious_dns_traffic.yml) \| *version*: **1**