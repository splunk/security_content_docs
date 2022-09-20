---
title: "Command and Control"
last_modified_at: 2018-06-01
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Endpoint_Processes
  - Network_Resolution
  - Network_Traffic
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Detect and investigate tactics, techniques, and procedures leveraged by attackers to establish and operate command and control channels. Implants installed by attackers on compromised endpoints use these channels to receive instructions and send data back to the malicious operators.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Endpoint_Processes](https://docs.splunk.com/Documentation/CIM/latest/User/EndpointProcesses), [Network_Resolution](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkResolution), [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic)
- **Last Updated**: 2018-06-01
- **Author**: Rico Valdez, Splunk
- **ID**: 943773c6-c4de-4f38-89a8-0b92f98804d8

#### Narrative

Threat actors typically architect and implement an infrastructure to use in various ways during the course of their attack campaigns. In some cases, they leverage this infrastructure for scanning and performing reconnaissance activities. In others, they may use this infrastructure to launch actual attacks. One of the most important functions of this infrastructure is to establish servers that will communicate with implants on compromised endpoints. These servers establish a command and control channel that is used to proxy data between the compromised endpoint and the attacker. These channels relay commands from the attacker to the compromised endpoint and the output of those commands back to the attacker.\
Because this communication is so critical for an adversary, they often use techniques designed to hide the true nature of the communications. There are many different techniques used to establish and communicate over these channels. This Analytic Story provides searches that look for a variety of the techniques used for these channels, as well as indications that these channels are active, by examining logs associated with border control devices and network-access control lists.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Clients Connecting to Multiple DNS Servers](/deprecated/74ec6f18-604b-4202-a567-86b2066be3ce/) | [Exfiltration Over Unencrypted Non-C2 Protocol](/tags/#exfiltration-over-unencrypted-non-c2-protocol) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [DNS Exfiltration Using Nslookup App](/endpoint/2452e632-9e0d-11eb-bacd-acde48001122/) | [Exfiltration Over Alternative Protocol](/tags/#exfiltration-over-alternative-protocol) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [DNS Exfiltration Using Nslookup App](/endpoint/2452e632-9e0d-11eb-34ba-acde48001122/) | [Exfiltration Over Alternative Protocol](/tags/#exfiltration-over-alternative-protocol) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [DNS Query Length Outliers - MLTK](/network/85fbcfe8-9718-4911-adf6-7000d077a3a9/) | [DNS](/tags/#dns), [Application Layer Protocol](/tags/#application-layer-protocol) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [DNS Query Length With High Standard Deviation](/network/1a67f15a-f4ff-4170-84e9-08cf6f75d6f5/) | [Exfiltration Over Unencrypted Non-C2 Protocol](/tags/#exfiltration-over-unencrypted-non-c2-protocol), [Exfiltration Over Alternative Protocol](/tags/#exfiltration-over-alternative-protocol) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [DNS Query Requests Resolved by Unauthorized DNS Servers](/deprecated/1a67f15a-f4ff-4170-84e9-08cf6f75d6f6/) | [DNS](/tags/#dns) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Large Outbound ICMP Packets](/network/e9c102de-4d43-42a7-b1c8-8062ea297419/) | [Non-Application Layer Protocol](/tags/#non-application-layer-protocol) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Long DNS TXT Record Response](/deprecated/05437c07-62f5-452e-afdc-04dd44815bb9/) | [Exfiltration Over Unencrypted Non-C2 Protocol](/tags/#exfiltration-over-unencrypted-non-c2-protocol) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Spike in blocked Outbound Traffic from your AWS](/cloud/d3fffa37-492f-487b-a35d-c60fcb2acf01/) |  | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect hosts connecting to dynamic domain providers](/network/a1e761ac-1344-4dbd-88b2-3f34c912d359/) | [Drive-by Compromise](/tags/#drive-by-compromise) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detection of DNS Tunnels](/deprecated/104658f4-afdc-499f-9719-17a43f9826f4/) | [Exfiltration Over Unencrypted Non-C2 Protocol](/tags/#exfiltration-over-unencrypted-non-c2-protocol) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Excessive DNS Failures](/network/104658f4-afdc-499e-9719-17243f9826f1/) | [DNS](/tags/#dns), [Application Layer Protocol](/tags/#application-layer-protocol) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Excessive Usage of NSLOOKUP App](/endpoint/0a69fdaa-a2b8-11eb-b16d-acde48001122/) | [Exfiltration Over Alternative Protocol](/tags/#exfiltration-over-alternative-protocol) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Multiple Archive Files Http Post Traffic](/network/4477f3ea-a28f-11eb-b762-acde48001122/) | [Exfiltration Over Unencrypted Non-C2 Protocol](/tags/#exfiltration-over-unencrypted-non-c2-protocol), [Exfiltration Over Alternative Protocol](/tags/#exfiltration-over-alternative-protocol) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Plain HTTP POST Exfiltrated Data](/network/e2b36208-a364-11eb-8909-acde48001122/) | [Exfiltration Over Unencrypted Non-C2 Protocol](/tags/#exfiltration-over-unencrypted-non-c2-protocol), [Exfiltration Over Alternative Protocol](/tags/#exfiltration-over-alternative-protocol) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Prohibited Network Traffic Allowed](/network/ce5a0962-849f-4720-a678-753fe6674479/) | [Exfiltration Over Alternative Protocol](/tags/#exfiltration-over-alternative-protocol) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Protocol or Port Mismatch](/network/54dc1265-2f74-4b6d-b30d-49eb506a31b3/) | [Exfiltration Over Unencrypted Non-C2 Protocol](/tags/#exfiltration-over-unencrypted-non-c2-protocol), [Exfiltration Over Alternative Protocol](/tags/#exfiltration-over-alternative-protocol) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [TOR Traffic](/network/ea688274-9c06-4473-b951-e4cb7a5d7a45/) | [Application Layer Protocol](/tags/#application-layer-protocol), [Web Protocols](/tags/#web-protocols) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Remote Access Software Hunt](/endpoint/8bd22c9f-05a2-4db1-b131-29271f28cb0a/) | [Remote Access Software](/tags/#remote-access-software) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://attack.mitre.org/wiki/Command_and_Control](https://attack.mitre.org/wiki/Command_and_Control)
* [https://searchsecurity.techtarget.com/feature/Command-and-control-servers-The-puppet-masters-that-govern-malware](https://searchsecurity.techtarget.com/feature/Command-and-control-servers-The-puppet-masters-that-govern-malware)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/command_and_control.yml) \| *version*: **1**