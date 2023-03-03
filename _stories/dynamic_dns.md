---
title: "Dynamic DNS"
last_modified_at: 2018-09-06
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Network_Resolution
  - Web
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Detect and investigate hosts in your environment that may be communicating with dynamic domain providers. Attackers may leverage these services to help them avoid firewall blocks and deny lists.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Network_Resolution](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkResolution), [Web](https://docs.splunk.com/Documentation/CIM/latest/User/Web)
- **Last Updated**: 2018-09-06
- **Author**: Bhavin Patel, Splunk
- **ID**: 8169f17b-ef68-4b59-aae8-586907301221

#### Narrative

Dynamic DNS services (DDNS) are legitimate low-cost or free services that allow users to rapidly update domain resolutions to IP infrastructure. While their usage can be benign, malicious actors can abuse DDNS to host harmful payloads or interactive-command-and-control infrastructure. These attackers will manually update or automate domain resolution changes by routing dynamic domains to IP addresses that circumvent firewall blocks and deny lists and frustrate a network defender's analytic and investigative processes. These searches will look for DNS queries made from within your infrastructure to suspicious dynamic domains and then investigate more deeply, when appropriate. While this list of top-level dynamic domains is not exhaustive, it can be dynamically updated as new suspicious dynamic domains are identified.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [DNS Exfiltration Using Nslookup App](/endpoint/2452e632-9e0d-11eb-bacd-acde48001122/) | [Exfiltration Over Alternative Protocol](/tags/#exfiltration-over-alternative-protocol) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [DNS Exfiltration Using Nslookup App](/endpoint/2452e632-9e0d-11eb-34ba-acde48001122/) | [Exfiltration Over Alternative Protocol](/tags/#exfiltration-over-alternative-protocol) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect DGA domains using pretrained model in DSDL](/network/92e24f32-9b9a-4060-bba2-2a0eb31f3493/) | [Domain Generation Algorithms](/tags/#domain-generation-algorithms) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect hosts connecting to dynamic domain providers](/network/a1e761ac-1344-4dbd-88b2-3f34c912d359/) | [Drive-by Compromise](/tags/#drive-by-compromise) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect web traffic to dynamic domain providers](/deprecated/134da869-e264-4a8f-8d7e-fcd01c18f301/) | [Web Protocols](/tags/#web-protocols) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Excessive Usage of NSLOOKUP App](/endpoint/0a69fdaa-a2b8-11eb-b16d-acde48001122/) | [Exfiltration Over Alternative Protocol](/tags/#exfiltration-over-alternative-protocol) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://www.fireeye.com/blog/threat-research/2017/09/apt33-insights-into-iranian-cyber-espionage.html](https://www.fireeye.com/blog/threat-research/2017/09/apt33-insights-into-iranian-cyber-espionage.html)
* [https://umbrella.cisco.com/blog/2013/04/15/on-the-trail-of-malicious-dynamic-dns-domains/](https://umbrella.cisco.com/blog/2013/04/15/on-the-trail-of-malicious-dynamic-dns-domains/)
* [http://www.noip.com/blog/2014/07/11/dynamic-dns-can-use-2/](http://www.noip.com/blog/2014/07/11/dynamic-dns-can-use-2/)
* [https://www.splunk.com/blog/2015/08/04/detecting-dynamic-dns-domains-in-splunk.html](https://www.splunk.com/blog/2015/08/04/detecting-dynamic-dns-domains-in-splunk.html)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/dynamic_dns.yml) \| *version*: **2**