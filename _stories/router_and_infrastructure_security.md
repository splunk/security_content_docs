---
title: "Router and Infrastructure Security"
last_modified_at: 2017-09-12
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Authentication
  - Network_Traffic
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Validate the security configuration of network infrastructure and verify that only authorized users and systems are accessing critical assets. Core routing and switching infrastructure are common strategic targets for attackers.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Authentication](https://docs.splunk.com/Documentation/CIM/latest/User/Authentication), [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic)
- **Last Updated**: 2017-09-12
- **Author**: Bhavin Patel, Splunk
- **ID**: 91c676cf-0b23-438d-abee-f6335e177e77

#### Narrative

Networking devices, such as routers and switches, are often overlooked as resources that attackers will leverage to subvert an enterprise. Advanced threats actors have shown a proclivity to target these critical assets as a means to siphon and redirect network traffic, flash backdoored operating systems, and implement cryptographic weakened algorithms to more easily decrypt network traffic.\
This Analytic Story helps you gain a better understanding of how your network devices are interacting with your hosts. By compromising your network devices, attackers can obtain direct access to the company's internal infrastructure&#151; effectively increasing the attack surface and accessing private services/data.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Detect ARP Poisoning](/network/b44bebd6-bd39-467b-9321-73971bcd7aac/) | [Hardware Additions](/tags/#hardware-additions), [Network Denial of Service](/tags/#network-denial-of-service), [Adversary-in-the-Middle](/tags/#adversary-in-the-middle), [ARP Cache Poisoning](/tags/#arp-cache-poisoning) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect IPv6 Network Infrastructure Threats](/network/c3be767e-7959-44c5-8976-0e9c12a91ad2/) | [Hardware Additions](/tags/#hardware-additions), [Network Denial of Service](/tags/#network-denial-of-service), [Adversary-in-the-Middle](/tags/#adversary-in-the-middle), [ARP Cache Poisoning](/tags/#arp-cache-poisoning) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect New Login Attempts to Routers](/application/bce3ed7c-9b1f-42a0-abdf-d8b123a34836/) |  | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Port Security Violation](/network/2de3d5b8-a4fa-45c5-8540-6d071c194d24/) | [Hardware Additions](/tags/#hardware-additions), [Network Denial of Service](/tags/#network-denial-of-service), [Adversary-in-the-Middle](/tags/#adversary-in-the-middle), [ARP Cache Poisoning](/tags/#arp-cache-poisoning) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Rogue DHCP Server](/network/6e1ada88-7a0d-4ac1-92c6-03d354686079/) | [Hardware Additions](/tags/#hardware-additions), [Network Denial of Service](/tags/#network-denial-of-service), [Adversary-in-the-Middle](/tags/#adversary-in-the-middle) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Software Download To Network Device](/network/cc590c66-f65f-48f2-986a-4797244762f8/) | [TFTP Boot](/tags/#tftp-boot), [Pre-OS Boot](/tags/#pre-os-boot) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Traffic Mirroring](/network/42b3b753-5925-49c5-9742-36fa40a73990/) | [Hardware Additions](/tags/#hardware-additions), [Automated Exfiltration](/tags/#automated-exfiltration), [Network Denial of Service](/tags/#network-denial-of-service), [Traffic Duplication](/tags/#traffic-duplication) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://web.archive.org/web/20210420020040/https://www.fireeye.com/blog/executive-perspective/2015/09/the_new_route_toper.html](https://web.archive.org/web/20210420020040/https://www.fireeye.com/blog/executive-perspective/2015/09/the_new_route_toper.html)
* [https://www.cisco.com/c/en/us/about/security-center/event-response/synful-knock.html](https://www.cisco.com/c/en/us/about/security-center/event-response/synful-knock.html)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/router_and_infrastructure_security.yml) \| *version*: **1**