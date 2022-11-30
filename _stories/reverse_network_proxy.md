---
title: "Reverse Network Proxy"
last_modified_at: 2022-11-16
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Network_Resolution
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic story describes applications that may be abused to reverse proxy back into an organization, either for persistence or remote access.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Network_Resolution](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkResolution)
- **Last Updated**: 2022-11-16
- **Author**: Michael Haag, Splunk
- **ID**: 265e4127-21fd-43e4-adac-ec5d12274111

#### Narrative

This analytic story covers tools like Ngrok which is a legitimate reverse proxy tool that can create a secure tunnel to servers located behind firewalls or on local machines that do not have a public IP. Ngrok in particular has been leveraged by threat actors in several campaigns including use for lateral movement and data exfiltration. There are many open source and closed/paid that fall into this reverse proxy category. The analytic story and complemented analytics will be released as more are identified.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Ngrok Reverse Proxy on Network](/network/5790a766-53b8-40d3-a696-3547b978fcf0/) | [Protocol Tunneling](/tags/#protocol-tunneling), [Proxy](/tags/#proxy), [Web Service](/tags/#web-service) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Ngrok Reverse Proxy Usage](/endpoint/e2549f2c-0aef-408a-b0c1-e0f270623436/) | [Protocol Tunneling](/tags/#protocol-tunneling), [Proxy](/tags/#proxy), [Web Service](/tags/#web-service) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://attack.mitre.org/software/S0508/](https://attack.mitre.org/software/S0508/)
* [https://www.cisa.gov/uscert/sites/default/files/publications/aa22-320a_joint_csa_iranian_government-sponsored_apt_actors_compromise_federal%20network_deploy_crypto%20miner_credential_harvester.pdf](https://www.cisa.gov/uscert/sites/default/files/publications/aa22-320a_joint_csa_iranian_government-sponsored_apt_actors_compromise_federal%20network_deploy_crypto%20miner_credential_harvester.pdf)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/reverse_network_proxy.yml) \| *version*: **1**