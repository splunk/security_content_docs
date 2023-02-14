---
title: "Data Exfiltration"
last_modified_at: 2020-10-21
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

The stealing of data by an adversary.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Endpoint_Processes](https://docs.splunk.com/Documentation/CIM/latest/User/EndpointProcesses), [Network_Resolution](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkResolution), [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic)
- **Last Updated**: 2020-10-21
- **Author**: Shannon Davis, Splunk
- **ID**: 66b0fe0c-1351-11eb-adc1-0242ac120002

#### Narrative

Exfiltration comes in many flavors.  Adversaries can collect data over encrypted or non-encrypted channels.  They can utilise Command and Control channels that are already in place to exfiltrate data.  They can use both standard data transfer protocols such as FTP, SCP, etc to exfiltrate data.  Or they can use non-standard protocols such as DNS, ICMP, etc with specially crafted fields to try and circumvent security technologies in place.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [DNS Exfiltration Using Nslookup App](/endpoint/2452e632-9e0d-11eb-34ba-acde48001122/) | [Exfiltration Over Alternative Protocol](/tags/#exfiltration-over-alternative-protocol) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [DNS Exfiltration Using Nslookup App](/endpoint/2452e632-9e0d-11eb-bacd-acde48001122/) | [Exfiltration Over Alternative Protocol](/tags/#exfiltration-over-alternative-protocol) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect DGA domains using pretrained model in DSDL](/network/92e24f32-9b9a-4060-bba2-2a0eb31f3493/) | [Domain Generation Algorithms](/tags/#domain-generation-algorithms) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect SNICat SNI Exfiltration](/network/82d06410-134c-11eb-adc1-0242ac120002/) | [Exfiltration Over C2 Channel](/tags/#exfiltration-over-c2-channel) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect shared ec2 snapshot](/cloud/2a9b80d3-6340-4345-b5ad-290bf3d222c4/) | [Transfer Data to Cloud Account](/tags/#transfer-data-to-cloud-account) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Excessive Usage of NSLOOKUP App](/endpoint/0a69fdaa-a2b8-11eb-b16d-acde48001122/) | [Exfiltration Over Alternative Protocol](/tags/#exfiltration-over-alternative-protocol) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Gdrive suspicious file sharing](/cloud/a7131dae-34e3-11ec-a2de-acde48001122/) | [Phishing](/tags/#phishing) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Linux Curl Upload File](/endpoint/c1de2d9a-0c02-4bb4-a49a-510c6e9cf2bf/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Mailsniper Invoke functions](/endpoint/a36972c8-b894-11eb-9f78-acde48001122/) | [Email Collection](/tags/#email-collection), [Local Email Collection](/tags/#local-email-collection) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Multiple Archive Files Http Post Traffic](/network/4477f3ea-a28f-11eb-b762-acde48001122/) | [Exfiltration Over Unencrypted Non-C2 Protocol](/tags/#exfiltration-over-unencrypted-non-c2-protocol), [Exfiltration Over Alternative Protocol](/tags/#exfiltration-over-alternative-protocol) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 PST export alert](/cloud/5f694cc4-a678-4a60-9410-bffca1b647dc/) | [Email Collection](/tags/#email-collection) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 Suspicious Admin Email Forwarding](/cloud/7f398cfb-918d-41f4-8db8-2e2474e02c28/) | [Email Forwarding Rule](/tags/#email-forwarding-rule), [Email Collection](/tags/#email-collection) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [O365 Suspicious User Email Forwarding](/cloud/f8dfe015-dbb3-4569-ba75-b13787e06aa4/) | [Email Forwarding Rule](/tags/#email-forwarding-rule), [Email Collection](/tags/#email-collection) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Plain HTTP POST Exfiltrated Data](/network/e2b36208-a364-11eb-8909-acde48001122/) | [Exfiltration Over Unencrypted Non-C2 Protocol](/tags/#exfiltration-over-unencrypted-non-c2-protocol), [Exfiltration Over Alternative Protocol](/tags/#exfiltration-over-alternative-protocol) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://attack.mitre.org/tactics/TA0010/](https://attack.mitre.org/tactics/TA0010/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/data_exfiltration.yml) \| *version*: **1**