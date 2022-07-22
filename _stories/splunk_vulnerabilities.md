---
title: "Splunk Vulnerabilities"
last_modified_at: 2022-03-28
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Splunk_Audit
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Keeping your Splunk Enterprise deployment up to date is critical and will help you reduce the risk associated with vulnerabilities in the product.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Splunk_Audit](https://docs.splunk.com/Documentation/CIM/latest/User/SplunkAudit)
- **Last Updated**: 2022-03-28
- **Author**: Lou Stella, Splunk
- **ID**: 5354df00-dce2-48ac-9a64-8adb48006828

#### Narrative

This analytic story includes detections that focus on attacker behavior targeted at your Splunk environment directly.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Detect Risky SPL using Pretrained ML Model](/application/b4aefb5f-1037-410d-a149-1e091288ba33/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Open Redirect in Splunk Web](/deprecated/d199fb99-2312-451a-9daa-e5efa6ed76a7/) |  | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Path traversal SPL injection](/application/dfe55688-82ed-4d24-a21b-ed8f0e0fda99/) | [File and Directory Discovery](/tags/#file-and-directory-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk Command and Scripting Interpreter Delete Usage](/application/8d3d5d5e-ca43-42be-aa1f-bc64375f6b04/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk Command and Scripting Interpreter Risky Commands](/application/1cf58ae1-9177-40b8-a26c-8966040f11ae/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk Command and Scripting Interpreter Risky SPL MLTK](/application/19d0146c-2eae-4e53-8d39-1198a78fa9ca/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk Digital Certificates Infrastructure Version](/application/3c162281-7edb-4ebc-b9a4-5087aaf28fa7/) | [Digital Certificates](/tags/#digital-certificates) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk Digital Certificates Lack of Encryption](/application/386a7ebc-737b-48cf-9ca8-5405459ed508/) | [Digital Certificates](/tags/#digital-certificates) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk DoS via Malformed S2S Request](/application/fc246e56-953b-40c1-8634-868f9e474cbd/) | [Network Denial of Service](/tags/#network-denial-of-service) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk Enterprise Information Disclosure](/deprecated/f6a26b7b-7e80-4963-a9a8-d836e7534ebd/) |  | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk Identified SSL TLS Certificates](/network/620fbb89-86fd-4e2e-925f-738374277586/) | [Network Sniffing](/tags/#network-sniffing) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk Process Injection Forwarder Bundle Downloads](/application/8ea57d78-1aac-45d2-a913-0cd603fb6e9e/) | [Process Injection](/tags/#process-injection) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk Protocol Impersonation Weak Encryption Configuration](/application/900892bf-70a9-4787-8c99-546dd98ce461/) | [Protocol Impersonation](/tags/#protocol-impersonation) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk User Enumeration Attempt](/application/25625cb4-1c4d-4463-b0f9-7cb462699cde/) | [Valid Accounts](/tags/#valid-accounts) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk XSS in Monitoring Console](/application/b11accac-6fa3-4103-8a1a-7210f1a67087/) | [Drive-by Compromise](/tags/#drive-by-compromise) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk protocol impersonation weak encryption selfsigned](/application/c76c7a2e-df49-414a-bb36-dce2683770de/) | [Digital Certificates](/tags/#digital-certificates) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk protocol impersonation weak encryption simplerequest](/application/839d12a6-b119-4d44-ac4f-13eed95412c8/) | [Digital Certificates](/tags/#digital-certificates) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://www.splunk.com/en_us/product-security/announcements.html](https://www.splunk.com/en_us/product-security/announcements.html)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/splunk_vulnerabilities.yml) \| *version*: **1**