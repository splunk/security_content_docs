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
| [Path traversal SPL injection](/application/path_traversal_spl_injection/) | [File and Directory Discovery](/tags/#file-and-directory-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk Command and Scripting Interpreter Delete Usage](/application/splunk_command_and_scripting_interpreter_delete_usage/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk Command and Scripting Interpreter Risky Commands](/application/splunk_command_and_scripting_interpreter_risky_commands/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk Command and Scripting Interpreter Risky SPL MLTK](/application/splunk_command_and_scripting_interpreter_risky_spl_mltk/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk Digital Certificates Infrastructure Version](/application/splunk_digital_certificates_infrastructure_version/) | [Digital Certificates](/tags/#digital-certificates) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk Digital Certificates Lack of Encryption](/application/splunk_digital_certificates_lack_of_encryption/) | [Digital Certificates](/tags/#digital-certificates) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk DoS via Malformed S2S Request](/application/splunk_dos_via_malformed_s2s_request/) | [Network Denial of Service](/tags/#network-denial-of-service) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk Identified SSL TLS Certificates](/network/splunk_identified_ssl_tls_certificates/) | [Network Sniffing](/tags/#network-sniffing) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk Process Injection Forwarder Bundle Downloads](/application/splunk_process_injection_forwarder_bundle_downloads/) | [Process Injection](/tags/#process-injection) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk Protocol Impersonation Weak Encryption Configuration](/application/splunk_protocol_impersonation_weak_encryption_configuration/) | [Protocol Impersonation](/tags/#protocol-impersonation) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk User Enumeration Attempt](/application/splunk_user_enumeration_attempt/) | [Valid Accounts](/tags/#valid-accounts) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk XSS in Monitoring Console](/application/splunk_xss_in_monitoring_console/) | [Drive-by Compromise](/tags/#drive-by-compromise) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk protocol impersonation weak encryption selfsigned](/application/splunk_protocol_impersonation_weak_encryption_selfsigned/) | [Digital Certificates](/tags/#digital-certificates) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk protocol impersonation weak encryption simplerequest](/application/splunk_protocol_impersonation_weak_encryption_simplerequest/) | [Digital Certificates](/tags/#digital-certificates) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://www.splunk.com/en_us/product-security/announcements.html](https://www.splunk.com/en_us/product-security/announcements.html)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/splunk_vulnerabilities.yml) \| *version*: **1**