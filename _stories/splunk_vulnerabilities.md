---
title: "Splunk Vulnerabilities"
last_modified_at: 2023-11-16
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Splunk_Audit
  - Web
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Keeping your Splunk Enterprise deployment up to date is critical and will help you reduce the risk associated with vulnerabilities in the product.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Splunk_Audit](https://docs.splunk.com/Documentation/CIM/latest/User/SplunkAudit), [Web](https://docs.splunk.com/Documentation/CIM/latest/User/Web)
- **Last Updated**: 2023-11-16
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
| [Persistent XSS in RapidDiag through User Interface Views](/application/ce6e1268-e01c-4df2-a617-0f034ed49a43/) | [Drive-by Compromise](/tags/#drive-by-compromise) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk Absolute Path Traversal Using runshellscript](/application/356bd3fe-f59b-4f64-baa1-51495411b7ad/) | [File and Directory Discovery](/tags/#file-and-directory-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk Account Discovery Drilldown Dashboard Disclosure](/application/f844c3f6-fd99-43a2-ba24-93e35fe84be6/) | [Account Discovery](/tags/#account-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk App for Lookup File Editing RCE via User XSLT](/application/a053e6a6-2146-483a-9798-2d43652f3299/) | [Exploitation of Remote Services](/tags/#exploitation-of-remote-services) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk Code Injection via custom dashboard leading to RCE](/application/b06b41d7-9570-4985-8137-0784f582a1b3/) | [Exploitation of Remote Services](/tags/#exploitation-of-remote-services) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk Command and Scripting Interpreter Delete Usage](/application/8d3d5d5e-ca43-42be-aa1f-bc64375f6b04/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk Command and Scripting Interpreter Risky Commands](/application/1cf58ae1-9177-40b8-a26c-8966040f11ae/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk Command and Scripting Interpreter Risky SPL MLTK](/application/19d0146c-2eae-4e53-8d39-1198a78fa9ca/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk DOS Via Dump SPL Command](/application/fb0e6823-365f-48ed-b09e-272ac4c1dad6/) | [Application or System Exploitation](/tags/#application-or-system-exploitation) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk DOS via printf search function](/application/78b48d08-075c-4eac-bd07-e364c3780867/) | [Application or System Exploitation](/tags/#application-or-system-exploitation) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk Data exfiltration from Analytics Workspace using sid query](/application/b6d77c6c-f011-4b03-8650-8f10edb7c4a8/) | [Exfiltration Over Web Service](/tags/#exfiltration-over-web-service) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk Digital Certificates Infrastructure Version](/application/3c162281-7edb-4ebc-b9a4-5087aaf28fa7/) | [Digital Certificates](/tags/#digital-certificates) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk Digital Certificates Lack of Encryption](/application/386a7ebc-737b-48cf-9ca8-5405459ed508/) | [Digital Certificates](/tags/#digital-certificates) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk DoS Using Malformed SAML Request](/application/8e8a86d5-f323-4567-95be-8e817e2baee6/) | [Network Denial of Service](/tags/#network-denial-of-service) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk DoS via Malformed S2S Request](/application/fc246e56-953b-40c1-8634-868f9e474cbd/) | [Network Denial of Service](/tags/#network-denial-of-service) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk Edit User Privilege Escalation](/application/39e1c326-67d7-4c0d-8584-8056354f6593/) | [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk Endpoint Denial of Service DoS Zip Bomb](/application/b237d393-2f57-4531-aad7-ad3c17c8b041/) | [Endpoint Denial of Service](/tags/#endpoint-denial-of-service) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk Enterprise Information Disclosure](/deprecated/f6a26b7b-7e80-4963-a9a8-d836e7534ebd/) |  | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk HTTP Response Splitting Via Rest SPL Command](/application/e615a0e1-a1b2-4196-9865-8aa646e1708c/) | [HTML Smuggling](/tags/#html-smuggling) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk Identified SSL TLS Certificates](/network/620fbb89-86fd-4e2e-925f-738374277586/) | [Network Sniffing](/tags/#network-sniffing) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk Improperly Formatted Parameter Crashes splunkd](/application/08978eca-caff-44c1-84dc-53f17def4e14/) | [Endpoint Denial of Service](/tags/#endpoint-denial-of-service) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk Low Privilege User Can View Hashed Splunk Password](/application/a1be424d-e59c-4583-b6f9-2dcc23be4875/) | [Exploitation for Credential Access](/tags/#exploitation-for-credential-access) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk Path Traversal In Splunk App For Lookup File Edit](/application/8ed58987-738d-4917-9e44-b8ef6ab948a6/) | [File and Directory Discovery](/tags/#file-and-directory-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk Persistent XSS Via URL Validation Bypass W Dashboard](/application/8a43558f-a53c-4ee4-86c1-30b1e8ef3606/) | [Drive-by Compromise](/tags/#drive-by-compromise) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk Process Injection Forwarder Bundle Downloads](/application/8ea57d78-1aac-45d2-a913-0cd603fb6e9e/) | [Process Injection](/tags/#process-injection) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk Protocol Impersonation Weak Encryption Configuration](/application/900892bf-70a9-4787-8c99-546dd98ce461/) | [Protocol Impersonation](/tags/#protocol-impersonation) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk RBAC Bypass On Indexing Preview REST Endpoint](/application/bbe26f95-1655-471d-8abd-3d32fafa86f8/) | [Access Token Manipulation](/tags/#access-token-manipulation) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk RCE via Serialized Session Payload](/application/d1d8fda6-874a-400f-82cf-dcbb59d8e4db/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk RCE via Splunk Secure Gateway  Splunk Mobile alerts feature](/application/baa41f09-df48-4375-8991-520beea161be/) | [Exploitation of Remote Services](/tags/#exploitation-of-remote-services) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk Reflected XSS in the templates lists radio](/application/d532d105-c63f-4049-a8c4-e249127ca425/) | [Drive-by Compromise](/tags/#drive-by-compromise) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk Reflected XSS on App Search Table Endpoint](/application/182f9080-4137-4629-94ac-cb1083ac981a/) | [Drive-by Compromise](/tags/#drive-by-compromise) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk Stored XSS via Data Model objectName field](/application/062bff76-5f9c-496e-a386-cb1adcf69871/) | [Drive-by Compromise](/tags/#drive-by-compromise) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk Unauthenticated Log Injection Web Service Log](/application/de3908dc-1298-446d-84b9-fa81d37e959b/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk User Enumeration Attempt](/application/25625cb4-1c4d-4463-b0f9-7cb462699cde/) | [Valid Accounts](/tags/#valid-accounts) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk XSS in Highlighted JSON Events](/application/1030bc63-0b37-4ac9-9ae0-9361c955a3cc/) | [Drive-by Compromise](/tags/#drive-by-compromise) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk XSS in Monitoring Console](/application/b11accac-6fa3-4103-8a1a-7210f1a67087/) | [Drive-by Compromise](/tags/#drive-by-compromise) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk XSS in Save table dialog header in search page](/application/a974d1ee-ddca-4837-b6ad-d55a8a239c20/) | [Drive-by Compromise](/tags/#drive-by-compromise) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk XSS via View](/application/9ac2bfea-a234-4a18-9d37-6d747e85c2e4/) | [Drive-by Compromise](/tags/#drive-by-compromise) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk csrf in the ssg kvstore client endpoint](/application/4742d5f7-ce00-45ce-9c79-5e98b43b4410/) | [Drive-by Compromise](/tags/#drive-by-compromise) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk list all nonstandard admin accounts](/application/401d689c-8596-4c6b-a710-7b6fdca296d3/) | [Drive-by Compromise](/tags/#drive-by-compromise) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk protocol impersonation weak encryption selfsigned](/application/c76c7a2e-df49-414a-bb36-dce2683770de/) | [Digital Certificates](/tags/#digital-certificates) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk protocol impersonation weak encryption simplerequest](/application/839d12a6-b119-4d44-ac4f-13eed95412c8/) | [Digital Certificates](/tags/#digital-certificates) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk risky Command Abuse disclosed february 2023](/application/ee69374a-d27e-4136-adac-956a96ff60fd/) | [Abuse Elevation Control Mechanism](/tags/#abuse-elevation-control-mechanism), [Indirect Command Execution](/tags/#indirect-command-execution) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Splunk unnecessary file extensions allowed by lookup table uploads](/application/b7d1293f-e78f-415e-b5f6-443df3480082/) | [Drive-by Compromise](/tags/#drive-by-compromise) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://www.splunk.com/en_us/product-security/announcements.html](https://www.splunk.com/en_us/product-security/announcements.html)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/splunk_vulnerabilities.yml) \| *version*: **1**