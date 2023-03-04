---
title: "Insider Threat"
last_modified_at: 2022-05-19
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Splunk Behavioral Analytics
  - Authentication
  - Endpoint
  - Endpoint_Processes
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Monitor for activities and techniques associated with insider threats and specifically focusing on malicious insiders operating with in a corporate environment.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud, Splunk Behavioral Analytics
- **Datamodel**: [Authentication](https://docs.splunk.com/Documentation/CIM/latest/User/Authentication), [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Endpoint_Processes](https://docs.splunk.com/Documentation/CIM/latest/User/EndpointProcesses)
- **Last Updated**: 2022-05-19
- **Author**: Jose Hernandez, Splunk
- **ID**: c633df29-a950-4c4c-a0f8-02be6730797c

#### Narrative

Insider Threats are best defined by CISA: "Insider threat incidents are possible in any sector or organization. An insider threat is typically a current or former employee, third-party contractor, or business partner. In their present or former role, the person has or had access to an organization's network systems, data, or premises, and uses their access (sometimes unwittingly). To combat the insider threat, organizations can implement a proactive, prevention-focused mitigation program to detect and identify threats, assess risk, and manage that risk - before an incident occurs." An insider is any person who has or had authorized access to or knowledge of an organization's resources, including personnel, facilities, information, equipment, networks, and systems. These are the common insiders that create insider threats: Departing Employees, Security Evaders, Malicious Insiders, and Negligent Employees. This story aims at detecting the malicious insider.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Anomalous usage of Archive Tools](/endpoint/63614a58-10e2-4c6c-ae81-ea1113681439/) | [Archive via Utility](/tags/#archive-via-utility), [Archive Collected Data](/tags/#archive-collected-data) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Prohibited Applications Spawning cmd exe](/endpoint/c10a18cb-fd80-4ffa-a844-25026e0a0c94/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect RClone Command-Line Usage](/endpoint/e8b74268-5454-11ec-a799-acde48001122/) | [Automated Exfiltration](/tags/#automated-exfiltration) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Fsutil Zeroing File](/endpoint/f792cdc9-43ee-4429-a3c0-ffce4fed1a85/) | [Indicator Removal](/tags/#indicator-removal) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Grant Permission Using Cacls Utility](/endpoint/c6da561a-cd29-11eb-ae65-acde48001122/) | [File and Directory Permissions Modification](/tags/#file-and-directory-permissions-modification) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Gsuite Drive Share In External Email](/cloud/f6ee02d6-fea0-11eb-b2c2-acde48001122/) | [Exfiltration to Cloud Storage](/tags/#exfiltration-to-cloud-storage), [Exfiltration Over Web Service](/tags/#exfiltration-over-web-service) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Gsuite Outbound Email With Attachment To External Domain](/cloud/dc4dc3a8-ff54-11eb-8bf7-acde48001122/) | [Exfiltration Over Unencrypted Non-C2 Protocol](/tags/#exfiltration-over-unencrypted-non-c2-protocol), [Exfiltration Over Alternative Protocol](/tags/#exfiltration-over-alternative-protocol) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Hiding Files And Directories With Attrib exe](/endpoint/028e4406-6176-11ec-aec2-acde48001122/) | [Windows File and Directory Permissions Modification](/tags/#windows-file-and-directory-permissions-modification), [File and Directory Permissions Modification](/tags/#file-and-directory-permissions-modification) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [High Frequency Copy Of Files In Network Share](/endpoint/40925f12-4709-11ec-bb43-acde48001122/) | [Transfer Data to Cloud Account](/tags/#transfer-data-to-cloud-account) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Potential password in username](/endpoint/5ced34b4-ab32-4bb0-8f22-3b8f186f0a38/) | [Local Accounts](/tags/#local-accounts), [Credentials In Files](/tags/#credentials-in-files) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Sdelete Application Execution](/endpoint/fcc52b9a-4616-11ec-8454-acde48001122/) | [Data Destruction](/tags/#data-destruction), [File Deletion](/tags/#file-deletion), [Indicator Removal](/tags/#indicator-removal) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [WevtUtil Usage To Clear Logs](/endpoint/5438113c-cdd9-11eb-93b8-acde48001122/) | [Indicator Removal](/tags/#indicator-removal), [Clear Windows Event Logs](/tags/#clear-windows-event-logs) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Wevtutil Usage To Disable Logs](/endpoint/a4bdc944-cdd9-11eb-ac97-acde48001122/) | [Indicator Removal](/tags/#indicator-removal), [Clear Windows Event Logs](/tags/#clear-windows-event-logs) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Curl Upload to Remote Destination](/endpoint/cc8d046a-543b-11ec-b864-acde48001122/) | [Ingress Tool Transfer](/tags/#ingress-tool-transfer) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Multiple Users Fail To Authenticate Wth ExplicitCredentials](/endpoint/e61918fa-9ca4-11eb-836c-acde48001122/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Multiple Users Failed To Authenticate From Process](/endpoint/9015385a-9c84-11eb-bef2-acde48001122/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Remote Access Software Hunt](/endpoint/8bd22c9f-05a2-4db1-b131-29271f28cb0a/) | [Remote Access Software](/tags/#remote-access-software) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Unusual Count Of Users Fail To Auth Wth ExplicitCredentials](/endpoint/14f414cf-3080-4b9b-aaf6-55a4ce947b93/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Unusual Count Of Users Failed To Authenticate From Process](/endpoint/25bdb6cb-2e49-4d34-a93c-d6c567c122fe/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://www.imperva.com/learn/application-security/insider-threats/](https://www.imperva.com/learn/application-security/insider-threats/)
* [https://www.cisa.gov/defining-insider-threats](https://www.cisa.gov/defining-insider-threats)
* [https://www.code42.com/glossary/types-of-insider-threats/](https://www.code42.com/glossary/types-of-insider-threats/)
* [https://github.com/Insider-Threat/Insider-Threat](https://github.com/Insider-Threat/Insider-Threat)
* [https://ctid.mitre-engenuity.org/our-work/insider-ttp-kb/](https://ctid.mitre-engenuity.org/our-work/insider-ttp-kb/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/insider_threat.yml) \| *version*: **1**