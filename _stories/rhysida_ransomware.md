---
title: "Rhysida Ransomware"
last_modified_at: 2023-12-12
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Utilize analytics designed to identify and delve into atypical behaviors, potentially associated with the Rhysida Ransomware. Employing these searches enables the detection of irregular patterns or actions within systems or networks, serving as proactive measures to spot potential indicators of compromise or ongoing threats. By implementing these search strategies, security analysts can effectively pinpoint anomalous activities, such as unusual file modifications, deviations in system behavior, that could potentially signify the presence or attempt of Rhysida Ransomware infiltration. These searches serve as pivotal tools in the arsenal against such threats, aiding in swift detection, investigation, and mitigation efforts to counter the impact of the Rhysida Ransomware or similar malicious entities.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2023-12-12
- **Author**: Teoderick Contreras, Splunk
- **ID**: 0925ee49-1185-4484-94ac-7867764a9183

#### Narrative

This story addresses Rhysida ransomware. Rhysida Ransomware emerges as a silent predator, infiltrating systems stealthily and unleashing havoc upon its victims. Employing sophisticated encryption tactics, it swiftly locks critical files and databases, holding them hostage behind an impenetrable digital veil. The haunting demand for ransom sends shockwaves through affected organizations, rendering operations inert and plunging them into a tumultuous struggle between compliance and resilience. Threat actors leveraging Rhysida ransomware are known to impact “targets of opportunity,” including victims in the education, healthcare, manufacturing, information technology, and government sectors. Open source reporting details similarities between Vice Society activity and the actors observed deploying Rhysida ransomware. Additionally, open source reporting has confirmed observed instances of Rhysida actors operating in a ransomware-as-a-service (RaaS) capacity, where ransomware tools and infrastructure are leased out in a profit-sharing model. Any ransoms paid are then split between the group and the affiliates.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [CMD Carry Out String Command Parameter](/endpoint/54a6ed00-3256-11ec-b031-acde48001122/) | [Windows Command Shell](/tags/#windows-command-shell), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Cmdline Tool Not Executed In CMD Shell](/endpoint/6c3f7dd8-153c-11ec-ac2d-acde48001122/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [JavaScript](/tags/#javascript) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Common Ransomware Extensions](/endpoint/a9e5c5db-db11-43ca-86a8-c852d1b2c0ec/) | [Data Destruction](/tags/#data-destruction) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Common Ransomware Notes](/endpoint/ada0f478-84a8-4641-a3f1-d82362d6bd71/) | [Data Destruction](/tags/#data-destruction) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Deleting Shadow Copies](/endpoint/b89919ed-ee5f-492c-b139-95dbb162039e/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect PsExec With accepteula Flag](/endpoint/27c3a83d-cada-47c6-9042-67baf19d2574/) | [Remote Services](/tags/#remote-services), [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Rare Executables](/endpoint/44fddcb2-8d3b-454c-874e-7c6de5a4f7ac/) |  | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Renamed PSExec](/endpoint/683e6196-b8e8-11eb-9a79-acde48001122/) | [System Services](/tags/#system-services), [Service Execution](/tags/#service-execution) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Zerologon via Zeek](/network/bf7a06ec-f703-11ea-adc1-0242ac120002/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Disable Logs Using WevtUtil](/endpoint/236e7c8e-c9d9-11eb-a824-acde48001122/) | [Indicator Removal](/tags/#indicator-removal), [Clear Windows Event Logs](/tags/#clear-windows-event-logs) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Domain Account Discovery With Net App](/endpoint/98f6a534-04c2-11ec-96b2-acde48001122/) | [Domain Account](/tags/#domain-account), [Account Discovery](/tags/#account-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Domain Controller Discovery with Nltest](/endpoint/41243735-89a7-4c83-bcdd-570aa78f00a1/) | [Remote System Discovery](/tags/#remote-system-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Domain Group Discovery With Net](/endpoint/f2f14ac7-fa81-471a-80d5-7eb65c3c7349/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Domain Groups](/tags/#domain-groups) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Elevated Group Discovery With Net](/endpoint/a23a0e20-0b1b-4a07-82e5-ec5f70811e7a/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Domain Groups](/tags/#domain-groups) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Excessive Usage Of Net App](/endpoint/45e52536-ae42-11eb-b5c6-acde48001122/) | [Account Access Removal](/tags/#account-access-removal) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Executables Or Script Creation In Suspicious Path](/endpoint/a7e3f0f0-ae42-11eb-b245-acde48001122/) | [Masquerading](/tags/#masquerading) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [High Process Termination Frequency](/endpoint/17cd75b2-8666-11eb-9ab4-acde48001122/) | [Data Encrypted for Impact](/tags/#data-encrypted-for-impact) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Malicious Powershell Executed As A Service](/endpoint/8e204dfd-cae0-4ea8-a61d-e972a1ff2ff8/) | [System Services](/tags/#system-services), [Service Execution](/tags/#service-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Modification Of Wallpaper](/endpoint/accb0712-c381-11eb-8e5b-acde48001122/) | [Defacement](/tags/#defacement) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [NLTest Domain Trust Discovery](/endpoint/c3e05466-5f22-11eb-ae93-0242ac130002/) | [Domain Trust Discovery](/tags/#domain-trust-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Net Localgroup Discovery](/endpoint/54f5201e-155b-11ec-a6e2-acde48001122/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Local Groups](/tags/#local-groups) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Ntdsutil Export NTDS](/endpoint/da63bc76-61ae-11eb-ae93-0242ac130002/) | [NTDS](/tags/#ntds), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [PowerShell 4104 Hunting](/endpoint/d6f2b006-0041-11ec-8885-acde48001122/) | [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter), [PowerShell](/tags/#powershell) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Ransomware Notes bulk creation](/endpoint/eff7919a-8330-11eb-83f8-acde48001122/) | [Data Encrypted for Impact](/tags/#data-encrypted-for-impact) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [SAM Database File Access Attempt](/endpoint/57551656-ebdb-11eb-afdf-acde48001122/) | [Security Account Manager](/tags/#security-account-manager), [OS Credential Dumping](/tags/#os-credential-dumping) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Scheduled Task Deleted Or Created via CMD](/endpoint/d5af132c-7c17-439c-9d31-13d55340f36c/) | [Scheduled Task](/tags/#scheduled-task), [Scheduled Task/Job](/tags/#scheduled-task/job) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [SecretDumps Offline NTDS Dumping Tool](/endpoint/5672819c-be09-11eb-bbfb-acde48001122/) | [NTDS](/tags/#ntds), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Spike in File Writes](/endpoint/fdb0f805-74e4-4539-8c00-618927333aae/) |  | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Process File Path](/endpoint/9be25988-ad82-11eb-a14f-acde48001122/) | [Create or Modify System Process](/tags/#create-or-modify-system-process) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious wevtutil Usage](/endpoint/2827c0fd-e1be-4868-ae25-59d28e0f9d4f/) | [Clear Windows Event Logs](/tags/#clear-windows-event-logs), [Indicator Removal](/tags/#indicator-removal) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [System User Discovery With Whoami](/endpoint/894fc43e-6f50-47d5-a68b-ee9ee23e18f4/) | [System Owner/User Discovery](/tags/#system-owner/user-discovery) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [WinRM Spawning a Process](/endpoint/a081836a-ba4d-11eb-8593-acde48001122/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows PowerView AD Access Control List Enumeration](/endpoint/39405650-c364-4e1e-a740-32a63ef042a6/) | [Domain Accounts](/tags/#domain-accounts), [Permission Groups Discovery](/tags/#permission-groups-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows PowerView Constrained Delegation Discovery](/endpoint/86dc8176-6e6c-42d6-9684-5444c6557ab3/) | [Remote System Discovery](/tags/#remote-system-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows PowerView Kerberos Service Ticket Request](/endpoint/970455a1-4ac2-47e1-a9a5-9e75443ddcb9/) | [Steal or Forge Kerberos Tickets](/tags/#steal-or-forge-kerberos-tickets), [Kerberoasting](/tags/#kerberoasting) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows PowerView SPN Discovery](/endpoint/a7093c28-796c-4ebb-9997-e2c18b870837/) | [Steal or Forge Kerberos Tickets](/tags/#steal-or-forge-kerberos-tickets), [Kerberoasting](/tags/#kerberoasting) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows PowerView Unconstrained Delegation Discovery](/endpoint/fbf9e47f-e531-4fea-942d-5c95af7ed4d6/) | [Remote System Discovery](/tags/#remote-system-discovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-319a](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-319a)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/rhysida_ransomware.yml) \| *version*: **1**