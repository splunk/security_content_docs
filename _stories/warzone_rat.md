---
title: "Warzone RAT"
last_modified_at: 2023-07-26
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

This analytic story contains detections that allow security analysts to detect and investigate unusual activities that might related to warzone (Ave maria) RAT. This analytic story looks for suspicious process execution, command-line activity, downloads, persistence, defense evasion and more.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2023-07-26
- **Author**: Teoderick Contreras, Splunk
- **ID**: 8dc84752-f4da-4285-931c-bddd5c4d440b

#### Narrative

Warzone RAT, also known as Ave Maria, is a sophisticated remote access trojan (RAT) that surfaced in January 2019. Originally offered as malware-as-a-service (MaaS), it rapidly gained notoriety and became one of the most prominent malware strains by 2020. Its exceptional capabilities in stealth and anti-analysis techniques make it a formidable threat in various campaigns, including those targeting sensitive geopolitical entities. The malware's impact is particularly concerning as it has been associated with attacks aimed at compromising government employees and military personnel, notably within India's National Informatics Centre (NIC). Its deployment by several advanced persistent threat (APT) groups further underlines its potency and adaptability in the hands of skilled threat actors. Warzone RAT's capabilities enable attackers to gain unauthorized access to targeted systems, facilitating data theft, surveillance, and the potential to wreak havoc on critical infrastructures. As the threat landscape continues to evolve, vigilance and robust cybersecurity measures are crucial in defending against such malicious tools." This version provides more context and elaborates on the malware's capabilities and potential impact. Additionally, it emphasizes the importance of cybersecurity measures to combat such threats effectively.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [CMD Carry Out String Command Parameter](/endpoint/54a6ed00-3256-11ec-b031-acde48001122/) | [Windows Command Shell](/tags/#windows-command-shell), [Command and Scripting Interpreter](/tags/#command-and-scripting-interpreter) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Create Remote Thread In Shell Application](/endpoint/10399c1e-f51e-11eb-b920-acde48001122/) | [Process Injection](/tags/#process-injection) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Executables Or Script Creation In Suspicious Path](/endpoint/a7e3f0f0-ae42-11eb-b245-acde48001122/) | [Masquerading](/tags/#masquerading) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Hide User Account From Sign-In Screen](/endpoint/834ba832-ad89-11eb-937d-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Non Chrome Process Accessing Chrome Default Dir](/endpoint/81263de4-160a-11ec-944f-acde48001122/) | [Credentials from Password Stores](/tags/#credentials-from-password-stores), [Credentials from Web Browsers](/tags/#credentials-from-web-browsers) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Office Application Drop Executable](/endpoint/73ce70c4-146d-11ec-9184-acde48001122/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Office Product Spawn CMD Process](/endpoint/b8b19420-e892-11eb-9244-acde48001122/) | [Phishing](/tags/#phishing), [Spearphishing Attachment](/tags/#spearphishing-attachment) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Ping Sleep Batch Command](/endpoint/ce058d6c-79f2-11ec-b476-acde48001122/) | [Virtualization/Sandbox Evasion](/tags/#virtualization/sandbox-evasion), [Time Based Evasion](/tags/#time-based-evasion) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Powershell Windows Defender Exclusion Commands](/endpoint/907ac95c-4dd9-11ec-ba2c-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Registry Keys Used For Persistence](/endpoint/f5f6af30-7aa7-4295-bfe9-07fe87c01a4b/) | [Registry Run Keys / Startup Folder](/tags/#registry-run-keys-/-startup-folder), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Process File Path](/endpoint/9be25988-ad82-11eb-a14f-acde48001122/) | [Create or Modify System Process](/tags/#create-or-modify-system-process) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Bypass UAC via Pkgmgr Tool](/endpoint/cce58e2c-988a-4319-9390-0daa9eefa3cd/) | [Bypass User Account Control](/tags/#bypass-user-account-control) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Credentials from Password Stores Chrome LocalState Access](/endpoint/3b1d09a8-a26f-473e-a510-6c6613573657/) | [Query Registry](/tags/#query-registry) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Credentials from Password Stores Chrome Login Data Access](/endpoint/0d32ba37-80fc-4429-809c-0ba15801aeaf/) | [Query Registry](/tags/#query-registry) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Defender Exclusion Registry Entry](/endpoint/13395a44-4dd9-11ec-9df7-acde48001122/) | [Disable or Modify Tools](/tags/#disable-or-modify-tools), [Impair Defenses](/tags/#impair-defenses) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows ISO LNK File Creation](/endpoint/d7c2c09b-9569-4a9e-a8b6-6a39a99c1d32/) | [Spearphishing Attachment](/tags/#spearphishing-attachment), [Phishing](/tags/#phishing), [Malicious Link](/tags/#malicious-link), [User Execution](/tags/#user-execution) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Mark Of The Web Bypass](/endpoint/8ca13343-7405-4916-a2d1-ae34ce0c28ae/) | [Mark-of-the-Web Bypass](/tags/#mark-of-the-web-bypass) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Modify Registry MaxConnectionPerServer](/endpoint/064cd09f-1ff4-4823-97e0-45c2f5b087ec/) | [Modify Registry](/tags/#modify-registry) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Phishing Recent ISO Exec Registry](/endpoint/cb38ee66-8ae5-47de-bd66-231c7bbc0b2c/) | [Spearphishing Attachment](/tags/#spearphishing-attachment), [Phishing](/tags/#phishing) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Process Injection Remote Thread](/endpoint/8a618ade-ca8f-4d04-b972-2d526ba59924/) | [Process Injection](/tags/#process-injection), [Portable Executable Injection](/tags/#portable-executable-injection) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Unsigned DLL Side-Loading](/endpoint/5a83ce44-8e0f-4786-a775-8249a525c879/) | [DLL Side-Loading](/tags/#dll-side-loading) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://www.blackberry.com/us/en/solutions/endpoint-security/ransomware-protection/warzone#:~:text=Warzone%20RAT%20(AKA%20Ave%20Maria)%20is%20a%20remote%20access%20trojan,is%20as%20an%20information%20stealer.](https://www.blackberry.com/us/en/solutions/endpoint-security/ransomware-protection/warzone#:~:text=Warzone%20RAT%20(AKA%20Ave%20Maria)%20is%20a%20remote%20access%20trojan,is%20as%20an%20information%20stealer.)
* [https://tccontre.blogspot.com/2020/02/2-birds-in-one-stone-ave-maria-wshrat.html](https://tccontre.blogspot.com/2020/02/2-birds-in-one-stone-ave-maria-wshrat.html)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/warzone_rat.yml) \| *version*: **1**