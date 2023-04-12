---
title: "LockBit Ransomware"
last_modified_at: 2023-01-16
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

Leverage searches that allow you to detect and investigate unusual activities that might relate to the LockBit ransomware, including looking for file writes (file encryption and ransomware notes), deleting services, terminating processes, registry key modification and more.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2023-01-16
- **Author**: Teoderick Contreras, Splunk
- **ID**: 67e5b98d-16d6-46a6-8d00-070a3d1a5cfc

#### Narrative

LockBit ransomware was first seen in 2019. This ransomware was used by cybercriminal in targeting multiple sectors and organizations. Lockbit is one of the ransomware being offered as a Ransomware-as-a-Service(RaaS) and also known to affiliates to implement the 'double extortion' techniques by uploading the stolen and sensitive victim information to their dark website and then threatening to sell/release it in public if their demands are not met. LockBit Ransomware advertised opportunities for threat actors that could provide credential access via RDP and VPN. Aside from this it is also uses threat emulation like Cobalt Strike and Metasploit to gain foot hold to the targeted host and persist if needed.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [CMLUA Or CMSTPLUA UAC Bypass](/endpoint/f87b5062-b405-11eb-a889-acde48001122/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [CMSTP](/tags/#cmstp) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Cobalt Strike Named Pipes](/endpoint/5876d429-0240-4709-8b93-ea8330b411b5/) | [Process Injection](/tags/#process-injection) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Common Ransomware Extensions](/endpoint/a9e5c5db-db11-43ca-86a8-c852d1b2c0ec/) | [Data Destruction](/tags/#data-destruction) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Common Ransomware Notes](/endpoint/ada0f478-84a8-4641-a3f1-d82362d6bd71/) | [Data Destruction](/tags/#data-destruction) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Deleting Shadow Copies](/endpoint/b89919ed-ee5f-492c-b139-95dbb162039e/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Executables Or Script Creation In Suspicious Path](/endpoint/a7e3f0f0-ae42-11eb-b245-acde48001122/) | [Masquerading](/tags/#masquerading) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Fsutil Zeroing File](/endpoint/4e5e024e-fabb-11eb-8b8f-acde48001122/) | [Indicator Removal](/tags/#indicator-removal) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [High Process Termination Frequency](/endpoint/17cd75b2-8666-11eb-9ab4-acde48001122/) | [Data Encrypted for Impact](/tags/#data-encrypted-for-impact) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Known Services Killed by Ransomware](/endpoint/3070f8e0-c528-11eb-b2a0-acde48001122/) | [Inhibit System Recovery](/tags/#inhibit-system-recovery) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Modification Of Wallpaper](/endpoint/accb0712-c381-11eb-8e5b-acde48001122/) | [Defacement](/tags/#defacement) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Ransomware Notes bulk creation](/endpoint/eff7919a-8330-11eb-83f8-acde48001122/) | [Data Encrypted for Impact](/tags/#data-encrypted-for-impact) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Recon Using WMI Class](/endpoint/018c1972-ca07-11eb-9473-acde48001122/) | [Gather Victim Host Information](/tags/#gather-victim-host-information), [PowerShell](/tags/#powershell) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Suspicious Process File Path](/endpoint/9be25988-ad82-11eb-a14f-acde48001122/) | [Create or Modify System Process](/tags/#create-or-modify-system-process) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [UAC Bypass With Colorui COM Object](/endpoint/2bcccd20-fc2b-11eb-8d22-acde48001122/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [CMSTP](/tags/#cmstp) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Wbemprox COM Object Execution](/endpoint/9d911ce0-c3be-11eb-b177-acde48001122/) | [System Binary Proxy Execution](/tags/#system-binary-proxy-execution), [CMSTP](/tags/#cmstp) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Modify Registry Default Icon Setting](/endpoint/a7a7afdb-3c58-45b6-9bff-63e5acfd9d40/) | [Modify Registry](/tags/#modify-registry) | [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://blogs.vmware.com/security/2022/10/lockbit-3-0-also-known-as-lockbit-black.html](https://blogs.vmware.com/security/2022/10/lockbit-3-0-also-known-as-lockbit-black.html)
* [https://news.sophos.com/en-us/2020/04/24/lockbit-ransomware-borrows-tricks-to-keep-up-with-revil-and-maze/](https://news.sophos.com/en-us/2020/04/24/lockbit-ransomware-borrows-tricks-to-keep-up-with-revil-and-maze/)
* [https://www.cybereason.com/blog/threat-analysis-report-lockbit-2.0-all-paths-lead-to-ransom](https://www.cybereason.com/blog/threat-analysis-report-lockbit-2.0-all-paths-lead-to-ransom)
* [https://www.trendmicro.com/en_us/research/22/g/lockbit-ransomware-group-augments-its-latest-variant--lockbit-3-.html](https://www.trendmicro.com/en_us/research/22/g/lockbit-ransomware-group-augments-its-latest-variant--lockbit-3-.html)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/lockbit_ransomware.yml) \| *version*: **1**