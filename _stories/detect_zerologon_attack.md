---
title: "Detect Zerologon Attack"
last_modified_at: 2020-09-18
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Uncover activity related to the execution of Zerologon CVE-2020-11472, a technique wherein attackers target a Microsoft Windows Domain Controller to reset its computer account password. The result from this attack is attackers can now provide themselves high privileges and take over Domain Controller. The included searches in this Analytic Story are designed to identify attempts to reset Domain Controller Computer Account via exploit code remotely or via the use of tool Mimikatz as payload carrier.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2020-09-18
- **Author**: Rod Soto, Jose Hernandez, Stan Miskowicz, David Dorsey, Shannon Davis Splunk
- **ID**: 5d14a962-569e-4578-939f-f386feb63ce4

#### Narrative

This attack is a privilege escalation technique, where attacker targets a Netlogon secure channel connection to a domain controller, using Netlogon Remote Protocol (MS-NRPC). This vulnerability exposes vulnerable Windows Domain Controllers to be targeted via unaunthenticated RPC calls which eventually reset Domain Contoller computer account ($) providing the attacker the opportunity to exfil domain controller credential secrets and assign themselve high privileges that can lead to domain controller and potentially complete network takeover. The detection searches in this Analytic Story use Windows Event viewer events and Sysmon events to detect attack execution, these searches monitor access to the Local Security Authority Subsystem Service (LSASS) process which is an indicator of the use of Mimikatz tool which has bee updated to carry this attack payload.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Detect Computer Changed with Anonymous Account](/endpoint/1400624a-d42d-484d-8843-e6753e6e3645/) | [Exploitation of Remote Services](/tags/#exploitation-of-remote-services) | [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Credential Dumping through LSASS access](/endpoint/2c365e57-4414-4540-8dc0-73ab10729996/) | [LSASS Memory](/tags/#lsass-memory), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Mimikatz Using Loaded Images](/deprecated/29e307ba-40af-4ab2-91b2-3c6b392bbba0/) | [LSASS Memory](/tags/#lsass-memory), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Detect Zerologon via Zeek](/network/bf7a06ec-f703-11ea-adc1-0242ac120002/) | [Exploit Public-Facing Application](/tags/#exploit-public-facing-application) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |
| [Windows Possible Credential Dumping](/endpoint/e4723b92-7266-11ec-af45-acde48001122/) | [LSASS Memory](/tags/#lsass-memory), [OS Credential Dumping](/tags/#os-credential-dumping) | [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types) |

#### Reference

* [https://attack.mitre.org/wiki/Technique/T1003](https://attack.mitre.org/wiki/Technique/T1003)
* [https://github.com/SecuraBV/CVE-2020-1472](https://github.com/SecuraBV/CVE-2020-1472)
* [https://www.secura.com/blog/zero-logon](https://www.secura.com/blog/zero-logon)
* [https://nvd.nist.gov/vuln/detail/CVE-2020-1472](https://nvd.nist.gov/vuln/detail/CVE-2020-1472)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/detect_zerologon_attack.yml) \| *version*: **1**