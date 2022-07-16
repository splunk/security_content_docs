---
title: "Windows PowerView Constrained Delegation Discovery"
excerpt: "Remote System Discovery"
categories:
  - Endpoint
last_modified_at: 2022-03-31
toc: true
toc_label: ""
tags:
  - Remote System Discovery
  - Discovery
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic utilizes PowerShell Script Block Logging (EventCode=4104) to identify commandlets used by the PowerView hacking tool leveraged to discover Windows endpoints with Kerberos Constrained Delegation. Red Teams and adversaries alike may leverage use this technique for situational awareness and Active Directory Discovery.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2022-03-31
- **Author**: Mauricio Velazco, Splunk
- **ID**: 86dc8176-6e6c-42d6-9684-5444c6557ab3


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1018](https://attack.mitre.org/techniques/T1018/) | Remote System Discovery | Discovery |

#### Search

```
`powershell` EventCode=4104 (Message = "*Get-DomainComputer*" OR Message = "*Get-NetComputer*") AND (Message = "*-TrustedToAuth*") 
| stats count min(_time) as firstTime max(_time) as lastTime by EventCode Message ComputerName User 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `windows_powerview_constrained_delegation_discovery_filter`
```

#### Associated Analytic Story
* [Active Directory Kerberos Attacks](/stories/active_directory_kerberos_attacks)


#### How To Implement
The following  analytic requires PowerShell operational logs to be imported. Modify the powershell macro as needed to match the sourcetype or add index. This analytic is specific to 4104, or PowerShell Script Block Logging.

#### Required field
* _time
* EventCode
* Message
* ComputerName
* User


#### Kill Chain Phase
* Reconnaissance


#### Known False Positives
Administrators or power users may leverage PowerView for system management or troubleshooting.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 35.0 | 50 | 70 | Suspicious PowerShell Get-DomainComputer was identified on endpoint $ComputerName$ |




#### Reference

* [https://attack.mitre.org/techniques/T1018/](https://attack.mitre.org/techniques/T1018/)
* [https://adsecurity.org/?p=1667](https://adsecurity.org/?p=1667)
* [https://docs.microsoft.com/en-us/defender-for-identity/cas-isp-unconstrained-kerberos](https://docs.microsoft.com/en-us/defender-for-identity/cas-isp-unconstrained-kerberos)
* [https://www.guidepointsecurity.com/blog/delegating-like-a-boss-abusing-kerberos-delegation-in-active-directory/](https://www.guidepointsecurity.com/blog/delegating-like-a-boss-abusing-kerberos-delegation-in-active-directory/)
* [https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/constrained-delegation](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/constrained-delegation)
* [https://www.cyberark.com/resources/threat-research-blog/weakness-within-kerberos-delegation](https://www.cyberark.com/resources/threat-research-blog/weakness-within-kerberos-delegation)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1018/constrained/windows-powershell.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1018/constrained/windows-powershell.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_powerview_constrained_delegation_discovery.yml) \| *version*: **1**