---
title: "Windows PowerView SPN Discovery"
excerpt: "Steal or Forge Kerberos Tickets, Kerberoasting"
categories:
  - Endpoint
last_modified_at: 2022-06-22
toc: true
toc_label: ""
tags:
  - Steal or Forge Kerberos Tickets
  - Credential Access
  - Kerberoasting
  - Credential Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic utilizes PowerShell Script Block Logging (EventCode=4104) to identify the execution of the `Get-DomainUser` or `Get-NetUSer` commandlets with specific parameters. These commandlets are part of PowerView, a PowerShell tool used to perform enumeration and discovery on Windows Active Directory networks. As the names suggest, these commandlets are used to identify domain users in a network and combining them with the `-SPN` parameter allows adversaries to discover domain accounts associated with a Service Principal Name (SPN). Red Teams and adversaries alike may leverage PowerView and these commandlets to identify accounts that can be attacked with the Kerberoasting technique.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2022-06-22
- **Author**: Gowthamaraj Rajendran, Splunk
- **ID**: a7093c28-796c-4ebb-9997-e2c18b870837


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1558](https://attack.mitre.org/techniques/T1558/) | Steal or Forge Kerberos Tickets | Credential Access |

| [T1558.003](https://attack.mitre.org/techniques/T1558/003/) | Kerberoasting | Credential Access |

#### Search

```
`powershell` EventCode=4104 (ScriptBlockText =*Get-NetUser* OR ScriptBlockText=*Get-DomainUser*) ScriptBlockText= *-SPN* 
| stats count min(_time) as firstTime max(_time) as lastTime by EventCode ScriptBlockText Computer 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)`
| `windows_powerview_spn_discovery_filter`
```

#### Associated Analytic Story
* [Active Directory Kerberos Attacks](/stories/active_directory_kerberos_attacks)


#### How To Implement
The following analytic requires PowerShell operational logs to be imported. Modify the powershell macro as needed to match the sourcetype or add index. This analytic is specific to 4104, or PowerShell Script Block Logging.

#### Required field
* _time
* EventCode
* Computer
* ScriptBlockText


#### Kill Chain Phase
* Reconnaissance
* Exploitation


#### Known False Positives
False positive may include Administrators using PowerView for troubleshooting and management.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 27.0 | 30 | 90 | PowerView commandlets used for SPN discovery executed on $Computer$ |




#### Reference

* [https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/kerberoast](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/kerberoast)
* [https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
* [https://attack.mitre.org/techniques/T1558/003](https://attack.mitre.org/techniques/T1558/003)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1558.003/powerview-2/windows-powershell.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1558.003/powerview-2/windows-powershell.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_powerview_spn_discovery.yml) \| *version*: **1**